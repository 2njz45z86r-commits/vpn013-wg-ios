// Synthetic URLProtocol intercepts every request; no customer data or network.
import Foundation

final class AuditRedirectProtocol: URLProtocol {
    static let lock = NSLock()
    static var target: URL!
    static var paths: [String] = []
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let url = request.url else { preconditionFailure("missing synthetic URL") }
        Self.lock.lock(); Self.paths.append(url.path); let target = Self.target!; Self.lock.unlock()
        if url.path == "/start" {
            let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": target.absoluteString])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            client?.urlProtocolDidFinishLoading(self)
        } else {
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("synthetic".utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }
    override func stopLoading() {}
}

@main enum Audit {
    static func run(_ target: String, allowed: Bool) {
        AuditRedirectProtocol.lock.lock(); AuditRedirectProtocol.target = URL(string: target)!; AuditRedirectProtocol.paths = []; AuditRedirectProtocol.lock.unlock()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [AuditRedirectProtocol.self]
        let download = ProxySubscriptionDownload(configuration: { config })
        var result: Result<Data, ProxySubscriptionError>?
        var calls = 0
        download.start(URL(string: "https://publisher.example.invalid:8443/start")!, kind: .happ,
                       identifier: "00000000-0000-4000-8000-000000000001") { value in calls += 1; result = value }
        let deadline = Date(timeIntervalSinceNow: 12)
        while result == nil && Date() < deadline { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
        guard let result = result else { preconditionFailure("synthetic request did not complete") }
        AuditRedirectProtocol.lock.lock(); let paths = AuditRedirectProtocol.paths; AuditRedirectProtocol.lock.unlock()
        if allowed {
            guard case .success(let data) = result else { preconditionFailure("same-origin redirect not delivered") }
            precondition(data == Data("synthetic".utf8) && paths == ["/start", "/done"])
        } else {
            guard case .failure(.transport) = result else { preconditionFailure("unsafe redirect not rejected") }
            precondition(paths == ["/start"])
        }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05)); precondition(calls == 1)
    }
    static func main() {
        run("https://publisher.example.invalid:8443/done", allowed: true)
        run("https://PUBLISHER.example.invalid:8443/done", allowed: true)
        run("https://other.example.invalid:8443/done", allowed: false)
        run("http://publisher.example.invalid:8443/done", allowed: false)
        run("https://publisher.example.invalid:443/done", allowed: false)
        run("https://user:password@publisher.example.invalid:8443/done", allowed: false)
        print("PASS: 6 synthetic URLSession subscription redirects; no real network")
    }
}
