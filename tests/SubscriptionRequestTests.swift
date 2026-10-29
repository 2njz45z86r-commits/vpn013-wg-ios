// No actual network or live subscription. URLProtocol intercepts every request.
import Foundation
import Dispatch

final class SyntheticSubscriptionProtocol: URLProtocol {
    static let lock = NSLock()
    static var requests: [URLRequest] = []
    static var scenario = 0
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock(); Self.requests.append(request); let scenario = Self.scenario; let index = Self.requests.count; Self.lock.unlock()
        let status = scenario == 1 && index == 1 ? 404 : scenario == 2 ? 403 : 200
        let headers = scenario == 3 ? ["Content-Length": String(ProxyImport.maximumBytes + 1)] : [:]
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data("synthetic-private-response".utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
    static func reset(_ scenario: Int) { lock.lock(); self.scenario = scenario; requests = []; lock.unlock() }
    static func snapshot() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return requests }
}

@main struct SubscriptionRequestTests {
    static var checks = 0
    static var retained: ProxySubscriptionDownload?
    static var identity = ""
    static let directory = FileManager.default.temporaryDirectory.appendingPathComponent("VPN013-subscription-test-" + UUID().uuidString, isDirectory: true)
    static let original = URL(string: "https://connect.vpn555.shop:8443/sub/" + String(repeating: "A", count: 43))!
    static func expect(_ value: Bool) { checks += 1; precondition(value, "Subscription request invariant") }
    static func main() throws {
        let wrapped = "blacktemple://import/" + original.absoluteString + "?client=a%2Bb"
        expect(try VPN013SubscriptionRequest.importText(wrapped) == original.absoluteString + "?client=a%2Bb")
        let encoded = original.absoluteString.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        expect(try VPN013SubscriptionRequest.importText("BLACKTEMPLE://IMPORT/" + encoded) == original.absoluteString)
        expect(try VPN013SubscriptionRequest.importText("vless://synthetic") == "vless://synthetic")
        for payload in ["http://example.invalid/a", "https://user:pass@example.invalid/a", "file:///tmp/a", "blacktemple://import/https://example.invalid/a"] {
            do { _ = try VPN013SubscriptionRequest.importText("blacktemple://import/" + payload); preconditionFailure("Unsafe wrapped URL accepted") }
            catch { checks += 1 }
        }
        identity = try VPN013SubscriptionIdentity.identifier(for: "Publisher.example.invalid", directory: directory)
        let repeated = try VPN013SubscriptionIdentity.identifier(for: "publisher.example.invalid", directory: directory)
        let other = try VPN013SubscriptionIdentity.identifier(for: "another.example.invalid", directory: directory)
        expect(UUID(uuidString: identity) != nil && identity == repeated && identity != other)
        let file = directory.appendingPathComponent("subscription-device-v1")
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        expect(permissions?.intValue == 0o600)
        let request = VPN013SubscriptionRequest.make(original, kind: .incy, identifier: identity, version: "1.7.0")
        expect(request.value(forHTTPHeaderField: "X-HWID") == identity)
        expect(request.value(forHTTPHeaderField: "User-Agent") == "VPN013/1.7.0 (iOS; source=INCY)")
        expect(VPN013SubscriptionRequest.compatibilityURL(original).query == "format=uri")
        let external = URL(string: "https://publisher.example.invalid/subscription")!
        expect(VPN013SubscriptionRequest.compatibilityURL(external) == external)
        expect(!VPN013SubscriptionRequest.isSecure(URL(string: "http://publisher.example.invalid/")!))
        expect(!VPN013SubscriptionRequest.isSecure(URL(string: "https://user:password@publisher.example.invalid/")!))
        DispatchQueue.main.async { run(0) }
        dispatchMain()
    }
    static func run(_ scenario: Int) {
        SyntheticSubscriptionProtocol.reset(scenario)
        let downloader = ProxySubscriptionDownload(configuration: { let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [SyntheticSubscriptionProtocol.self]; return config })
        retained = downloader
        downloader.start(original, kind: .happ, identifier: identity) { result in
            let requests = SyntheticSubscriptionProtocol.snapshot()
            expect(requests.allSatisfy { $0.value(forHTTPHeaderField: "X-HWID") == identity && $0.url?.host == original.host })
            switch scenario {
            case 0:
                guard case .success(let bytes) = result else { preconditionFailure("Missing successful response") }
                expect(bytes == Data("synthetic-private-response".utf8) && requests.count == 1)
            case 1:
                guard case .success = result else { preconditionFailure("No original-format fallback") }
                expect(requests.count == 2 && requests[0].url?.query == "format=uri" && requests[1].url == original)
            case 2:
                guard case .failure(.http(403)) = result else { preconditionFailure("Authorization error hidden") }
                expect(requests.count == 1)
            default:
                guard case .failure(.tooLarge) = result else { preconditionFailure("Oversized response accepted") }
                expect(requests.count == 1)
            }
            retained = nil
            if scenario < 3 { run(scenario + 1) }
            else {
                // Only this random owned directory is removed.
                try! FileManager.default.removeItem(at: directory)
                print("Subscription identity/HTTP: \(checks) checks passed; synthetic URLProtocol only, no real network")
                exit(0)
            }
        }
    }
}
