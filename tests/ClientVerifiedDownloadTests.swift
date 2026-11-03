// Synthetic URLProtocol exercises the real ClientVerifiedDownload and URLSession.
// Every request is intercepted locally; no network or customer files are used.
import Foundation
import CryptoKit

enum ClientUpdateError: Error { case invalidResponse }

final class SyntheticReleaseProtocol: URLProtocol {
    static let lock = NSLock()
    static var requests: [String] = []
    static var streamed: (() -> Void)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    static func clear() { lock.lock(); requests = []; streamed = nil; lock.unlock() }
    static func captured() -> [String] { lock.lock(); defer { lock.unlock() }; return requests }
    override func startLoading() {
        guard let url = request.url else { fatalError("Synthetic URL missing") }
        Self.lock.lock(); Self.requests.append(url.absoluteString); let onStream = Self.streamed; Self.lock.unlock()
        func response(_ status: Int, _ headers: [String: String] = [:]) -> HTTPURLResponse {
            HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        }
        switch url.path {
        case "/ok", "/bad-hash":
            client?.urlProtocol(self, didReceive: response(200, ["Content-Length": "3"]), cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("a".utf8))
            client?.urlProtocol(self, didLoad: Data("bc".utf8))
            client?.urlProtocolDidFinishLoading(self)
        case "/too-large-declared":
            client?.urlProtocol(self, didReceive: response(200, ["Content-Length": "5"]), cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        case "/too-large-stream":
            client?.urlProtocol(self, didReceive: response(200), cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("abc".utf8))
            client?.urlProtocol(self, didLoad: Data("de".utf8))
            client?.urlProtocolDidFinishLoading(self)
        case "/redirect-allowed":
            let target = URL(string: "https://release-assets.githubusercontent.com/ok")!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response(302, ["Location": target.absoluteString]))
        case "/redirect-denied":
            let target = URL(string: "https://untrusted.invalid/ok")!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response(302, ["Location": target.absoluteString]))
        case "/cancel":
            client?.urlProtocol(self, didReceive: response(200), cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("a".utf8))
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { onStream?() }
        default:
            if url.path.hasPrefix("/redirect-chain-"), let number = Int(url.lastPathComponent.dropFirst("redirect-chain-".count)) {
                let target = URL(string: "https://github.com/redirect-chain-\(number + 1)")!
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response(302, ["Location": target.absoluteString]))
            } else {
                client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            }
        }
    }
    override func stopLoading() { }
}

@main struct ClientVerifiedDownloadTests {
    static let correctHash = SHA256.hash(data: Data("abc".utf8)).map { String(format: "%02x", $0) }.joined()
    static func run(_ path: String, hash: String? = nil, limit: Int64 = 3,
                    cancelBeforeStart: Bool = false, cancelOnData: Bool = false,
                    expectSuccess: Bool = false, expectedRequests: Int? = nil) throws {
        precondition(Thread.isMainThread)
        SyntheticReleaseProtocol.clear()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SyntheticReleaseProtocol.self]
        let url = URL(string: "https://github.com/" + path)!
        var result: Result<URL, Error>?
        var callbacks = 0
        let driver = try ClientVerifiedDownloadTestDriver(url: url, expectedHash: hash ?? correctHash,
                                                          configuration: config, limit: limit) { value in
            callbacks += 1; result = value
        }
        let dir = driver.directory
        if cancelOnData {
            SyntheticReleaseProtocol.lock.lock()
            SyntheticReleaseProtocol.streamed = { driver.cancel() }
            SyntheticReleaseProtocol.lock.unlock()
        }
        if cancelBeforeStart { driver.cancel() }
        driver.start()
        let deadline = Date(timeIntervalSinceNow: 10)
        while result == nil && Date() < deadline { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
        guard let outcome = result else { preconditionFailure("URLSession did not complete for \(path)") }
        precondition(callbacks == 1, "Completion must occur once")
        switch outcome {
        case .success(let file):
            precondition(expectSuccess, "Unexpected success for \(path)")
            precondition(file.deletingLastPathComponent() == dir)
            let contents = try Data(contentsOf: file)
            precondition(contents == Data("abc".utf8))
            let fileMode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
            let directoryMode = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? NSNumber
            precondition(fileMode?.intValue == 0o600 && directoryMode?.intValue == 0o700)
            try FileManager.default.removeItem(at: dir)
        case .failure(let error):
            precondition(!expectSuccess, "Unexpected failure for \(path): \(error)")
            precondition(!FileManager.default.fileExists(atPath: dir.path), "Failed transfer left a partial file")
            if cancelBeforeStart || cancelOnData { precondition((error as? URLError)?.code == .cancelled) }
        }
        let requests = SyntheticReleaseProtocol.captured()
        if let expectedRequests = expectedRequests { precondition(requests.count == expectedRequests, "Unexpected request count for \(path): \(requests)") }
        if path == "redirect-denied" { precondition(!requests.contains { $0.contains("untrusted.invalid") }, "Disallowed redirect was followed") }
        // Give duplicate completion callbacks a chance to surface.
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        precondition(callbacks == 1)
        print("PASS synthetic URLSession \(path)")
    }
    static func main() throws {
        try run("ok", expectSuccess: true, expectedRequests: 1)
        try run("bad-hash", hash: String(repeating: "0", count: 64), expectedRequests: 1)
        try run("too-large-declared", expectedRequests: 1)
        try run("too-large-stream", expectedRequests: 1)
        try run("redirect-allowed", expectSuccess: true, expectedRequests: 2)
        try run("redirect-denied", expectedRequests: 1)
        try run("redirect-chain-0", expectedRequests: 6)
        try run("cancel", cancelBeforeStart: true, expectedRequests: 0)
        try run("cancel", cancelOnData: true, expectedRequests: 1)
        print("PASS 9/9 actual URLSession and file-download scenarios; synthetic URLProtocol; no external network")
    }
}
