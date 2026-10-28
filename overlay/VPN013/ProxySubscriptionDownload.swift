// SPDX-License-Identifier: MIT
import Foundation

final class ProxySubscriptionDownload: NSObject, URLSessionDataDelegate {
    private var session: URLSession?
    private var received = Data()
    private var original: URL?
    private var fallback: URL?
    private var kind: VPN013ConnectionKind = .happ
    private var identifier = ""
    private var completion: ((Result<Data, ProxySubscriptionError>) -> Void)?
    private let configuration: () -> URLSessionConfiguration
    init(configuration: @escaping () -> URLSessionConfiguration = { .ephemeral }) { self.configuration = configuration }
    func start(_ url: URL, kind: VPN013ConnectionKind, identifier: String, completion: @escaping (Result<Data, ProxySubscriptionError>) -> Void) {
        cancel()
        guard VPN013SubscriptionRequest.isSecure(url), UUID(uuidString: identifier) != nil else { completion(.failure(.transport)); return }
        original = url; self.kind = kind; self.identifier = identifier; self.completion = completion
        let preferred = VPN013SubscriptionRequest.compatibilityURL(url)
        fallback = preferred == url ? nil : url
        begin(preferred)
    }
    private func begin(_ url: URL) {
        let previous = session; session = nil; previous?.invalidateAndCancel(); received = Data()
        let config = configuration()
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 25
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false; config.urlCredentialStorage = nil; config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: config, delegate: self, delegateQueue: .main); self.session = session
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.7.0"
        session.dataTask(with: VPN013SubscriptionRequest.make(url, kind: kind, identifier: identifier, version: version)).resume()
    }
    func cancel() { completion = nil; session?.invalidateAndCancel(); session = nil; received = Data(); fallback = nil; identifier = "" }
    private func finish(_ result: Result<Data, ProxySubscriptionError>) {
        let callback = completion; cancel(); callback?(result)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard session === self.session else { completionHandler(.cancel); return }
        guard let http = response as? HTTPURLResponse else { completionHandler(.cancel); finish(.failure(.transport)); return }
        if [400, 404].contains(http.statusCode), let url = fallback {
            fallback = nil; completionHandler(.cancel); begin(url); return
        }
        guard http.statusCode == 200 else { completionHandler(.cancel); finish(.failure(.http(http.statusCode))); return }
        guard response.expectedContentLength <= Int64(ProxyImport.maximumBytes) else { completionHandler(.cancel); finish(.failure(.tooLarge)); return }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard session === self.session else { return }
        guard data.count <= ProxyImport.maximumBytes - received.count else { finish(.failure(.tooLarge)); return }
        received.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard session === self.session else { return }; finish(error == nil ? .success(received) : .failure(.transport))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        guard session === self.session else { completionHandler(nil); return }
        guard let original = original, let next = request.url, VPN013SubscriptionRequest.isSecure(next),
              next.host?.lowercased() == original.host?.lowercased(), (next.port ?? 443) == (original.port ?? 443) else {
            completionHandler(nil); finish(.failure(.transport)); return
        }
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.7.0"
        completionHandler(VPN013SubscriptionRequest.make(next, kind: kind, identifier: identifier, version: version))
    }
}
