// No system trust changes and no real subscription or customer data.
import Foundation

@main enum Audit {
    static func awaitValue<T>(_ body: (@escaping (T) -> Void) -> Void) -> T? {
        var value: T?
        body { value = $0 }
        let deadline = Date().addingTimeInterval(28)
        while value == nil && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        return value
    }
    static func main() {
        guard CommandLine.arguments.count == 3, let port = UInt16(CommandLine.arguments[1]), port > 0,
              let localURL = URL(string: "https://127.0.0.1:\(port)/synthetic") else { fatalError("bad test port") }
        let stage = URL(fileURLWithPath: CommandLine.arguments[2]).appendingPathComponent("stage")
        try! "downloader".write(to: stage, atomically: true, encoding: .utf8)
        let download = ProxySubscriptionDownload()
        let result: Result<Data, ProxySubscriptionError>? = awaitValue { callback in
            download.start(localURL, kind: .happ, identifier: "00000000-0000-4000-8000-000000000001", completion: callback)
        }
        guard let result = result, case .failure(.transport) = result else {
            fatalError("real subscription downloader did not reject local self-signed TLS")
        }
        // Separate default URLSession confirms the failure is certificate trust,
        // because the production downloader intentionally hides the raw error.
        try! "default".write(to: stage, atomically: true, encoding: .utf8)
        let request = URLRequest(url: localURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 12)
        let error: NSError? = awaitValue { callback in
            let config = URLSessionConfiguration.ephemeral
            let session = URLSession(configuration: config)
            session.dataTask(with: request) { _, _, failure in
                let result = failure as NSError? ?? NSError(domain: "audit.no-error", code: 0)
                DispatchQueue.main.async { callback(result) }
                session.finishTasksAndInvalidate()
            }.resume()
        }
        guard let error = error, error.domain == NSURLErrorDomain,
              error.code == NSURLErrorServerCertificateUntrusted else {
            fatalError("default session did not establish expected certificate-untrusted result")
        }
        print("PASS: real subscription downloader rejected self-signed localhost; default URLSession reports certificate untrusted")
        let positive = ProxySubscriptionDownload()
        let publicResult: Result<Data, ProxySubscriptionError>? = awaitValue { callback in
            positive.start(URL(string: "https://example.com/")!, kind: .happ,
                           identifier: "00000000-0000-4000-8000-000000000001", completion: callback)
        }
        if let publicResult = publicResult, case .success(let data) = publicResult, !data.isEmpty {
            print("PASS: default downloader fetched publicly trusted HTTPS endpoint")
        } else {
            print("UNVERIFIED: publicly trusted HTTPS endpoint did not complete successfully")
        }
    }
}
