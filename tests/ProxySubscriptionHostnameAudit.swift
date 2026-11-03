// Public negative fixture and synthetic identifier only. Never changes trust stores.
import Foundation
import Security
import CryptoKit

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

    static func evaluate(_ certificates: CFArray, hostname: String) -> Bool? {
        var candidate: SecTrust?
        guard SecTrustCreateWithCertificates(certificates, SecPolicyCreateSSL(true, hostname as CFString), &candidate) == errSecSuccess,
              let candidate = candidate else { return nil }
        return SecTrustEvaluateWithError(candidate, nil)
    }

    // Observe a separate default URLSession; never accept or override a challenge.
    // Different URLSession connections could have received different certificates.
    static func inspect(_ url: URL) -> Data? {
        let observed: Error? = awaitValue { callback in
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 20
            let session = URLSession(configuration: config)
            session.dataTask(with: url) { _, _, failure in
                let value = failure ?? NSError(domain: "audit.no-error", code: 0)
                DispatchQueue.main.async { callback(value) }
                session.finishTasksAndInvalidate()
            }.resume()
        }
        guard let error = observed as? URLError, error.code == .serverCertificateUntrusted,
              let trust = error.failureURLPeerTrust,
              let certificates = SecTrustCopyCertificateChain(trust),
              let leaf = SecTrustGetCertificateAtIndex(trust, 0),
              evaluate(certificates, hostname: "wrong.host.badssl.com") == false,
              evaluate(certificates, hostname: "badssl.com") == true else { return nil }
        return Data(SHA256.hash(data: SecCertificateCopyData(leaf) as Data))
    }

    static func main() {
        let url = URL(string: "https://wrong.host.badssl.com/")!
        guard let before = inspect(url) else {
            print("UNVERIFIED: public fixture unavailable or peer chain/name checks did not both establish expected conditions")
            return
        }
        let downloader = ProxySubscriptionDownload()
        let result: Result<Data, ProxySubscriptionError>? = awaitValue { callback in
            downloader.start(url, kind: .happ, identifier: "00000000-0000-4000-8000-000000000001", completion: callback)
        }
        guard let result = result, case .failure(.transport) = result else {
            fatalError("subscription downloader did not reject the hostname mismatch fixture")
        }
        guard let after = inspect(url), before == after else {
            print("UNVERIFIED: peer certificate or observable trust checks changed across separate connections")
            return
        }
        print("PASS: downloader rejected public mismatch fixture; independent default URLSession peer chain was trusted for badssl.com and not wrong.host.badssl.com")
        print("LIMIT: observer and downloader use separate connections; the downloader peer certificate was not independently captured")
    }
}
