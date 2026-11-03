// The test uses an isolated HTTP server on 127.0.0.1, never a production URL.
// HTTP and the observation seam exist only in this separately compiled test.
import Foundation

enum ClientUpdateError: Error { case invalidResponse }

@main struct ClientVerifiedDownloadLoopbackTests {
    static func main() throws {
        guard let raw = ProcessInfo.processInfo.environment["VPN013_LOOPBACK_PORT"],
              let port = Int(raw), (1...65535).contains(port),
              let url = URL(string: "http://127.0.0.1:\(port)/synthetic.ipa") else {
            preconditionFailure("Expected a loopback server port")
        }
        var result: Result<URL, Error>?
        var observedWrite = false
        var completions = 0
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        let driver = try ClientVerifiedDownloadTestDriver(
            url: url, expectedHash: String(repeating: "0", count: 64),
            configuration: config, limit: 131_072
        ) { value in
            completions += 1
            result = value
        }
        let directory = driver.directory
        driver.observeFirstWrite {
            let file = directory.appendingPathComponent("VPN013.ipa")
            guard let bytes = try? Data(contentsOf: file), !bytes.isEmpty,
                  bytes.allSatisfy({ $0 == 65 }) else {
                preconditionFailure("The loopback payload was not written correctly")
            }
            DispatchQueue.main.async {
                observedWrite = true
                driver.cancel()
            }
        }
        driver.start()
        let deadline = Date(timeIntervalSinceNow: 20)
        while result == nil && Date() < deadline {
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        guard let outcome = result else { preconditionFailure("Loopback transfer did not finish") }
        guard case .failure(let error) = outcome, (error as? URLError)?.code == .cancelled else {
            preconditionFailure("Expected a cancelled loopback download")
        }
        precondition(observedWrite && completions == 1)
        precondition(!FileManager.default.fileExists(atPath: directory.path), "Partial file was not removed")
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.1))
        precondition(completions == 1)
        print("PASS real loopback HTTP streaming, file write, cancellation and cleanup; no TLS or iPhone")
    }
}
