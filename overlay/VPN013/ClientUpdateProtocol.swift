// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

enum ClientUpdateError: LocalizedError {
    case invalidDocument, invalidResponse, accessEnded, network, localChanges(String), activeVPN, busy
    var errorDescription: String? {
        switch self {
        case .invalidDocument: return "Документ обновления повреждён или не относится к VPN013. Существующие конфигурации сохранены."
        case .invalidResponse: return "Не удалось проверить полный ответ бота. Существующие конфигурации сохранены."
        case .accessEnded: return "Доступ к обновлению заявки закончился или отозван. Откройте «Мои заявки» в боте."
        case .network: return "Сервис обновлений недоступен. Проверьте интернет и повторите позже."
        case .localChanges(let name): return "Профиль «\(name)» изменён вручную. Обновление остановлено, чтобы сохранить ваши настройки."
        case .activeVPN: return "Обновление загружено. Оно применится после отключения VPN и автоподключения, когда приложение открыто."
        case .busy: return "Обновление уже выполняется."
        }
    }
}

enum ClientUpdateProtocol {
    static let manifestName = "VPN013-Access"
    static let origins = ["https://connect.vpn555.shop:8443", "https://connect.vpn555.shop:8444"]
    static let botURL = URL(string: "https://t.me/vpn013_com_bot?start=download_vpn013_ios")!
    static let maximumResponseBytes = 1_048_576
    static func digest(_ value: String) -> String { SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined() }
    static func validID(_ value: String) -> Bool { value.range(of: "^[a-f0-9]{12}$", options: .regularExpression) != nil }
    static func validHash(_ value: String) -> Bool { value.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil }
    static func validToken(_ value: String) -> Bool { value.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil }
}

struct ClientServer: Codable, Equatable {
    let id: String
    let name: String
    let config: String
    func validate() throws {
        guard id.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil,
              !name.isEmpty, name.count <= 128, !name.contains(where: { $0.isNewline || $0.isASCII && $0.asciiValue! < 32 }),
              !config.isEmpty, config.utf8.count <= 65_536 else { throw ClientUpdateError.invalidDocument }
    }
}

struct ClientSnapshot: Codable {
    let schema: Int
    let kind: String
    let orderID: String
    let expiry: Int64
    let revision: String
    let complete: Bool
    let servers: [ClientServer]
    func validate(orderID expected: String? = nil) throws {
        guard schema == 1, kind == "vpn013-awg", ClientUpdateProtocol.validID(orderID), expected == nil || expected == orderID,
              complete, (1...30).contains(servers.count), ClientUpdateProtocol.validHash(revision), expiry > 0,
              Set(servers.map { $0.id }).count == servers.count, Set(servers.map { $0.name }).count == servers.count else { throw ClientUpdateError.invalidDocument }
        try servers.forEach { try $0.validate() }
        // The digest binds the authoritative roster, names and exact configuration bytes.
        let expectedDigest = ClientUpdateProtocol.digest(servers.map { $0.id + "\n" + $0.name + "\n" + $0.config + "\n" }.joined())
        guard revision == expectedDigest else { throw ClientUpdateError.invalidDocument }
    }
}

struct ClientAccessDocument: Codable {
    let schema: Int
    let kind: String
    let capability: String
    let snapshot: ClientSnapshot
    func validate() throws {
        guard schema == 1, kind == "vpn013-access", ClientUpdateProtocol.validToken(capability) else { throw ClientUpdateError.invalidDocument }
        try snapshot.validate()
    }
    static func decode(_ data: Data) throws -> Self {
        guard data.count <= ClientUpdateProtocol.maximumResponseBytes else { throw ClientUpdateError.invalidDocument }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate()
        return value
    }
}

struct ClientAppRelease: Codable {
    let schema: Int
    let app: String
    let platform: String
    let version: String
    let build: Int
    let downloadURL: String
    let sha256: String
    let notes: String
    func validate() throws {
        guard schema == 1, app == "vpn013-wg", platform == "ios", build > 0,
              version.range(of: "^[0-9]+[.][0-9]+[.][0-9]+$", options: .regularExpression) != nil,
              ClientUpdateProtocol.validHash(sha256), notes.count <= 2000,
              let url = URL(string: downloadURL), url.scheme == "https", url.host == "github.com", url.user == nil, url.password == nil,
              url.path.hasPrefix("/2njz45z86r-commits/vpn013-wg-ios/releases/download/"), url.path.hasSuffix(".ipa") else { throw ClientUpdateError.invalidResponse }
    }
    func isNewer(version current: String, build currentBuild: Int) -> Bool {
        let comparison = version.compare(current, options: .numeric)
        return comparison == .orderedDescending || comparison == .orderedSame && build > currentBuild
    }
}

/// Only bound profile IDs are eligible for deletion. Names never confer ownership.
struct ClientRosterPlan {
    let added: [ClientServer]
    let retained: [ClientServer]
    let removedIDs: [String]
    init(previousIDs: Set<String>, snapshot: ClientSnapshot) throws {
        try snapshot.validate()
        let current = Set(snapshot.servers.map { $0.id })
        added = snapshot.servers.filter { !previousIDs.contains($0.id) }
        retained = snapshot.servers.filter { previousIDs.contains($0.id) }
        removedIDs = previousIDs.subtracting(current).sorted()
    }
}

/// Bounded response, ephemeral session, strict system TLS, no redirects or cookies.
final class ClientHTTPTask: NSObject, URLSessionDataDelegate {
    private var session: URLSession?
    private var contents = Data()
    private var response: HTTPURLResponse?
    private var failed = false
    private let completion: (Result<Data, Error>) -> Void
    init(request: URLRequest, completion: @escaping (Result<Data, Error>) -> Void) {
        self.completion = completion
        super.init()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 95
        config.timeoutIntervalForResource = 100
        config.httpShouldSetCookies = false
        config.urlCache = nil
        session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        session?.dataTask(with: request).resume()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse
        guard response.expectedContentLength <= ClientUpdateProtocol.maximumResponseBytes else { failed = true; completionHandler(.cancel); return }
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard contents.count + data.count <= ClientUpdateProtocol.maximumResponseBytes else { failed = true; dataTask.cancel(); return }
        contents.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { session.finishTasksAndInvalidate(); self.session = nil }
        let result: Result<Data, Error>
        if failed { result = .failure(ClientUpdateError.invalidResponse) }
        else if let error = error { result = .failure(error) }
        else if let response = response, [401, 403, 410].contains(response.statusCode) { result = .failure(ClientUpdateError.accessEnded) }
        else if response?.statusCode == 200, response?.mimeType == "application/json" { result = .success(contents) }
        else { result = .failure(ClientUpdateError.invalidResponse) }
        DispatchQueue.main.async { self.completion(result) }
    }
    static func request(path: String, capability: String? = nil, originIndex: Int = 0, completion: @escaping (Result<Data, Error>) -> Void) {
        guard ClientUpdateProtocol.origins.indices.contains(originIndex), path.hasPrefix("/client/") else { completion(.failure(ClientUpdateError.network)); return }
        var request = URLRequest(url: URL(string: ClientUpdateProtocol.origins[originIndex] + path)!, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let capability = capability {
            guard ClientUpdateProtocol.validToken(capability) else { completion(.failure(ClientUpdateError.invalidDocument)); return }
            request.httpMethod = "POST"
            request.setValue("Bearer " + capability, forHTTPHeaderField: "Authorization")
            request.httpBody = Data()
        }
        _ = ClientHTTPTask(request: request) { result in
            if case .failure(let error) = result, !(error is ClientUpdateError), originIndex + 1 < ClientUpdateProtocol.origins.count {
                Self.request(path: path, capability: capability, originIndex: originIndex + 1, completion: completion)
            } else { completion(result) }
        }
    }
}
