// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

/// Checks integrity relative to the HTTPS-delivered manifest; this is not a code signature check.
struct ClientReleaseVerification {
    static let maximumBytes: Int64 = 256 * 1024 * 1024
    static let maximumRedirects = 5
    private(set) var byteCount: Int64 = 0
    private var digest = SHA256()
    let limit: Int64

    init(limit: Int64 = maximumBytes) { self.limit = limit }

    static func allowsRedirect(_ url: URL, count: Int) -> Bool {
        let hosts: Set<String> = ["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"]
        guard count > 0, count <= maximumRedirects, url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased(), hosts.contains(host),
              url.user == nil, url.password == nil, url.port == nil || url.port == 443,
              url.fragment == nil else { return false }
        return true
    }

    func acceptsResponse(status: Int, contentLength: Int64) -> Bool {
        status == 200 && (contentLength == -1 || (contentLength > 0 && contentLength <= limit))
    }

    mutating func append(_ data: Data) -> Bool {
        guard Int64(data.count) <= limit - byteCount else { return false }
        byteCount += Int64(data.count)
        digest.update(data: data)
        return true
    }

    mutating func matches(_ expected: String) -> Bool {
        guard byteCount > 0 else { return false }
        let actual = digest.finalize().map { String(format: "%02x", $0) }.joined()
        return actual == expected
    }
}

#if canImport(UIKit)
import UIKit

final class ClientUpdatesViewController: UITableViewController {
    private let manager: TunnelsManager
    private let coordinator = ClientUpdateCoordinator.shared
    private var observer: NSObjectProtocol?
    #if DEBUG && targetEnvironment(simulator)
    private var fixtureStatus: String?
    #endif
    init(manager: TunnelsManager) { self.manager = manager; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Обновления"
        view.backgroundColor = VPN013Theme.background
        view.tintColor = VPN013Theme.accent
        tableView.backgroundColor = VPN013Theme.background
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 60
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(close))
        observer = NotificationCenter.default.addObserver(forName: ClientUpdateCoordinator.changed, object: nil, queue: .main) { [weak self] _ in self?.tableView.reloadData() }
        coordinator.presenter = self
    }
    deinit { if let observer = observer { NotificationCenter.default.removeObserver(observer) } }
    @objc private func close() {
        if let navigation = navigationController, navigation.viewControllers.first !== self {
            navigation.popViewController(animated: true)
        } else { dismiss(animated: true) }
    }
    override func numberOfSections(in tableView: UITableView) -> Int { 3 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        #if DEBUG && targetEnvironment(simulator)
        if section == 2 && (ProcessInfo.processInfo.arguments.contains("--vpn013-test-sync") || ProcessInfo.processInfo.arguments.contains("--vpn013-test-ownership-corrupt")) { return 2 }
        #endif
        switch section { case 0: return coordinator.release == nil ? 2 : 3; case 1: return max(1, coordinator.registry.bindings.count); default: return 1 }
    }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        ["Приложение и конфигурации", "Привязанные заявки", "Автоматическая проверка"][section]
    }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        if section == 1 { return "Привязка появляется после импорта ZIP с документом VPN013-Access.json. Старые ZIP и сторонние серверы работают как раньше. Для отключения обновлений удерживайте заявку." }
        return nil
    }
    override func tableView(_ tableView: UITableView, cellForRowAt path: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.surface
        cell.textLabel?.font = .preferredFont(forTextStyle: .body)
        cell.textLabel?.adjustsFontForContentSizeCategory = true
        cell.textLabel?.numberOfLines = 0
        cell.textLabel?.textColor = VPN013Theme.text
        cell.detailTextLabel?.font = .preferredFont(forTextStyle: .footnote)
        cell.detailTextLabel?.adjustsFontForContentSizeCategory = true
        cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        cell.detailTextLabel?.numberOfLines = 0
        cell.selectionStyle = .none
        if path.section == 0 {
            if path.row == 0 {
                cell.textLabel?.text = coordinator.status
                cell.accessibilityIdentifier = "vpn013.update-status"
            } else if path.row == 1 {
                cell.textLabel?.text = coordinator.busy ? "Проверяем…" : "Обновить"
                cell.imageView?.image = UIImage(systemName: "arrow.clockwise")
                cell.textLabel?.textColor = VPN013Theme.accent
                cell.accessibilityIdentifier = "vpn013.update-check"
                cell.accessibilityTraits.insert(.button)
                cell.isUserInteractionEnabled = !coordinator.busy
            } else {
                cell.textLabel?.text = "Скачать IPA"
                cell.detailTextLabel?.text = "После загрузки приложение проверит контрольную сумму и предложит сохранить IPA. Затем подпишите файл своим сертификатом."
                cell.textLabel?.textColor = VPN013Theme.accent
                cell.accessibilityIdentifier = "vpn013.update-download"
                cell.accessoryType = .disclosureIndicator
                cell.accessibilityTraits.insert(.button)
            }
        } else if path.section == 1 {
            let orders = coordinator.registry.bindings.keys.sorted()
            if orders.isEmpty {
                cell.textLabel?.text = "Пока нет привязанных заявок"
                cell.detailTextLabel?.text = "Скачайте свежий ZIP из раздела «Мои заявки» в боте и импортируйте в VPN013."
            } else {
                let order = orders[path.row]
                if let binding = coordinator.registry.bindings[order] {
                    cell.textLabel?.text = "Заявка №" + order
                    let formatter = DateFormatter(); formatter.dateStyle = .medium; formatter.timeStyle = .short
                    let expiry = formatter.string(from: Date(timeIntervalSince1970: Double(binding.document.snapshot.expiry) / 1000))
                    cell.detailTextLabel?.text = "\(binding.profileIDs.count) серверов · до \(expiry)" + (binding.pending == nil ? "" : "\nОбновление ожидает отключения VPN.")
                    let longPress = UILongPressGestureRecognizer(target: self, action: #selector(unbind(_:)))
                    cell.addGestureRecognizer(longPress)
                }
            }
        } else {
            cell.textLabel?.text = "При открытии, раз в сутки"
            cell.detailTextLabel?.text = "На iPhone проверка работает, когда приложение открыто. Новые серверы добавляются, удалённые исчезают только из своей заявки. Применение ждёт отключения VPN и автоподключения. Ключи и срок доступа сохраняются. Сторонние профили не удаляются."
            #if DEBUG && targetEnvironment(simulator)
            if path.row == 1 {
                cell.textLabel?.text = fixtureStatus ?? "Проверить синхронизацию"
                cell.detailTextLabel?.text = "Synthetic simulator fixture only"
                cell.accessibilityIdentifier = "vpn013.sync-fixture"
                cell.accessibilityTraits.insert(.button)
            }
            #endif
        }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt path: IndexPath) {
        #if DEBUG && targetEnvironment(simulator)
        if path.section == 2 && path.row == 1 {
            ClientUpdateFixture.run(manager: manager) { [weak self] message in self?.fixtureStatus = message; self?.tableView.reloadData() }
            return
        }
        #endif
        guard path.section == 0 else { return }
        coordinator.presenter = self
        if path.row == 1 { coordinator.check(manager: manager, manual: true) }
        if path.row == 2, let release = coordinator.release { ClientReleaseDownload.open(release, from: self) }
    }
    @objc private func unbind(_ recognizer: UILongPressGestureRecognizer) {
        guard recognizer.state == .began, let cell = recognizer.view as? UITableViewCell, let path = tableView.indexPath(for: cell), !coordinator.busy else { return }
        let orders = coordinator.registry.bindings.keys.sorted()
        guard orders.indices.contains(path.row) else { return }
        let order = orders[path.row]
        let alert = UIAlertController(title: "Отключить обновления заявки?", message: "Заявка №\(order). Серверы и ключи останутся в приложении. Для новой привязки импортируйте ZIP из бота.", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Отключить обновления", style: .destructive) { [weak self] _ in
            do { try self?.coordinator.unbind(order: order) }
            catch { self?.showError(error) }
        })
        alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true)
    }
    private func showError(_ error: Error) {
        let alert = UIAlertController(title: "Обновления", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}

/// Public software downloads never carry order capabilities or open Telegram.
enum ClientReleaseDownload {
    private static var active: ClientVerifiedDownload?
    static func open(_ release: ClientAppRelease, from presenter: UIViewController) {
        do {
            try release.validate()
            guard let url = URL(string: release.downloadURL) else { throw ClientUpdateError.invalidResponse }
            #if DEBUG && targetEnvironment(simulator)
            if ProcessInfo.processInfo.arguments.contains("--vpn013-test-direct-download") {
                let alert = UIAlertController(title: "Прямая загрузка IPA", message: url.absoluteString, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Понятно", style: .default)); presenter.present(alert, animated: true)
                return
            }
            #endif
            guard active == nil else { return }
            let progress = UIAlertController(title: "Загрузка IPA", message: "Загружаем файл и проверяем контрольную сумму…", preferredStyle: .alert)
            let download = try ClientVerifiedDownload(url: url, expectedHash: release.sha256) { [weak presenter, weak progress] result in
                let cancelled = active?.cancelledByUser == true
                active = nil
                if cancelled {
                    if case .success(let file) = result { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
                    return
                }
                guard let progress = progress else {
                    if case .success(let file) = result { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
                    return
                }
                let presentResult = {
                    guard let presenter = presenter, presenter.viewIfLoaded?.window != nil else {
                        if case .success(let file) = result { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
                        return
                    }
                    switch result {
                    case .success(let file):
                        let sheet = UIActivityViewController(activityItems: [file], applicationActivities: nil)
                        sheet.popoverPresentationController?.sourceView = presenter.view
                        sheet.popoverPresentationController?.sourceRect = CGRect(x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 1, height: 1)
                        sheet.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }
                        presenter.present(sheet, animated: true)
                    case .failure(let error):
                        guard (error as? URLError)?.code != .cancelled else { return }
                        let alert = UIAlertController(title: "Загрузка IPA", message: "Не удалось загрузить файл или проверить его контрольную сумму. Повторите проверку обновлений.", preferredStyle: .alert)
                        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); presenter.present(alert, animated: true)
                    }
                }
                if progress.presentingViewController != nil { progress.dismiss(animated: true, completion: presentResult) }
                else { presentResult() }
            }
            active = download
            progress.addAction(UIAlertAction(title: "Отмена", style: .cancel) { _ in download.cancel() })
            let presentProgress = {
                guard presenter.viewIfLoaded?.window != nil else { download.cancel(); download.start(); return }
                presenter.present(progress, animated: true) { download.start() }
            }
            if let current = presenter.presentedViewController { current.dismiss(animated: true, completion: presentProgress) }
            else { presentProgress() }
        } catch {
            let alert = UIAlertController(title: "Загрузка IPA", message: "Ссылка на обновление не прошла проверку. Проверьте обновления ещё раз.", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Понятно", style: .default))
            presenter.present(alert, animated: true)
        }
    }
}

#endif
#if canImport(UIKit) || VPN013_DOWNLOAD_TESTS
/// Streams into an app-private temporary file; no partially downloaded file is shared.
private final class ClientVerifiedDownload: NSObject, URLSessionDataDelegate {
    private let url: URL
    private let expectedHash: String
    private let directory: URL
    private let file: URL
    private let output: FileHandle
    private let completion: (Result<URL, Error>) -> Void
    private var verification = ClientReleaseVerification()
    private var redirects = 0
    private var responseAccepted = false
    private var failure: Error?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    // start and cancel are both called by the UI on the main queue.
    private var cancelledBeforeStart = false
    private(set) var cancelledByUser = false
    #if VPN013_DOWNLOAD_TESTS
    private var syntheticConfiguration: URLSessionConfiguration?
    func configureForTest(_ configuration: URLSessionConfiguration, limit: Int64) {
        precondition(session == nil && task == nil && limit > 0)
        syntheticConfiguration = configuration
        verification = ClientReleaseVerification(limit: limit)
    }
    var testDirectory: URL { directory }
    var testRedirectCount: Int { redirects }
    #endif

    init(url: URL, expectedHash: String, completion: @escaping (Result<URL, Error>) -> Void) throws {
        self.url = url; self.expectedHash = expectedHash; self.completion = completion
        let tempDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("vpn013-ipa-" + UUID().uuidString, isDirectory: true)
        let tempFile = tempDirectory.appendingPathComponent("VPN013.ipa")
        directory = tempDirectory; file = tempFile
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        guard FileManager.default.createFile(atPath: tempFile.path, contents: nil, attributes: [.posixPermissions: 0o600, .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]) else {
            try? FileManager.default.removeItem(at: tempDirectory); throw ClientUpdateError.invalidResponse
        }
        do { output = try FileHandle(forWritingTo: tempFile) }
        catch { try? FileManager.default.removeItem(at: tempDirectory); throw error }
        super.init()
    }

    func start() {
        guard !cancelledBeforeStart else {
            try? output.close(); try? FileManager.default.removeItem(at: directory)
            completion(.failure(URLError(.cancelled))); return
        }
        #if VPN013_DOWNLOAD_TESTS
        let config = syntheticConfiguration ?? URLSessionConfiguration.ephemeral
        #else
        let config = URLSessionConfiguration.ephemeral
        #endif
        config.httpCookieStorage = nil; config.urlCredentialStorage = nil; config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 60; config.timeoutIntervalForResource = 600
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
        self.session = session
        let task = session.dataTask(with: url); self.task = task; task.resume()
    }
    func cancel() {
        cancelledByUser = true
        if let task = task { task.cancel() } else { cancelledBeforeStart = true }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        redirects += 1
        guard let url = request.url, ClientReleaseVerification.allowsRedirect(url, count: redirects) else {
            failure = ClientUpdateError.invalidResponse; completionHandler(nil); return
        }
        completionHandler(request)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse,
              verification.acceptsResponse(status: response.statusCode, contentLength: response.expectedContentLength) else {
            failure = ClientUpdateError.invalidResponse; completionHandler(.cancel); return
        }
        responseAccepted = true; completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard failure == nil, verification.append(data) else {
            failure = ClientUpdateError.invalidResponse; dataTask.cancel(); return
        }
        do { try output.write(contentsOf: data) }
        catch { failure = error; dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        var result: Result<URL, Error>
        do {
            try output.close()
            if let failure = failure { throw failure }
            if let error = error { throw error }
            guard responseAccepted, verification.matches(expectedHash) else { throw ClientUpdateError.invalidResponse }
            result = .success(file)
        } catch {
            try? FileManager.default.removeItem(at: directory); result = .failure(error)
        }
        session.finishTasksAndInvalidate()
        DispatchQueue.main.async { self.completion(result) }
    }
}

#if VPN013_DOWNLOAD_TESTS
// This wrapper is compiled only into the isolated macOS test executable.
final class ClientVerifiedDownloadTestDriver {
    private let download: ClientVerifiedDownload
    var directory: URL { download.testDirectory }
    var redirectCount: Int { download.testRedirectCount }
    init(url: URL, expectedHash: String, configuration: URLSessionConfiguration, limit: Int64,
         completion: @escaping (Result<URL, Error>) -> Void) throws {
        download = try ClientVerifiedDownload(url: url, expectedHash: expectedHash, completion: completion)
        download.configureForTest(configuration, limit: limit)
    }
    func start() { download.start() }
    func cancel() { download.cancel() }
}
#endif
#endif

#if canImport(UIKit)
extension TunnelsListTableViewController {
    @objc func clientUpdatesTapped() {
        guard let manager = tunnelsManager else { return }
        let controller = UINavigationController(rootViewController: ClientUpdatesViewController(manager: manager))
        controller.modalPresentationStyle = .formSheet
        present(controller, animated: true)
    }
}
#endif
