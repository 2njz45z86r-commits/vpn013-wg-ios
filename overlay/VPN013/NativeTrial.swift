// SPDX-License-Identifier: MIT
#if os(iOS)
import Foundation
import UIKit
import UserNotifications

/// A per-install protected ticket resumes the same server-authoritative trial.
/// Trial acquisition never opens Safari or Telegram and never stops a live VPN.
final class NativeTrialCoordinator: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NativeTrialCoordinator()
    static let label = "Три дня теста бесплатно"
    private var generation: UUID?
    private var network: ClientHTTPTask?
    private var poll: DispatchWorkItem?
    private var progress: UIAlertController?
    private var importing = false
    private var until: UInt64 = 0
    private var lastTick: Date?
    private var refreshing = false
    private var requestedOrder: String?
    private weak var presenter: UIViewController?
    private weak var manager: TunnelsManager?
    private let notifications = UNUserNotificationCenter.current()
    #if DEBUG && targetEnvironment(simulator)
    static var fixture: ((String, Data, String?, @escaping (Result<Data, Error>) -> Void) -> Void)?
    private var fixtureCreates = 0
    private var fixtureDownloads = 0
    #endif

    override private init() {
        super.init()
        notifications.delegate = self
        NotificationCenter.default.addObserver(self, selector: #selector(background), name: UIApplication.didEnterBackgroundNotification, object: nil)
        #if DEBUG && targetEnvironment(simulator)
        installFixtureIfRequested()
        #endif
    }
    @objc private func background() { if !importing { cancel() } }
    private func cancel() {
        generation = nil; network?.cancel(); network = nil; poll?.cancel(); poll = nil
        progress?.dismiss(animated: false); progress = nil
    }
    private func message(_ title: String, _ text: String, from vc: UIViewController, onDismiss: (() -> Void)? = nil) {
        var detail = text
        #if DEBUG && targetEnvironment(simulator)
        if Self.fixture != nil { detail += "\nСинтетический стенд: выдач \(fixtureCreates), загрузок \(fixtureDownloads)." }
        #endif
        let alert = UIAlertController(title: title, message: detail, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Готово", style: .cancel) { _ in onDismiss?() }); vc.present(alert, animated: true)
    }
    func show(manager: TunnelsManager, presenter: UIViewController) {
        guard generation == nil, !ClientUpdateCoordinator.shared.busy else { return }
        guard !manager.mapTunnels(transform: { $0.status != .inactive || $0.isActivateOnDemandEnabled }).contains(true) else {
            message("Тестовые конфигурации", "Сначала отключите VPN и автоподключение. Приложение сохранит прежние профили.", from: presenter); return
        }
        self.presenter = presenter; self.manager = manager
        let stamp = UUID(); generation = stamp; until = DispatchTime.now().uptimeNanoseconds + 120_000_000_000
        let alert = UIAlertController(title: Self.label, message: "Готовим тестовый ZIP…", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Отмена", style: .cancel) { [weak self] _ in self?.cancel() })
        progress = alert; presenter.present(alert, animated: true)
        do {
            let state = try ClientUpdateCoordinator.shared.nativeTrialState()
            let action = state.ticket == nil ? "create" : "info"
            let body: [String: String] = state.ticket == nil ? ["requestID": state.requestID, "platform": "ios"] : [:]
            request(action, body: body, ticket: state.ticket, stamp: stamp) { [weak self] result in self?.received(result, previous: state, stamp: stamp) }
        } catch { failed(error, stamp: stamp) }
    }
    private func request(_ action: String, body: [String: String], ticket: String?, stamp: UUID, origin: Int = 0, completion: @escaping (Result<Data, Error>) -> Void) {
        guard generation == stamp, ["create", "info", "file"].contains(action), ClientUpdateProtocol.origins.indices.contains(origin),
              ticket == nil || ClientUpdateProtocol.validToken(ticket!) else { return }
        guard let payload = try? JSONEncoder().encode(body), payload.count <= 2048 else { completion(.failure(ClientUpdateError.invalidDocument)); return }
        #if DEBUG && targetEnvironment(simulator)
        if let fixture = Self.fixture { fixture(action, payload, ticket) { [weak self] result in
            DispatchQueue.main.async { if self?.generation == stamp { completion(result) } }
        }; return }
        #endif
        var req = URLRequest(url: URL(string: ClientUpdateProtocol.origins[origin] + "/client/trial/awg/" + action)!, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        req.httpMethod = "POST"; req.httpBody = payload; req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(action == "file" ? "application/zip" : "application/json", forHTTPHeaderField: "Accept")
        if let ticket = ticket { req.setValue("Bearer " + ticket, forHTTPHeaderField: "Authorization") }
        network = ClientHTTPTask(request: req, maximumBytes: action == "file" ? 8_388_608 : 32768,
            mimeType: action == "file" ? "application/zip" : "application/json", acceptedStatuses: action == "create" ? [200, 202] : [200]) { [weak self] result in
            guard let self = self, self.generation == stamp else { return }; self.network = nil
            if case .failure(let error) = result, !(error is ClientUpdateError), origin + 1 < ClientUpdateProtocol.origins.count {
                self.request(action, body: body, ticket: ticket, stamp: stamp, origin: origin + 1, completion: completion)
            } else { completion(result) }
        }
    }
    private func received(_ result: Result<Data, Error>, previous: ClientNativeTrialState, stamp: UUID) {
        guard generation == stamp else { return }
        do {
            let info = try JSONDecoder().decode(ClientNativeTrialInfo.self, from: result.get()); try info.validate(previous: previous.info)
            var state = previous
            if state.ticket == nil { guard let ticket = info.ticket else { throw ClientUpdateError.invalidResponse }; state.ticket = ticket }
            state.info = info; state.serverOffset = info.serverTime - Int64(Date().timeIntervalSince1970 * 1000)
            try ClientUpdateCoordinator.shared.saveNativeTrial(state)
            if info.state == "provisioning", DispatchTime.now().uptimeNanoseconds < until {
                progress?.message = "Готовим все серверы. Пожалуйста, подождите…"
                let work = DispatchWorkItem { [weak self] in self?.request("info", body: [:], ticket: state.ticket, stamp: stamp) { [weak self] result in self?.received(result, previous: state, stamp: stamp) } }
                poll = work; DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: work); return
            }
            if info.expiresAt <= info.serverTime || info.state == "expired" {
                finish(stamp: stamp) { [weak self] in self?.renew(order: info.orderID, url: info.renewalURL, expired: true) }; return
            }
            guard info.state == "active" else { throw ClientUpdateError.invalidResponse }
            progress?.message = "Загружаем и добавляем конфигурации…"
            request("file", body: ["platform": "ios"], ticket: state.ticket, stamp: stamp) { [weak self] result in self?.importArchive(result, info: info, stamp: stamp) }
        } catch { failed(error, stamp: stamp) }
    }
    private func importArchive(_ result: Result<Data, Error>, info: ClientNativeTrialInfo, stamp: UUID) {
        guard generation == stamp, let manager = manager else { return }
        do {
            let bytes = try result.get(); guard bytes.count <= 8_388_608 else { throw ClientUpdateError.invalidDocument }
            DispatchQueue.global(qos: .userInitiated).async {
                let parsed: Result<ClientAccessDocument, Error> = Result {
                    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("native-trial-" + UUID().uuidString, isDirectory: true)
                    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700, .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
                    defer { try? FileManager.default.removeItem(at: directory) }
                    let url = directory.appendingPathComponent("trial.zip")
                    try bytes.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
                    let entries = try ZipArchive.unarchive(url: url, requiredFileExtensions: ["json", "conf"], strictRoot: true)
                    let manifests = entries.filter { $0.fileBaseName == ClientUpdateProtocol.manifestName }
                    guard manifests.count == 1 else { throw ClientUpdateError.invalidDocument }
                    let doc = try ClientAccessDocument.decode(manifests[0].contents)
                    guard doc.snapshot.orderID == info.orderID, doc.snapshot.expiry == info.expiresAt,
                          doc.trial?.renewalURL == info.renewalURL else { throw ClientUpdateError.invalidDocument }
                    let configs = try entries.filter { $0.fileBaseName != ClientUpdateProtocol.manifestName }.map { entry -> String in
                        guard let text = String(data: entry.contents, encoding: .utf8) else { throw ClientUpdateError.invalidDocument }
                        return try TunnelConfiguration(fromWgQuickConfig: text, called: entry.fileBaseName).asWgQuickConfig()
                    }
                    let expected = try doc.snapshot.servers.map { try TunnelConfiguration(fromWgQuickConfig: $0.config, called: $0.name).asWgQuickConfig() }
                    guard configs.count == expected.count, configs.sorted() == expected.sorted() else { throw ClientUpdateError.invalidDocument }
                    return doc
                }
                DispatchQueue.main.async {
                    guard self.generation == stamp else { return }
                    do {
                        let doc = try parsed.get(); self.importing = true
                        self.progress?.actions.forEach { $0.isEnabled = false }
                        ClientUpdateCoordinator.shared.importDocument(doc, manager: manager) { error in
                            self.importing = false
                            if let error = error { self.failed(error, stamp: stamp); return }
                            self.scheduleNotifications()
                            self.finish(stamp: stamp) {
                                guard let presenter = self.presenter else { return }
                                let deadline = Date(timeIntervalSince1970: Double(info.expiresAt) / 1000)
                                self.message(info.isTrial ? "Тестовые профили добавлены" : "Конфигурации обновлены", "Добавлено профилей: \(doc.snapshot.servers.count). Доступ до " + DateFormatter.localizedString(from: deadline, dateStyle: .medium, timeStyle: .short) + ". Выберите сервер и включите VPN. Для напоминаний разрешите уведомления; продление доступно в приложении.", from: presenter) {
                                    self.notifications.requestAuthorization(options: [.alert, .sound]) { _, _ in
                                        DispatchQueue.main.async { self.scheduleNotifications() }
                                    }
                                }
                            }
                        }
                    } catch { self.failed(error, stamp: stamp) }
                }
            }
        } catch { failed(error, stamp: stamp) }
    }
    private func finish(stamp: UUID, completion: @escaping () -> Void) {
        guard generation == stamp else { return }; generation = nil; network = nil; poll?.cancel(); poll = nil
        let alert = progress; progress = nil
        if let alert = alert { alert.dismiss(animated: true, completion: completion) } else { completion() }
    }
    private func failed(_ error: Error, stamp: UUID) {
        finish(stamp: stamp) { [weak self] in
            guard let self = self, let presenter = self.presenter else { return }
            let text = (error as? ClientUpdateError) == nil ? "Не удалось завершить загрузку. Прежние профили сохранены. Повторное нажатие продолжит тот же тест и не продлит его срок." : error.localizedDescription
            self.message("Тест не добавлен", text, from: presenter)
        }
    }
    func renewalMenu(manager: TunnelsManager, presenter: UIViewController, source: AnyObject?) {
        self.manager = manager; self.presenter = presenter
        let registry = ClientUpdateCoordinator.shared.registry
        var links = registry.bindings.mapValues { $0.document.trial?.renewalURL ?? "https://t.me/vpn013_com_bot?start=renew_" + $0.document.snapshot.orderID }
        if let info = registry.nativeTrial?.info { links[info.orderID] = info.renewalURL }
        guard !links.isEmpty else { UIApplication.shared.open(URL(string: "https://t.me/vpn013_com_bot")!); return }
        let alert = UIAlertController(title: "Продлить конфигурацию", message: nil, preferredStyle: .actionSheet)
        for order in links.keys.sorted() {
            let url = links[order]!
            alert.addAction(UIAlertAction(title: "Заявка №" + order, style: .default) { [weak self] _ in self?.renew(order: order, url: url, expired: false) })
        }
        alert.addAction(UIAlertAction(title: "Отмена", style: .cancel))
        if let item = source as? UIBarButtonItem { alert.popoverPresentationController?.barButtonItem = item }
        else { alert.popoverPresentationController?.sourceView = presenter.view; alert.popoverPresentationController?.sourceRect = CGRect(x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 1, height: 1) }
        presenter.present(alert, animated: true)
    }
    private func renew(order: String, url: String, expired: Bool) {
        guard ClientUpdateProtocol.validID(order), ClientTrialMetadata.validRenewalURL(url) || url == "https://t.me/vpn013_com_bot?start=renew_" + order,
              let presenter = presenter else { return }
        let alert = UIAlertController(title: expired ? "Срок доступа закончился" : "Продлить конфигурацию", message: "После оплаты и ручного подтверждения в боте продлятся прежние профили и ключи. Повторный импорт не нужен.", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Продлить конфигурацию", style: .default) { _ in
            do { try ClientUpdateCoordinator.shared.rememberRenewal(order); UIApplication.shared.open(URL(string: url)!) }
            catch { self.message("Продление", "Не удалось сохранить привязку. Прежние профили сохранены.", from: presenter) }
        })
        alert.addAction(UIAlertAction(title: "Позже", style: .cancel)); presenter.present(alert, animated: true)
    }
    func tick(manager: TunnelsManager, presenter: UIViewController) {
        self.manager = manager; self.presenter = presenter
        if let order = requestedOrder, presenter.presentedViewController == nil {
            requestedOrder = nil
            if let url = ClientUpdateCoordinator.shared.registry.bindings[order]?.document.trial?.renewalURL { renew(order: order, url: url, expired: true) }
        }
        guard generation == nil, !refreshing, lastTick == nil || Date().timeIntervalSince(lastTick!) > 60 else { return }
        lastTick = Date(); scheduleNotifications()
        let orders = Array(ClientUpdateCoordinator.shared.registry.renewalsAwaitingReturn?.keys ?? Dictionary<String, Int64>().keys).sorted()
        refreshing = true
        func next(_ index: Int) {
            guard index < orders.count else { refreshing = false; scheduleNotifications(); return }
            ClientUpdateCoordinator.shared.refreshRenewal(order: orders[index], manager: manager) { next(index + 1) }
        }
        next(0)
    }
    private func scheduleNotifications() {
        let registry = ClientUpdateCoordinator.shared.registry
        let offset = registry.nativeTrial?.serverOffset ?? 0
        for (order, binding) in registry.bindings where binding.document.trial != nil {
            let expiry = binding.pending?.expiry ?? binding.document.snapshot.expiry
            let id = "vpn013-trial-" + order
            let seconds = Double(expiry) / 1000 - Double(offset) / 1000 - Date().timeIntervalSince1970
            let marker = "VPN013TrialNotice-" + order
            if seconds <= 0, (UserDefaults.standard.object(forKey: marker) as? NSNumber)?.int64Value == expiry { continue }
            notifications.removePendingNotificationRequests(withIdentifiers: [id])
            if seconds > 0 { notifications.removeDeliveredNotifications(withIdentifiers: [id]) }
            let content = UNMutableNotificationContent(); content.title = "Срок доступа закончился"
            content.body = "Продлите конфигурацию. Прежние профили и ключи сохранятся."; content.sound = .default
            content.userInfo = ["nativeTrialOrder": order] // Public orderID only, no capability URL.
            let trigger = UNTimeIntervalNotificationTrigger(timeInterval: max(1, seconds), repeats: false)
            notifications.add(UNNotificationRequest(identifier: id, content: content, trigger: trigger)) { error in
                if error == nil { UserDefaults.standard.set(NSNumber(value: expiry), forKey: marker) }
            }
        }
    }
    #if DEBUG && targetEnvironment(simulator)
    private func installFixtureIfRequested() {
        let args = ProcessInfo.processInfo.arguments
        guard args.contains(where: { $0.hasPrefix("--vpn013-test-native-trial") }) else { return }
        let expiry = Int64(Date().timeIntervalSince1970 * 1000) + (args.contains("--vpn013-test-native-trial-expired") ? -1000 : 259200000)
        let order = "012345abcdef"
        let token = String(repeating: "A", count: 43)
        let url = "https://t.me/vpn013_com_bot?start=trial_" + String(repeating: "C", count: 43)
        let configs = MockTunnels.createMockTunnels().compactMap { $0.tunnelConfiguration }.enumerated().map { index, config in
            ClientServer(id: "test\(index)", name: "Тестовый сервер \(index + 1)", config: TunnelConfiguration(name: "Тестовый сервер \(index + 1)", interface: config.interface, peers: config.peers).asWgQuickConfig())
        }
        let revision = ClientUpdateProtocol.digest(configs.map { $0.id + "\n" + $0.name + "\n" + $0.config + "\n" }.joined())
        let snapshot = ClientSnapshot(schema: 1, kind: "vpn013-awg", orderID: order, expiry: expiry, revision: revision, complete: true, servers: configs)
        let doc = ClientAccessDocument(schema: 1, kind: "vpn013-access", capability: String(repeating: "B", count: 43), snapshot: snapshot, trial: .init(durationSeconds: 259200, renewalURL: url))
        Self.fixture = { [weak self] action, body, auth, completion in
            do {
                guard let self = self, let fields = try JSONSerialization.jsonObject(with: body) as? [String: String] else { throw ClientUpdateError.invalidDocument }
                if action == "create" { guard fields["platform"] == "ios", ClientUpdateProtocol.validToken(fields["requestID"] ?? ""), auth == nil else { throw ClientUpdateError.invalidDocument }; self.fixtureCreates += 1 }
                else { guard auth == token else { throw ClientUpdateError.invalidDocument } }
                if action == "file" {
                    self.fixtureDownloads += 1
                    var entries = configs.map { (fileName: $0.name + ".conf", contents: Data($0.config.utf8)) }
                    entries.append((fileName: "VPN013-Access.json", contents: try JSONEncoder().encode(doc)))
                    if args.contains("--vpn013-test-native-trial-bad-zip") { entries.append((fileName: "../escape.conf", contents: Data(configs[0].config.utf8))) }
                    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".zip")
                    defer { try? FileManager.default.removeItem(at: file) }
                    try ZipArchive.archive(inputs: entries, to: file); completion(.success(try Data(contentsOf: file)))
                } else {
                    let info = ClientNativeTrialInfo(schema: 1, kind: "vpn013-native-trial", app: "vpn013-wg", orderID: order, state: expiry <= Int64(Date().timeIntervalSince1970 * 1000) ? "expired" : "active", issuedAt: expiry - 259200000, expiresAt: expiry, serverTime: Int64(Date().timeIntervalSince1970 * 1000), durationSeconds: 259200, isTrial: true, renewalURL: url, ticket: action == "create" ? token : nil)
                    completion(.success(try JSONEncoder().encode(info)))
                }
            } catch { completion(.failure(error)) }
        }
    }
    #endif
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        if let order = response.notification.request.content.userInfo["nativeTrialOrder"] as? String, ClientUpdateProtocol.validID(order) {
            DispatchQueue.main.async { self.requestedOrder = order; self.lastTick = nil }
        }
        completionHandler()
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) { completionHandler([.banner, .sound]) }
}
#endif
