// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension
import UniformTypeIdentifiers

private func proxyLabel(_ text: String, style: UIFont.TextStyle = .body) -> UILabel {
    let label = UILabel(); label.text = text; label.numberOfLines = 0
    label.font = .preferredFont(forTextStyle: style); label.adjustsFontForContentSizeCategory = true
    label.textColor = VPN013Theme.text; return label
}
private func proxyError(_ error: Error, from controller: UIViewController) {
    let known = error is ProxyProfileError || error is ProxyOperationError || error is ProxySubscriptionError || error is CrossProtocolError
    let alert = UIAlertController(title: "Действие не завершено", message: known ? error.localizedDescription : ProxyOperationError.system.localizedDescription, preferredStyle: .alert)
    alert.addAction(UIAlertAction(title: "Понятно", style: .default)); controller.present(alert, animated: true)
}

/// Native top-level sections. Changing a tab never starts/stops a connection.
final class VPN013UnifiedViewController: UITabBarController, UITabBarControllerDelegate {
    private let awg: MainViewController
    private let profiles = ProxyProfilesManager.shared
    private let kinds = VPN013ConnectionKind.allCases
    private var automaticObserver: NSObjectProtocol?
    private let crossObserver = CrossProtocolObserver()
    private let crossStatus = CrossProtocolStatusView()
    private var crossHeight: NSLayoutConstraint?
    private var crossIsActive = false
    private var crossIdentity: String?
    init(awg: MainViewController) { self.awg = awg; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); delegate = self
        AutomaticModeRow.canChange = { [weak self] in
            guard let self = self else { return true }
            return !self.profiles.working && !self.profiles.entries.contains(where: { [.connecting, .reasserting, .disconnecting].contains($0.status) }) && self.awg.tunnelsManager?.automaticModeBusy != true
        }
        view.backgroundColor = VPN013Theme.background; tabBar.tintColor = VPN013Theme.accent
        let appearance = UITabBarAppearance(); appearance.configureWithOpaqueBackground(); appearance.backgroundColor = VPN013Theme.background
        appearance.stackedLayoutAppearance.normal.iconColor = VPN013Theme.secondaryText
        appearance.stackedLayoutAppearance.normal.titleTextAttributes = [.foregroundColor: VPN013Theme.secondaryText]
        tabBar.standardAppearance = appearance
        if #available(iOS 15, *) { tabBar.scrollEdgeAppearance = appearance }
        let symbols = ["sparkle", "network", "shield.lefthalf.filled", "circle.hexagongrid"]
        viewControllers = kinds.enumerated().map { index, kind in
            let controller: UIViewController = kind == .amneziawg ? awg : UINavigationController(rootViewController: ProxyListViewController(kind: kind))
            controller.tabBarItem = UITabBarItem(title: kind.title, image: UIImage(systemName: symbols[index]), tag: index)
            controller.tabBarItem.accessibilityIdentifier = "vpn013.kind." + kind.rawValue
            return controller
        }
        crossStatus.translatesAutoresizingMaskIntoConstraints = false; crossStatus.isHidden = true
        view.addSubview(crossStatus)
        let height = crossStatus.heightAnchor.constraint(equalToConstant: 150); crossHeight = height
        NSLayoutConstraint.activate([crossStatus.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 16), crossStatus.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -16), crossStatus.bottomAnchor.constraint(equalTo: tabBar.topAnchor, constant: -8), height])
        crossStatus.stop = { [weak self] in self?.crossObserver.stopConnection() }
        crossObserver.changed = { [weak self] runtime, active in
            guard let self = self else { return }
            self.crossIsActive = active; self.crossStatus.isHidden = !active
            self.crossStatus.update(runtime)
            if let runtime = runtime {
                let identity = runtime.kind.rawValue + "\n" + runtime.name + "\n" + (runtime.endpoint ?? "")
                if self.crossIdentity != identity {
                    self.crossIdentity = identity
                    if let index = self.kinds.firstIndex(of: runtime.kind) { self.selectedIndex = index }
                }
            } else if !active { self.crossIdentity = nil }
            self.layoutCrossStatus()
        }
        crossObserver.start()
        let remembered = UserDefaults.standard.string(forKey: "VPN013SelectedKind")
        selectedIndex = kinds.firstIndex(where: { $0.rawValue == remembered }) ?? 2
        #if targetEnvironment(simulator) && DEBUG
        let args = ProcessInfo.processInfo.arguments
        if !args.contains("--vpn013-test-unified") { selectedIndex = 2 }
        #endif
        profiles.changed = { [weak self] in
            NotificationCenter.default.post(name: .vpn013ProxyChanged, object: nil)
            NotificationCenter.default.post(name: AutomaticModeRow.availabilityChanged, object: nil)
            self?.showActiveSection()
        }
        profiles.reportError = { [weak self] error in
            guard let self = self, self.presentedViewController == nil else { return }
            proxyError(error, from: self)
        }
        profiles.reload()
        automaticObserver = NotificationCenter.default.addObserver(forName: VPN013AutomaticMode.changed, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            let finished: (Error?) -> Void = { [weak self] error in
                guard let self = self, let error = error, self.presentedViewController == nil else { return }; proxyError(error, from: self)
            }
            self.profiles.applyAutomaticPreference(completion: finished)
            self.awg.tunnelsManager?.applyAutomaticPreference(completion: finished)
        }
    }
    deinit { crossObserver.stop(); if let token = automaticObserver { NotificationCenter.default.removeObserver(token) } }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); layoutCrossStatus() }
    private func layoutCrossStatus() {
        let width = max(1, view.bounds.width - view.safeAreaInsets.left - view.safeAreaInsets.right - 32)
        let height = crossStatus.preferredHeight(width: width)
        if abs((crossHeight?.constant ?? 0) - height) > 0.5 { crossHeight?.constant = height }
        let inset: CGFloat = crossIsActive ? height + 16 : 0
        for controller in viewControllers ?? [] where abs(controller.additionalSafeAreaInsets.bottom - inset) > 0.5 { controller.additionalSafeAreaInsets.bottom = inset }
    }
    func refresh() {
        awg.refreshTunnelConnectionStatuses(); profiles.reload(); crossObserver.refresh(); showActiveSection()
    }
    private func showActiveSection() {
        guard !crossIsActive else { return }
        // Only follow a newly active connection, so a person may still inspect
        // another section while connected. Foreground refresh follows active kind.
        guard let active = profiles.entries.first(where: { [.connected, .connecting, .reasserting].contains($0.status) }) else { return }
        let key = active.value.profile.id.uuidString
        guard activeIdentity != key else { return }; activeIdentity = key
        if let index = kinds.firstIndex(of: active.value.profile.source) { selectedIndex = index }
    }
    private var activeIdentity: String?
    func foreground() {
        activeIdentity = nil; refresh()
        if awg.tunnelsManager?.tunnelInOperation() != nil { selectedIndex = 2 }
    }
    func tabBarController(_ tabBarController: UITabBarController, didSelect viewController: UIViewController) {
        UserDefaults.standard.set(kinds[selectedIndex].rawValue, forKey: "VPN013SelectedKind")
    }
    func importFile(_ url: URL) {
        if ["conf", "zip"].contains(url.pathExtension.lowercased()) {
            selectedIndex = 2; awg.importFromDisposableFile(url: url); return
        }
        guard kinds[selectedIndex] != .amneziawg,
              let navigation = selectedViewController as? UINavigationController else {
            let alert = UIAlertController(title: "В какой раздел добавить?", message: "Для VLESS или JSON выберите приложение, из которого получена конфигурация.", preferredStyle: .alert)
            for kind in kinds where kind != .amneziawg {
                alert.addAction(UIAlertAction(title: kind.title, style: .default) { [weak self] _ in
                    guard let self = self, let index = self.kinds.firstIndex(of: kind) else { return }
                    self.selectedIndex = index; self.importFile(url)
                })
            }
            alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true); return
        }
        let form = ProxyImportViewController(kind: kinds[selectedIndex]); navigation.pushViewController(form, animated: true); form.readFile(url)
    }
}
extension Notification.Name { static let vpn013ProxyChanged = Notification.Name("VPN013ProxyChanged") }

final class ProxyListViewController: UITableViewController {
    private let kind: VPN013ConnectionKind
    private let manager = ProxyProfilesManager.shared
    private var observer: NSObjectProtocol?
    private let automaticHeader = AutomaticModeRow()
    private var rows: [ProxyProfilesManager.Entry] { manager.entries.filter { $0.value.profile.source == kind } }
    init(kind: VPN013ConnectionKind) { self.kind = kind; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); navigationItem.title = "VPN013"; view.backgroundColor = VPN013Theme.background
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified") { navigationItem.prompt = "Тестовые данные · VPN не запускается" }
        #endif
        tableView.backgroundColor = VPN013Theme.background; tableView.separatorColor = VPN013Theme.separator
        let container = UIView(); automaticHeader.translatesAutoresizingMaskIntoConstraints = false; container.addSubview(automaticHeader)
        NSLayoutConstraint.activate([automaticHeader.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 20), automaticHeader.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -20), automaticHeader.topAnchor.constraint(equalTo: container.topAnchor), automaticHeader.bottomAnchor.constraint(equalTo: container.bottomAnchor)])
        tableView.tableHeaderView = container
        let add = UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(importTapped))
        add.accessibilityLabel = "Добавить конфигурацию " + kind.title
        add.accessibilityIdentifier = "vpn013.proxy.add"
        let invite = UIBarButtonItem(image: UIImage(systemName: "person.badge.plus"), style: .plain, target: self, action: #selector(inviteFriend))
        invite.accessibilityLabel = "Пригласить друга"; invite.accessibilityIdentifier = "vpn013.invite"
        navigationItem.rightBarButtonItems = [add, invite]
        let avatar = UIImageView(image: UIImage(named: "VPN013Avatar")); avatar.contentMode = .scaleAspectFit
        NSLayoutConstraint.activate([avatar.widthAnchor.constraint(equalToConstant: 32), avatar.heightAnchor.constraint(equalToConstant: 32)])
        avatar.isAccessibilityElement = true; avatar.accessibilityLabel = "VPN013"
        navigationItem.leftBarButtonItem = UIBarButtonItem(customView: avatar)
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-subscription-roster") {
            navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Проверить подписки", style: .plain, target: self, action: #selector(testSubscriptionRoster))
            navigationItem.leftBarButtonItem?.accessibilityIdentifier = "vpn013.subscription.fixture"
        }
        #endif
        observer = NotificationCenter.default.addObserver(forName: .vpn013ProxyChanged, object: nil, queue: .main) { [weak self] _ in self?.tableView.reloadData() }
        refreshControl = UIRefreshControl(); refreshControl?.addTarget(self, action: #selector(refreshProfiles), for: .valueChanged)
    }
    deinit { if let token = observer { NotificationCenter.default.removeObserver(token) } }
    override func viewWillAppear(_ animated: Bool) { super.viewWillAppear(animated); tableView.reloadData() }
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        guard let header = tableView.tableHeaderView else { return }
        let width = tableView.bounds.width
        let size = header.systemLayoutSizeFitting(CGSize(width: width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel)
        if abs(header.frame.height - size.height) > 0.5 || header.frame.width != width { header.frame = CGRect(x: 0, y: 0, width: width, height: size.height); tableView.tableHeaderView = header }
    }
    @objc private func refreshProfiles() {
        manager.refreshSubscriptions(kind) { [weak self] error in
            guard let self = self else { return }; self.refreshControl?.endRefreshing()
            if let error = error { proxyError(error, from: self) } else { self.tableView.reloadData() }
        }
    }
    @objc private func importTapped() { navigationController?.pushViewController(ProxyImportViewController(kind: kind), animated: true) }
    @objc private func inviteFriend() { navigationController?.pushViewController(InvitationViewController(), animated: true) }
    #if targetEnvironment(simulator) && DEBUG
    @objc private func testSubscriptionRoster() {
        do {
            let uri = "vless://00000000-0000-4000-8000-000000000001@synthetic.example.invalid:443?type=ws&security=tls&sni=synthetic.example.invalid#Fixture"
            let prototype = try ProxyProfile.fromURI(uri, source: .happ)
            func roster(_ count: Int) -> [ProxyProfile] { (0..<count).map { index in var value = prototype; value.id = UUID(); value.name = "Country \(index)"; value.host = "node\(index).example.invalid"; return value } }
            guard let url = URL(string: "https://subscription.example.invalid/a"), let other = URL(string: "https://subscription.example.invalid/b") else { return }
            var manual = prototype; manual.name = "Personal preserved"
            var originalID: UUID?
            var stage = 0
            func done(_ error: Error?) {
                let alert = UIAlertController(title: error == nil ? "Проверка подписок пройдена" : "Проверка подписок не пройдена", message: error == nil ? "10→20→15; удалённый сервер восстановлен; личный профиль, другая подписка и маршрутизация сохранены. Синтетические данные, без запуска VPN." : "Нарушен проверяемый контракт синхронизации.", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Понятно", style: .default)); self.present(alert, animated: true)
            }
            func next(_ error: Error?) {
                guard error == nil else { done(error); return }; stage += 1
                switch stage {
                case 1: self.manager.add([manual], completion: next)
                case 2: self.manager.installSubscription(url, profiles: roster(10), kind: .happ, completion: next)
                case 3:
                    guard let entry = self.manager.entries.first(where: { $0.value.profile.name == "Country 0" }) else { done(ProxyProfileError.invalid); return }
                    originalID = entry.value.profile.id; self.manager.remove(entry, completion: next)
                case 4: self.manager.installSubscription(url, profiles: roster(10), kind: .happ, completion: next)
                case 5:
                    guard let entry = self.manager.entries.first(where: { $0.value.profile.id == originalID }) else { done(ProxyProfileError.invalid); return }
                    self.manager.update(entry, routing: ProxyRoutingPolicy(mode: .bypass, domains: ["example.invalid"]), completion: next)
                case 6: self.manager.installSubscription(other, profiles: Array(roster(19).suffix(3)), kind: .happ, completion: next)
                case 7: self.manager.installSubscription(url, profiles: roster(20), kind: .happ, completion: next)
                case 8:
                    guard self.manager.entries.count == 24 else { done(ProxyProfileError.invalid); return }
                    self.manager.installSubscription(url, profiles: roster(15), kind: .happ, completion: next)
                default:
                    let entries = self.manager.entries
                    guard entries.count == 19, entries.contains(where: { $0.value.profile.name == "Personal preserved" && $0.value.subscriptionID == nil }),
                          entries.contains(where: { $0.value.profile.name == "Country 18" }),
                          entries.first(where: { $0.value.profile.id == originalID })?.value.routing.mode == .bypass else { done(ProxyProfileError.invalid); return }
                    done(nil)
                }
            }
            next(nil)
        } catch { proxyError(ProxyProfileError.invalid, from: self) }
    }
    #endif
    override func numberOfSections(in tableView: UITableView) -> Int { 1 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { max(1, rows.count) }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? { kind.title + " · ваши подключения" }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        rows.isEmpty ? "Добавьте свою ссылку VLESS, файл JSON Xray или совместимую подписку. Потяните список вниз, чтобы восстановить серверы сохранённых подписок." : "Нажмите сервер, чтобы подключиться и настроить маршрутизацию. Потяните список вниз для обновления сохранённых подписок. Личные конфигурации остаются отдельно."
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.background; cell.textLabel?.textColor = VPN013Theme.text; cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        cell.textLabel?.font = .preferredFont(forTextStyle: .headline); cell.textLabel?.adjustsFontForContentSizeCategory = true
        cell.textLabel?.numberOfLines = 0; cell.detailTextLabel?.numberOfLines = 0
        if rows.isEmpty { cell.textLabel?.text = "Добавить конфигурацию"; cell.detailTextLabel?.text = "Из буфера, файла или ссылки подписки"; cell.imageView?.image = UIImage(systemName: "plus.circle") }
        else {
            let entry = rows[indexPath.row]; cell.textLabel?.text = entry.value.profile.name
            cell.detailTextLabel?.text = entry.value.profile.endpoint + "\n" + ProxyDetailViewController.statusText(entry.status)
            cell.imageView?.image = UIImage(systemName: entry.inOperation ? "power.circle.fill" : "network")
        }
        cell.imageView?.tintColor = VPN013Theme.accent; cell.accessoryType = .disclosureIndicator
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        if rows.isEmpty { importTapped() }
        else { navigationController?.pushViewController(ProxyDetailViewController(id: rows[indexPath.row].value.profile.id), animated: true) }
    }
    override func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        guard !rows.isEmpty else { return nil }; let entry = rows[indexPath.row]
        return UISwipeActionsConfiguration(actions: [UIContextualAction(style: .destructive, title: "Удалить") { [weak self] _, _, done in
            self?.manager.remove(entry) { error in if let error = error, let self = self { proxyError(error, from: self) }; done(error == nil) }
        }])
    }
}

final class ProxyDetailViewController: UITableViewController {
    private let id: UUID
    private let manager = ProxyProfilesManager.shared
    private var entry: ProxyProfilesManager.Entry? { manager.entries.first { $0.value.profile.id == id } }
    private var observer: NSObjectProtocol?
    private var timer: Timer?
    private var traffic: ProxyTraffic?
    private var trafficInFlight = false
    private var trafficRequest = UUID()
    init(id: UUID) { self.id = id; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    static func statusText(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected: return "VPN запущен"
        case .connecting: return "Подключаемся…"
        case .disconnecting: return "Отключаемся…"
        case .reasserting: return "Восстанавливаем подключение…"
        default: return "VPN выключен"
        }
    }
    override func viewDidLoad() {
        super.viewDidLoad(); view.backgroundColor = VPN013Theme.background
        tableView.backgroundColor = VPN013Theme.background; tableView.separatorColor = VPN013Theme.separator
        observer = NotificationCenter.default.addObserver(forName: .vpn013ProxyChanged, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }; self.invalidateTraffic(); self.tableView.reloadData(); self.readTraffic()
        }
    }
    deinit { if let token = observer { NotificationCenter.default.removeObserver(token) }; timer?.invalidate() }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated); title = entry?.value.profile.name ?? "Подключение"
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.readTraffic() }; readTraffic()
    }
    override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); timer?.invalidate(); timer = nil; invalidateTraffic() }
    private func invalidateTraffic() { trafficRequest = UUID(); trafficInFlight = false; traffic = nil }
    private func readTraffic() {
        guard viewIfLoaded?.window != nil, !trafficInFlight, let entry = entry, entry.status == .connected else { return }
        let request = UUID(); trafficRequest = request; trafficInFlight = true
        manager.traffic(entry) { [weak self] value in
            guard let self = self, self.trafficRequest == request, self.entry?.status == .connected else { return }
            self.trafficInFlight = false; self.traffic = value; self.tableView.reloadData()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self = self, self.trafficRequest == request, self.trafficInFlight else { return }
            self.invalidateTraffic(); self.tableView.reloadData()
        }
    }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { 5 }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        "Статус iOS означает запуск VPN. Полученный трафик проверяйте по счётчикам и открытию сайта. Для VLESS не показывается рукопожатие WireGuard."
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.background; cell.textLabel?.textColor = VPN013Theme.text; cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        cell.textLabel?.font = .preferredFont(forTextStyle: .body); cell.textLabel?.numberOfLines = 0; cell.textLabel?.adjustsFontForContentSizeCategory = true
        cell.detailTextLabel?.numberOfLines = 0
        guard let entry = entry else { cell.textLabel?.text = "Профиль больше не доступен"; return cell }
        switch indexPath.row {
        case 0: cell.textLabel?.text = entry.value.profile.source.title; cell.detailTextLabel?.text = Self.statusText(entry.status)
        case 1:
            cell.textLabel?.text = entry.inOperation ? "Выключить VPN" : "Включить VPN"
            cell.textLabel?.textColor = VPN013Theme.accent; cell.imageView?.image = UIImage(systemName: "power"); cell.imageView?.tintColor = VPN013Theme.accent
            cell.accessibilityIdentifier = "vpn013.proxy.power"
        case 2:
            cell.accessibilityIdentifier = "vpn013.proxy.current-endpoint"
            cell.textLabel?.text = entry.status == .connected ? (traffic?.selectedName ?? "Текущий сервер") : "Адрес профиля"
            cell.detailTextLabel?.text = entry.status == .connected ? (traffic?.selectedEndpoint ?? "VPN-расширение пока не вернуло текущий сервер") : entry.value.profile.endpoint
        if let milliseconds = traffic?.httpsMilliseconds, entry.status == .connected { cell.detailTextLabel?.text?.append("\nHTTPS через VPN: \(Int(milliseconds)) мс") }
        case 3:
            cell.textLabel?.text = "Трафик"
            if entry.status == .connected, let value = traffic, value.running {
                cell.detailTextLabel?.text = "Получено: " + ByteCountFormatter.string(fromByteCount: max(0, value.rx), countStyle: .binary) + " · Отправлено: " + ByteCountFormatter.string(fromByteCount: max(0, value.tx), countStyle: .binary)
            } else { cell.detailTextLabel?.text = entry.status == .connected ? "Статистика пока недоступна" : "Появится после подключения" }
        default: cell.textLabel?.text = "Маршрутизация"; cell.detailTextLabel?.text = entry.value.routing.mode.title; cell.accessoryType = .disclosureIndicator
        }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true); guard let entry = entry else { return }
        if indexPath.row == 1 { manager.toggle(entry) }
        if indexPath.row == 4 { navigationController?.pushViewController(ProxyRoutingViewController(entry: entry), animated: true) }
    }
}

final class ProxyRoutingViewController: UIViewController {
    private let entry: ProxyProfilesManager.Entry
    private let modes = UIButton(type: .system)
    private var selectedMode: ProxyRoutingPolicy.Mode
    private let domains = UITextView(); private let networks = UITextView()
    init(entry: ProxyProfilesManager.Entry) { self.entry = entry; selectedMode = entry.value.routing.mode; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Маршрутизация"; view.backgroundColor = VPN013Theme.background
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Сохранить", style: .done, target: self, action: #selector(save))
        updateModes()
        modes.showsMenuAsPrimaryAction = true; modes.contentHorizontalAlignment = .leading
        modes.titleLabel?.font = .preferredFont(forTextStyle: .headline); modes.titleLabel?.adjustsFontForContentSizeCategory = true; modes.titleLabel?.numberOfLines = 0
        modes.heightAnchor.constraint(greaterThanOrEqualToConstant: 48).isActive = true
        modes.accessibilityIdentifier = "vpn013.proxy.routing.mode"
        domains.text = entry.value.routing.domains.joined(separator: "\n"); networks.text = entry.value.routing.networks.joined(separator: "\n")
        let info = proxyLabel("Исключения идут напрямую; в режиме «Только выбранное» остальной трафик идёт напрямую. Домены определяются по доступному имени соединения; для точного правила добавьте IP-сеть. Выбор отдельных установленных приложений на обычном iPhone недоступен.", style: .footnote)
        info.textColor = VPN013Theme.secondaryText
        let stack = UIStackView(arrangedSubviews: [modes, info, proxyLabel("Домены, по одному в строке", style: .headline), domains, proxyLabel("IP-сети, например 192.0.2.0/24", style: .headline), networks])
        stack.axis = .vertical; stack.spacing = 16
        let scroll = UIScrollView(); scroll.keyboardDismissMode = .interactive; scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll); stack.translatesAutoresizingMaskIntoConstraints = false; scroll.addSubview(stack)
        NSLayoutConstraint.activate([scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor), scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor), scroll.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuideIfAvailable), stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 20), stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24), stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20), stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40)])
        for field in [domains, networks] {
            field.font = .preferredFont(forTextStyle: .body); field.adjustsFontForContentSizeCategory = true; field.textColor = VPN013Theme.text; field.backgroundColor = .secondarySystemBackground
            field.autocorrectionType = .no; field.autocapitalizationType = .none; field.smartQuotesType = .no; field.smartDashesType = .no
            field.heightAnchor.constraint(equalToConstant: 110).isActive = true
        }
        domains.accessibilityLabel = "Домены"; networks.accessibilityLabel = "IP-сети"
    }
    @objc private func save() {
        func lines(_ value: String) -> [String] { Array(Set(value.split(whereSeparator: { $0.isNewline }).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })).sorted() }
        do {
            let policy = ProxyRoutingPolicy(mode: selectedMode, domains: try lines(domains.text).map(ProxyRoutingPolicy.domain), networks: lines(networks.text))
            try policy.validate()
            ProxyProfilesManager.shared.update(entry, routing: policy) { [weak self] error in
                guard let self = self else { return }
                if let error = error { proxyError(error, from: self) } else { self.navigationController?.popViewController(animated: true) }
            }
        } catch { proxyError(error, from: self) }
    }
    private func updateModes() {
        modes.setTitle(selectedMode.title, for: .normal)
        modes.setImage(UIImage(systemName: "chevron.down"), for: .normal)
        modes.accessibilityLabel = "Режим маршрутизации"; modes.accessibilityValue = selectedMode.title
        modes.menu = UIMenu(children: ProxyRoutingPolicy.Mode.allCases.map { mode in
            UIAction(title: mode.title, state: selectedMode == mode ? .on : .off) { [weak self] _ in self?.selectedMode = mode; self?.updateModes() }
        })
    }
}

private extension UIView {
    var keyboardLayoutGuideIfAvailable: NSLayoutYAxisAnchor {
        if #available(iOS 15, *) { return keyboardLayoutGuide.topAnchor }
        return safeAreaLayoutGuide.bottomAnchor
    }
}
