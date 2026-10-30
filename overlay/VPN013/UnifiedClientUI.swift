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
    var settingsTunnelsManager: TunnelsManager? { awg.tunnelsManager }
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
            return !CrossProtocolPlan.changingSources && !self.profiles.working && !self.profiles.entries.contains(where: { [.connecting, .reasserting, .disconnecting].contains($0.status) }) && self.awg.tunnelsManager?.automaticModeBusy != true
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
                    if !self.isEditingImport, let index = self.kinds.firstIndex(of: runtime.kind) { self.selectedIndex = index }
                }
            } else if !active { self.crossIdentity = nil }
            self.layoutCrossStatus()
        }
        let remembered = UserDefaults.standard.string(forKey: "VPN013SelectedKind")
        selectedIndex = kinds.firstIndex(where: { $0.rawValue == remembered }) ?? 2
        #if targetEnvironment(simulator) && DEBUG
        let args = ProcessInfo.processInfo.arguments
        if !args.contains("--vpn013-test-unified") { selectedIndex = 2 }
        #endif
        // Restore preferences first so an existing runtime selects its actual section.
        crossObserver.start()
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
    private var isEditingImport: Bool {
        (selectedViewController as? UINavigationController)?.topViewController is ProxyImportViewController
    }
    private func showActiveSection() {
        guard !crossIsActive, !isEditingImport else { return }
        // Only follow a newly active connection, so a person may still inspect
        // another section while connected. Foreground refresh follows active kind.
        guard let active = profiles.entries.first(where: { [.connected, .connecting, .reasserting].contains($0.status) }) else { return }
        let key = active.value.profile.id.uuidString
        guard activeIdentity != key else { return }; activeIdentity = key
        if let index = kinds.firstIndex(of: active.value.profile.source) { selectedIndex = index }
    }
    private var activeIdentity: String?
    func foreground() {
        let keepDraft = isEditingImport
        activeIdentity = nil; refresh()
        if !keepDraft && awg.tunnelsManager?.tunnelInOperation() != nil { selectedIndex = 2 }
    }
    func tabBarController(_ tabBarController: UITabBarController, didSelect viewController: UIViewController) {
        UserDefaults.standard.set(kinds[selectedIndex].rawValue, forKey: "VPN013SelectedKind")
    }
    func importConnection(kind: VPN013ConnectionKind, text: String?) {
        loadViewIfNeeded()
        guard presentedViewController == nil, let index = kinds.firstIndex(of: kind) else { return }
        selectedIndex = index
        UserDefaults.standard.set(kind.rawValue, forKey: "VPN013SelectedKind")
        if kind == .amneziawg {
            // ZIP stays an authenticated file download. iOS Open In imports it without exposing a new token.
            awg.loadViewIfNeeded()
            awg.tunnelsListVC?.presentViewControllerForFileImport()
        } else if let navigation = selectedViewController as? UINavigationController {
            // Keep a person's existing draft instead of replacing it with an incoming link.
            if let existing = navigation.topViewController as? ProxyImportViewController { existing.offerIncomingText(text); return }
            navigation.pushViewController(ProxyImportViewController(kind: kind, text: text), animated: true)
        }
    }
    func importFile(_ url: URL) {
        if url.pathExtension.lowercased() == "zip" {
            let scoped = url.startAccessingSecurityScopedResource()
            let entries = try? ZipArchive.unarchive(url: url, requiredFileExtensions: ["txt"])
            if scoped { url.stopAccessingSecurityScopedResource() }
            guard let entries = entries else {
                let alert = UIAlertController(title: "Не удалось открыть ZIP", message: "Проверьте архив и повторите попытку.", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true); return
            }
            let hasSubscription = entries.contains(where: { $0.fileBaseName == "Подписка" })
            if hasSubscription {
                // Owner ZIP instructions identify the application and platform
                // in their first line. Select only when all copies agree.
                let instructions = entries.filter { $0.fileBaseName == "Инструкция" }
                let labels = instructions.compactMap { entry -> VPN013ConnectionKind? in
                    guard let text = String(data: entry.contents, encoding: .utf8), let line = text.split(separator: "\n").first else { return nil }
                    let parts = String(line).components(separatedBy: " · ")
                    guard parts.count >= 3, ["Android", "iPhone", "Windows"].contains(parts.last ?? "") else { return nil }
                    let name = parts[parts.count - 2].lowercased()
                    return VPN013ConnectionKind(rawValue: name)
                }
                if let kind = labels.first, labels.count == instructions.count, kind != .amneziawg, labels.allSatisfy({ $0 == kind }), let index = kinds.firstIndex(of: kind),
                   let navigation = viewControllers?[index] as? UINavigationController {
                    selectedIndex = index
                    let form = ProxyImportViewController(kind: kind); navigation.pushViewController(form, animated: true); form.readFile(url); return
                }
                let alert = UIAlertController(title: "В какой раздел добавить?", message: "Выберите приложение, для которого выпущена подписка.", preferredStyle: .alert)
                for kind in kinds where kind != .amneziawg {
                    alert.addAction(UIAlertAction(title: kind.title, style: .default) { [weak self] _ in
                        guard let self = self, let index = self.kinds.firstIndex(of: kind) else { return }
                        self.selectedIndex = index
                        guard let navigation = self.selectedViewController as? UINavigationController else { return }
                        let form = ProxyImportViewController(kind: kind); navigation.pushViewController(form, animated: true); form.readFile(url)
                    })
                }
                alert.addAction(UIAlertAction(title: VPN013ConnectionKind.amneziawg.title, style: .default) { [weak self] _ in
                    guard let self = self else { return }; self.selectedIndex = 2; self.awg.importFromDisposableFile(url: url)
                })
                alert.addAction(UIAlertAction(title: "Отмена", style: .cancel)); present(alert, animated: true); return
            }
            selectedIndex = 2; awg.importFromDisposableFile(url: url); return
        }
        if url.pathExtension.lowercased() == "conf" {
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

enum VPN013SettingsPresentation {
    static func show(from controller: UIViewController, kind: VPN013ConnectionKind?) {
        let unified = (controller.tabBarController as? VPN013UnifiedViewController) ??
            (controller.view.window?.rootViewController as? VPN013UnifiedViewController)
        let settings = SettingsTableViewController(tunnelsManager: unified?.settingsTunnelsManager, connectionKind: kind)
        let navigation = UINavigationController(rootViewController: settings)
        navigation.modalPresentationStyle = .formSheet
        controller.present(navigation, animated: true)
    }
}

/// Selection is local to this screen; only explicit Save in the next screen
/// changes the selected profiles. Opening the picker never applies a rule.
final class ProxyRoutingProfilesViewController: UITableViewController {
    private let kind: VPN013ConnectionKind?
    private var selected = Set<UUID>()
    private let selectAll = UIButton(type: .system)
    private var nextButton: UIBarButtonItem!
    private var entries: [ProxyProfilesManager.Entry] {
        ProxyProfilesManager.shared.entries.filter { kind == nil || $0.value.profile.source == kind }
    }
    init(kind: VPN013ConnectionKind?) { self.kind = kind; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Маршрутизация"
        tableView.backgroundColor = VPN013Theme.background
        nextButton = UIBarButtonItem(title: "Далее", style: .done, target: self, action: #selector(nextTapped))
        nextButton.accessibilityIdentifier = "vpn013.routing.next"; navigationItem.rightBarButtonItem = nextButton
        let header = UIView(); selectAll.translatesAutoresizingMaskIntoConstraints = false; header.addSubview(selectAll)
        selectAll.tintColor = VPN013Theme.accent; tableView.tintColor = VPN013Theme.accent
        selectAll.titleLabel?.font = .preferredFont(forTextStyle: .headline); selectAll.titleLabel?.adjustsFontForContentSizeCategory = true
        selectAll.titleLabel?.numberOfLines = 0; selectAll.contentHorizontalAlignment = .leading
        selectAll.accessibilityIdentifier = "vpn013.routing.select-all"; selectAll.addTarget(self, action: #selector(selectAllTapped), for: .touchUpInside)
        NSLayoutConstraint.activate([selectAll.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 20), selectAll.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -20), selectAll.topAnchor.constraint(equalTo: header.topAnchor, constant: 12), selectAll.bottomAnchor.constraint(equalTo: header.bottomAnchor, constant: -12), selectAll.heightAnchor.constraint(greaterThanOrEqualToConstant: 44)])
        tableView.tableHeaderView = header; refreshSelection()
    }
    override func viewWillAppear(_ animated: Bool) { super.viewWillAppear(animated); selected.formIntersection(entries.map { $0.value.profile.id }); refreshSelection(); tableView.reloadData() }
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews(); guard let header = tableView.tableHeaderView else { return }
        let height = header.systemLayoutSizeFitting(CGSize(width: tableView.bounds.width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel).height
        if abs(header.frame.height - height) > 0.5 { header.frame.size = CGSize(width: tableView.bounds.width, height: height); tableView.tableHeaderView = header }
    }
    private func refreshSelection() {
        selectAll.setTitle(!entries.isEmpty && selected.count == entries.count ? "Снять выбор" : "Выбрать все", for: .normal)
        selectAll.isEnabled = !entries.isEmpty; nextButton.isEnabled = !selected.isEmpty
        nextButton.title = selected.isEmpty ? "Далее" : "Далее (\(selected.count))"
        navigationItem.prompt = (kind?.title ?? "Серверы") + " · Выбрано: \(selected.count)"
    }
    @objc private func selectAllTapped() {
        selected = !entries.isEmpty && selected.count == entries.count ? [] : Set(entries.map { $0.value.profile.id })
        refreshSelection(); tableView.reloadData()
    }
    @objc private func nextTapped() {
        let targets = entries.filter { selected.contains($0.value.profile.id) }; guard !targets.isEmpty else { return }
        navigationController?.pushViewController(ProxyRoutingViewController(entries: targets), animated: true)
    }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { max(1, entries.count) }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        "Отметьте нужные серверы и нажмите «Далее». Один набор правил применяется только к выбранным серверам после сохранения. Пока ничего не выбрано, маршруты остаются прежними."
    }
    override func tableView(_ tableView: UITableView, cellForRowAt path: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.surface; cell.textLabel?.textColor = VPN013Theme.text
        cell.textLabel?.numberOfLines = 0; cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        guard !entries.isEmpty else { cell.textLabel?.text = "Сначала добавьте конфигурацию"; cell.selectionStyle = .none; return cell }
        let entry = entries[path.row]
        cell.textLabel?.text = entry.value.profile.name; cell.detailTextLabel?.text = entry.value.profile.source.title
        let checked = selected.contains(entry.value.profile.id)
        cell.accessoryType = checked ? .checkmark : .none
        cell.accessibilityIdentifier = "vpn013.routing.server." + entry.value.profile.id.uuidString
        cell.accessibilityValue = checked ? "Выбран" : "Не выбран"
        if checked { cell.accessibilityTraits.insert(.selected) }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt path: IndexPath) {
        tableView.deselectRow(at: path, animated: true)
        guard entries.indices.contains(path.row) else { return }
        let id = entries[path.row].value.profile.id
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
        refreshSelection(); tableView.reloadRows(at: [path], with: .none)
    }
}

private final class ProxyServerListCell: UITableViewCell {
    var openConfiguration: (() -> Void)?
    private let configuration = UIButton(type: .system)
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: .subtitle, reuseIdentifier: reuseIdentifier)
        configuration.setImage(UIImage(systemName: "chevron.right"), for: .normal)
        configuration.tintColor = VPN013Theme.secondaryText
        configuration.accessibilityIdentifier = "vpn013.proxy.configuration"
        configuration.frame.size = CGSize(width: 64, height: 44)
        configuration.addTarget(self, action: #selector(openTapped), for: .touchUpInside)
        accessoryView = configuration
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func layoutSubviews() {
        super.layoutSubviews()
        // The entire right strip opens details, including above/below its
        // chevron. The globe and central row remain the connect target.
        configuration.frame = CGRect(x: bounds.width - 64, y: 0, width: 64, height: bounds.height)
    }
    func configure(name: String) { configuration.accessibilityLabel = "Открыть конфигурацию: " + name }
    @objc private func openTapped() { openConfiguration?() }
}

private final class ProxyConnectionPanel: UIView {
    var powerAction: (() -> Void)?
    var pingAction: (() -> Void)?
    private let name = proxyLabel("Нет конфигураций", style: .title1)
    private let status = proxyLabel("Не подключено", style: .subheadline)
    private let detail = proxyLabel("Добавьте конфигурацию кнопкой +", style: .body)
    private let routing = proxyLabel("", style: .footnote)
    private let statistics = proxyLabel("", style: .footnote)
    private let power = UIButton(type: .system)
    private let ping = UIButton(type: .system)
    private let note = proxyLabel("Пинг адресов по текущему сетевому маршруту. Без переключения VPN. Ответ не подтверждает работу VPN; сервер может блокировать пинг.", style: .footnote)
    override init(frame: CGRect) {
        super.init(frame: frame)
        let preferred = UIFont.preferredFont(forTextStyle: .title1)
        name.font = UIFont(descriptor: preferred.fontDescriptor.withSymbolicTraits(.traitBold) ?? preferred.fontDescriptor, size: preferred.pointSize)
        status.textColor = VPN013Theme.secondaryText
        for label in [detail, routing, statistics, note] { label.textColor = VPN013Theme.secondaryText }
        name.accessibilityIdentifier = "vpn013.proxy.current.name"
        status.accessibilityIdentifier = "vpn013.proxy.current.status"
        statistics.accessibilityIdentifier = "vpn013.proxy.current.traffic"
        let card = UIView(); card.backgroundColor = VPN013Theme.surface; card.layer.cornerRadius = 18
        card.layer.borderWidth = 1; card.layer.borderColor = VPN013Theme.separator.cgColor
        let heading = UIStackView(arrangedSubviews: [name, status]); heading.axis = .horizontal; heading.spacing = 12; heading.alignment = .top
        name.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        status.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        let descriptions = UIStackView(arrangedSubviews: [detail, routing, statistics]); descriptions.axis = .vertical; descriptions.spacing = 8
        let body = UIStackView(arrangedSubviews: [descriptions, power]); body.axis = .horizontal; body.spacing = 14; body.alignment = .center
        let contents = UIStackView(arrangedSubviews: [heading, body]); contents.axis = .vertical; contents.spacing = 12
        contents.translatesAutoresizingMaskIntoConstraints = false; card.addSubview(contents)
        NSLayoutConstraint.activate([status.widthAnchor.constraint(lessThanOrEqualTo: card.widthAnchor, multiplier: 0.45), contents.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16), contents.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16), contents.topAnchor.constraint(equalTo: card.topAnchor, constant: 16), contents.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16)])
        power.setImage(UIImage(systemName: "power", withConfiguration: UIImage.SymbolConfiguration(pointSize: 37, weight: .semibold)), for: .normal)
        power.backgroundColor = VPN013Theme.selected; power.layer.cornerRadius = 36
        power.accessibilityIdentifier = "vpn013.proxy.current.power"
        power.addTarget(self, action: #selector(powerTapped), for: .touchUpInside)
        NSLayoutConstraint.activate([power.widthAnchor.constraint(equalToConstant: 72), power.heightAnchor.constraint(equalToConstant: 72)])
        ping.setTitle("Проверить пинг", for: .normal); ping.setImage(UIImage(systemName: "waveform.path.ecg"), for: .normal)
        ping.titleLabel?.font = .preferredFont(forTextStyle: .headline); ping.titleLabel?.adjustsFontForContentSizeCategory = true
        ping.titleLabel?.numberOfLines = 0; ping.backgroundColor = VPN013Theme.accent; ping.tintColor = VPN013Theme.background
        ping.layer.cornerRadius = 12; ping.contentEdgeInsets = UIEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
        ping.accessibilityIdentifier = "vpn013.proxy.current.ping"
        ping.addTarget(self, action: #selector(pingTapped), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [card, ping, note]); stack.axis = .vertical; stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false; addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20), stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20), stack.topAnchor.constraint(equalTo: topAnchor, constant: 12), stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -20)])
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func update(name title: String, status state: String, detail text: String, routing policy: String, statistics traffic: String?, on: Bool, powerEnabled: Bool, pingEnabled: Bool, checkingPing: Bool) {
        name.text = title; status.text = state; detail.text = text; routing.text = policy
        statistics.text = traffic; statistics.isHidden = traffic == nil
        power.tintColor = on ? VPN013Theme.accent : VPN013Theme.secondaryText; power.isEnabled = powerEnabled
        power.accessibilityLabel = on ? "Отключить VPN" : "Подключить VPN"
        power.accessibilityValue = state
        ping.isEnabled = pingEnabled; ping.alpha = pingEnabled ? 1 : 0.5
        ping.setTitle(checkingPing ? "Отменить проверку пинга" : "Проверить пинг", for: .normal)
    }
    @objc private func powerTapped() { powerAction?() }
    @objc private func pingTapped() { pingAction?() }
}

final class ProxyListViewController: UITableViewController {
    private let kind: VPN013ConnectionKind
    private let manager = ProxyProfilesManager.shared
    private var observer: NSObjectProtocol?
    private let automaticHeader = AutomaticModeRow()
    private let connectionPanel = ProxyConnectionPanel()
    private let panelPing = EndpointPingCoordinator()
    private var panelTimer: Timer?
    private var panelRequest = UUID()
    private var panelInFlight = false
    private var panelIdentity: UUID?
    private var panelTraffic: ProxyTraffic?
    private var panelRates = VPN013TrafficSampler()
    private var panelRate: VPN013TrafficSampler.Rate?
    private var pingValues: [String: EndpointPingResult] = [:]
    private var pingBusy = false
    private var panelPingRequest = UUID()
    private var rows: [ProxyProfilesManager.Entry] { manager.entries.filter { $0.value.profile.source == kind } }
    private var panelEntry: ProxyProfilesManager.Entry? {
        if let active = rows.first(where: { $0.inOperation }) { return active }
        let remembered = UserDefaults.standard.string(forKey: "vpn013.panel.profile." + kind.rawValue)
        return rows.first(where: { $0.value.profile.id.uuidString == remembered }) ?? rows.first
    }
    init(kind: VPN013ConnectionKind) { self.kind = kind; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); navigationItem.title = "VPN013"; view.backgroundColor = VPN013Theme.background
        tableView.register(ProxyServerListCell.self, forCellReuseIdentifier: "vpn013.proxy.server-cell")
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-unified") { navigationItem.prompt = "Тестовые данные · VPN не запускается" }
        #endif
        tableView.backgroundColor = VPN013Theme.background; tableView.separatorColor = VPN013Theme.separator
        let add = UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(importTapped))
        add.accessibilityLabel = "Добавить конфигурацию " + kind.title
        add.accessibilityIdentifier = "vpn013.proxy.add"
        let invite = UIBarButtonItem(image: UIImage(systemName: "person.badge.plus"), style: .plain, target: self, action: #selector(inviteFriend))
        invite.accessibilityLabel = "Пригласить друга"; invite.accessibilityIdentifier = "vpn013.invite"
        navigationItem.rightBarButtonItems = [add, invite]
        let settings = UIBarButtonItem(image: UIImage(systemName: "gearshape"), style: .plain, target: self, action: #selector(openSettings))
        settings.accessibilityLabel = "Настройки"; settings.accessibilityIdentifier = "vpn013.settings"
        navigationItem.leftBarButtonItems = [settings, UIBarButtonItem(customView: automaticHeader)]
        #if targetEnvironment(simulator) && DEBUG
        if ProcessInfo.processInfo.arguments.contains("--vpn013-test-subscription-roster") {
            navigationItem.leftBarButtonItem = UIBarButtonItem(title: "Проверить подписки", style: .plain, target: self, action: #selector(testSubscriptionRoster))
            navigationItem.leftBarButtonItem?.accessibilityIdentifier = "vpn013.subscription.fixture"
        }
        #endif
        connectionPanel.powerAction = { [weak self] in guard let self = self, let entry = self.panelEntry else { return }; self.manager.toggle(entry) }
        connectionPanel.pingAction = { [weak self] in self?.checkPanelPing() }
        tableView.tableHeaderView = connectionPanel
        observer = NotificationCenter.default.addObserver(forName: .vpn013ProxyChanged, object: nil, queue: .main) { [weak self] _ in self?.tableView.reloadData(); self?.refreshPanel() }
        refreshControl = UIRefreshControl(); refreshControl?.addTarget(self, action: #selector(refreshProfiles), for: .valueChanged)
        renderPanel()
    }
    deinit { if let token = observer { NotificationCenter.default.removeObserver(token) }; panelTimer?.invalidate(); panelPing.cancel() }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated); tableView.reloadData()
        panelTimer?.invalidate(); panelTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshPanel() }
        refreshPanel()
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated); panelTimer?.invalidate(); panelTimer = nil
        panelRequest = UUID(); panelInFlight = false; panelTraffic = nil; panelRates.reset(); panelRate = nil
        panelPingRequest = UUID(); panelPing.cancel(); pingBusy = false
    }
    private func renderPanel() {
        let entry = panelEntry, running = entry?.status == .connected
        let actual = running ? panelTraffic : nil
        let title = actual?.selectedName ?? (running && VPN013AutomaticMode.enabled() ? "Текущий сервер" : entry?.value.profile.name ?? "Нет конфигураций")
        let state = entry.map { $0.status == .disconnected || $0.status == .invalid ? "Не подключено" : ProxyDetailViewController.statusText($0.status) } ?? "Не подключено"
        var detail = entry == nil ? "Добавьте конфигурацию кнопкой +" : running ? actual?.selectedEndpoint ?? "Ожидаем данные текущего сервера" : "Нажмите кнопку питания, чтобы подключиться."
        let pingHost = actual.flatMap { value in entry?.value.candidates.first(where: { $0.endpoint == value.selectedEndpoint })?.host } ?? (running ? nil : entry?.value.profile.host)
        if let host = pingHost, let result = pingValues[host] { detail += "\nПинг адреса: " + result.text }
        let policy = entry?.value.routing.mode.title ?? "Выберите конфигурацию ниже"
        let traffic = actual.map { value in "Скорость: ↓ " + VPN013TrafficDisplay.speed(panelRate?.received) + " · ↑ " + VPN013TrafficDisplay.speed(panelRate?.sent) + "\nВсего: ↓ " + VPN013TrafficDisplay.amount(value.rx >= 0 ? UInt64(value.rx) : nil) + " · ↑ " + VPN013TrafficDisplay.amount(value.tx >= 0 ? UInt64(value.tx) : nil) }
        connectionPanel.update(name: title, status: state, detail: detail, routing: policy, statistics: traffic,
            on: entry?.inOperation == true, powerEnabled: entry != nil && (entry?.inOperation == true || !manager.working),
            pingEnabled: pingBusy || !rows.isEmpty, checkingPing: pingBusy)
        tableView.setNeedsLayout()
    }
    private func refreshPanel() {
        let entry = panelEntry
        if panelIdentity != entry?.value.profile.id {
            panelIdentity = entry?.value.profile.id; panelRequest = UUID(); panelInFlight = false
            panelTraffic = nil; panelRates.reset(); panelRate = nil
        }
        if entry?.status != .connected { panelRequest = UUID(); panelInFlight = false; panelTraffic = nil; panelRates.reset(); panelRate = nil }
        renderPanel()
        guard panelTimer != nil, viewIfLoaded?.window != nil, !panelInFlight, let current = entry, current.status == .connected else { return }
        let request = UUID(); panelRequest = request; panelInFlight = true
        manager.traffic(current) { [weak self] value in
            guard let self = self, self.panelRequest == request, self.panelEntry?.value.profile.id == current.value.profile.id, self.panelEntry?.status == .connected else { return }
            self.panelInFlight = false; self.panelTraffic = value
            self.panelRate = self.panelRates.sample(identity: current.value.profile.id.uuidString + "|" + String(current.manager.connection.connectedDate?.timeIntervalSince1970 ?? 0) + "|" + (value?.selectedEndpoint ?? ""), time: ProcessInfo.processInfo.systemUptime,
                received: value.flatMap { $0.rx >= 0 ? UInt64($0.rx) : nil }, sent: value.flatMap { $0.tx >= 0 ? UInt64($0.tx) : nil })
            self.renderPanel()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
            guard let self = self, self.panelRequest == request, self.panelInFlight else { return }
            self.panelRequest = UUID(); self.panelInFlight = false; self.panelTraffic = nil; self.panelRates.reset(); self.panelRate = nil; self.renderPanel()
        }
    }
    private func checkPanelPing() {
        if pingBusy { panelPingRequest = UUID(); panelPing.cancel(); pingBusy = false; renderPanel(); return }
        let hosts = rows.map { $0.value.profile.host }; guard !hosts.isEmpty else { return }
        let request = UUID(); panelPingRequest = request; pingBusy = true; pingValues = [:]; renderPanel()
        panelPing.start(hosts: hosts, update: { [weak self] host, result in
            guard let self = self, self.panelPingRequest == request else { return }; self.pingValues[host] = result; self.renderPanel(); self.tableView.reloadData()
        }, completion: { [weak self] in
            guard let self = self, self.panelPingRequest == request else { return }; self.pingBusy = false; self.renderPanel()
        })
    }
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
    @objc private func openSettings() { VPN013SettingsPresentation.show(from: self, kind: kind) }
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
        let cell = rows.isEmpty ? UITableViewCell(style: .subtitle, reuseIdentifier: nil) : tableView.dequeueReusableCell(withIdentifier: "vpn013.proxy.server-cell", for: indexPath)
        cell.backgroundColor = VPN013Theme.background; cell.textLabel?.textColor = VPN013Theme.text; cell.detailTextLabel?.textColor = VPN013Theme.secondaryText
        cell.textLabel?.font = .preferredFont(forTextStyle: .headline); cell.textLabel?.adjustsFontForContentSizeCategory = true
        cell.textLabel?.numberOfLines = 0; cell.detailTextLabel?.numberOfLines = 0
        if rows.isEmpty { cell.textLabel?.text = "Добавить конфигурацию"; cell.detailTextLabel?.text = "Из буфера, файла или ссылки подписки"; cell.imageView?.image = UIImage(systemName: "plus.circle") }
        else {
            let entry = rows[indexPath.row]; cell.textLabel?.text = entry.value.profile.name
            cell.detailTextLabel?.text = entry.value.profile.endpoint + "\n" + ProxyDetailViewController.statusText(entry.status)
            if let result = pingValues[entry.value.profile.host] { cell.detailTextLabel?.text?.append("\nПинг адреса: " + result.text) }
            cell.imageView?.image = UIImage(systemName: "globe", withConfiguration: UIImage.SymbolConfiguration(pointSize: 28, weight: .regular))
            if let serverCell = cell as? ProxyServerListCell {
                serverCell.configure(name: entry.value.profile.name)
                serverCell.openConfiguration = { [weak self] in
                    guard let self = self, let current = self.rows.first(where: { $0.value.profile.id == entry.value.profile.id }) else { return }
                    UserDefaults.standard.set(current.value.profile.id.uuidString, forKey: "vpn013.panel.profile." + self.kind.rawValue)
                    self.refreshPanel(); self.navigationController?.pushViewController(ProxyDetailViewController(id: current.value.profile.id), animated: true)
                }
            }
            cell.accessibilityHint = "Нажмите строку для подключения. Кнопка справа открывает конфигурацию."
        }
        cell.imageView?.tintColor = VPN013Theme.accent; cell.accessoryType = rows.isEmpty ? .disclosureIndicator : .none
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        if rows.isEmpty { importTapped() }
        else {
            let entry = rows[indexPath.row]
            UserDefaults.standard.set(entry.value.profile.id.uuidString, forKey: "vpn013.panel.profile." + kind.rawValue)
            refreshPanel(); manager.toggle(entry)
        }
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
    private var trafficSampler = VPN013TrafficSampler()
    private var trafficRate: VPN013TrafficSampler.Rate?
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
        let settings = UIBarButtonItem(image: UIImage(systemName: "gearshape"), style: .plain, target: self, action: #selector(openSettings))
        settings.accessibilityLabel = "Настройки"; settings.accessibilityIdentifier = "vpn013.settings"
        navigationItem.rightBarButtonItem = settings
        observer = NotificationCenter.default.addObserver(forName: .vpn013ProxyChanged, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }; self.invalidateTraffic(); self.tableView.reloadData(); self.readTraffic()
        }
    }
    deinit { if let token = observer { NotificationCenter.default.removeObserver(token) }; timer?.invalidate() }
    @objc private func openSettings() { VPN013SettingsPresentation.show(from: self, kind: entry?.value.profile.source) }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated); title = entry?.value.profile.name ?? "Подключение"
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.readTraffic() }; readTraffic()
    }
    override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); timer?.invalidate(); timer = nil; invalidateTraffic() }
    private func invalidateTraffic() { trafficRequest = UUID(); trafficInFlight = false; traffic = nil; trafficSampler.reset(); trafficRate = nil }
    private func readTraffic() {
        guard viewIfLoaded?.window != nil, !trafficInFlight, let entry = entry, entry.status == .connected else { return }
        let request = UUID(); trafficRequest = request; trafficInFlight = true
        manager.traffic(entry) { [weak self] value in
            guard let self = self, self.trafficRequest == request, self.entry?.status == .connected else { return }
            self.trafficInFlight = false; self.traffic = value
            self.trafficRate = self.trafficSampler.sample(identity: self.id.uuidString + "|" + (value?.selectedEndpoint ?? ""),
                time: ProcessInfo.processInfo.systemUptime,
                received: value.flatMap { $0.running && $0.rx >= 0 ? UInt64($0.rx) : nil },
                sent: value.flatMap { $0.running && $0.tx >= 0 ? UInt64($0.tx) : nil })
            self.tableView.reloadData()
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
                cell.detailTextLabel?.text = "Скорость: ↓ " + VPN013TrafficDisplay.speed(trafficRate?.received) + " · ↑ " + VPN013TrafficDisplay.speed(trafficRate?.sent) +
                    "\nВсего: ↓ " + VPN013TrafficDisplay.amount(value.rx >= 0 ? UInt64(value.rx) : nil) + " · ↑ " + VPN013TrafficDisplay.amount(value.tx >= 0 ? UInt64(value.tx) : nil)
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
    private let entries: [ProxyProfilesManager.Entry]
    private var entry: ProxyProfilesManager.Entry { entries[0] }
    private let modes = UIButton(type: .system)
    private var selectedMode: ProxyRoutingPolicy.Mode
    private let domains = UITextView(); private let networks = UITextView()
    convenience init(entry: ProxyProfilesManager.Entry) { self.init(entries: [entry]) }
    init(entries: [ProxyProfilesManager.Entry]) { precondition(!entries.isEmpty); self.entries = entries; selectedMode = entries[0].value.routing.mode; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Маршрутизация"; view.backgroundColor = VPN013Theme.background
        if entries.count > 1 { navigationItem.prompt = "Один набор правил для серверов: \(entries.count)" }
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Сохранить", style: .done, target: self, action: #selector(save))
        navigationItem.rightBarButtonItem?.accessibilityIdentifier = "vpn013.proxy.routing.save"
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
            ProxyProfilesManager.shared.update(entries, routing: policy) { [weak self] error in
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
