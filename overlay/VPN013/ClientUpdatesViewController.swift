// SPDX-License-Identifier: MIT
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
    @objc private func close() { dismiss(animated: true) }
    override func numberOfSections(in tableView: UITableView) -> Int { 3 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        #if DEBUG && targetEnvironment(simulator)
        if section == 2 && ProcessInfo.processInfo.arguments.contains("--vpn013-test-sync") { return 2 }
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
                cell.textLabel?.text = "Скачать обновление в боте"
                cell.detailTextLabel?.text = "iOS: скачайте IPA, подпишите своей подписью и установите."
                cell.textLabel?.textColor = VPN013Theme.accent
                cell.accessibilityIdentifier = "vpn013.update-download"
                cell.accessoryType = .disclosureIndicator
                cell.accessibilityTraits.insert(.button)
            }
        } else if path.section == 1 {
            let orders = coordinator.registry.bindings.keys.sorted()
            if orders.isEmpty {
                cell.textLabel?.text = "Пока нет привязанных заявок"
                cell.detailTextLabel?.text = "Скачайте свежий ZIP из раздела «Мои заявки» в боте и импортируйте в VPN013 WG."
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
        if path.row == 2 { UIApplication.shared.open(ClientUpdateProtocol.botURL) }
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

extension TunnelsListTableViewController {
    @objc func clientUpdatesTapped() {
        guard let manager = tunnelsManager else { return }
        let controller = UINavigationController(rootViewController: ClientUpdatesViewController(manager: manager))
        controller.modalPresentationStyle = .formSheet
        present(controller, animated: true)
    }
}
