// SPDX-License-Identifier: MIT
import UIKit

/// Catalog displays only friendly service metadata. No technical rule is ever
/// rendered here. State stays local until the explicit Save operation.
final class ServiceRoutingViewController: UITableViewController, UISearchResultsUpdating {
    private let saveSelection: (ServiceRoutingSelection, @escaping (Error?) -> Void) -> Void
    private let wireGuard: Bool
    private let catalog: ServiceRoutingCatalog
    private var selection: ServiceRoutingSelection
    private var groups: [ServiceCatalogGroup] = []
    private var expanded = Set<String>()
    private let search = UISearchController(searchResultsController: nil)
    private let only = UISwitch()
    private let bypass = UISwitch()

    init(entries: [ProxyProfilesManager.Entry], catalog: ServiceRoutingCatalog) {
        precondition(!entries.isEmpty)
        self.catalog = catalog; self.wireGuard = false
        self.saveSelection = { selection, completion in ProxyProfilesManager.shared.update(entries, services: selection, completion: completion) }
        self.selection = entries[0].value.routing.serviceSelection ?? ServiceRoutingSelection()
        super.init(style: .insetGrouped)
    }
    init(targets: [WireGuardRoutingTarget], manager: TunnelsManager, catalog: ServiceRoutingCatalog) {
        precondition(!targets.isEmpty)
        self.catalog = catalog; self.wireGuard = true
        self.selection = targets[0].selection
        self.saveSelection = { selection, completion in manager.updateServiceRouting(targets, selection: selection, completion: completion) }
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad(); title = "Сервисы"; view.backgroundColor = VPN013Theme.background
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Сохранить", style: .done, target: self, action: #selector(save))
        navigationItem.rightBarButtonItem?.accessibilityIdentifier = "vpn013.services.save"
        only.accessibilityIdentifier = "vpn013.services.only"; bypass.accessibilityIdentifier = "vpn013.services.bypass"
        only.accessibilityLabel = "VPN только для выбранных сервисов"
        bypass.accessibilityLabel = "Выбранные сервисы без VPN"
        only.addTarget(self, action: #selector(onlyChanged), for: .valueChanged)
        bypass.addTarget(self, action: #selector(bypassChanged), for: .valueChanged)
        search.obscuresBackgroundDuringPresentation = false; search.searchResultsUpdater = self
        search.hidesNavigationBarDuringPresentation = false
        search.searchBar.placeholder = "Найти сервис"; navigationItem.searchController = search
        navigationItem.hidesSearchBarWhenScrolling = false; definesPresentationContext = true
        refresh()
    }
    @objc private func onlyChanged() { selection.setOnly(only.isOn); refresh() }
    @objc private func bypassChanged() { selection.setBypass(bypass.isOn); refresh() }
    private func refresh() {
        only.isOn = selection.mode == .only; bypass.isOn = selection.mode == .bypass
        groups = catalog.displayGroups(matching: search.searchBar.text ?? "")
        tableView.reloadData()
    }
    func updateSearchResults(for searchController: UISearchController) { refresh() }
    override func numberOfSections(in tableView: UITableView) -> Int { groups.count + 1 }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if section == 0 { return 2 }
        let group = groups[section - 1]
        return expanded.contains(group.id) || !(search.searchBar.text ?? "").isEmpty ? group.services.count : 0
    }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        guard section == 0 else { return nil }
        if wireGuard {
            return "Правила IPv4-сетей выбранных сервисов применяются только к отмеченным серверам при следующем подключении. IPv6 сохраняет прежние правила; DNS остаётся в VPN. Оба режима выключены — прежняя маршрутизация каждого сервера. Действующий VPN не прерывается. Сервис без IP-сетей отмечен как недоступный для WireGuard."
        }
        return "Выберите сервисы по названиям. Один режим исключает другой. Оба выключены — сохраняются прежние правила каждого сервера. Правила применяются после сохранения при следующем подключении; действующий VPN не прерывается. На iPhone это маршрутизация сервисов, а не выбор установленных приложений."
    }
    override func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        guard section > 0 else { return nil }
        let group = groups[section - 1]
        let button = UIButton(type: .system)
        button.contentHorizontalAlignment = .leading
        button.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        button.titleLabel?.adjustsFontForContentSizeCategory = true; button.titleLabel?.numberOfLines = 0
        button.setTitle("\(expanded.contains(group.id) ? "▾" : "▸") \(group.title)", for: .normal)
        button.accessibilityIdentifier = "vpn013.services.group.\(group.id)"
        button.addAction(UIAction { [weak self] _ in
            guard let self = self else { return }
            if !self.expanded.insert(group.id).inserted { self.expanded.remove(group.id) }
            self.tableView.reloadData()
        }, for: .touchUpInside)
        return button
    }
    override func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        guard section > 0 else { return 16 }
        let size = ("▸ " + groups[section - 1].title).boundingRect(with: CGSize(width: max(100, tableView.bounds.width - 64), height: .greatestFiniteMagnitude), options: [.usesLineFragmentOrigin], attributes: [.font: UIFont.preferredFont(forTextStyle: .headline)], context: nil)
        return max(64, ceil(size.height) + 24)
    }
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.background; cell.textLabel?.textColor = VPN013Theme.text
        cell.textLabel?.font = .preferredFont(forTextStyle: .body); cell.textLabel?.adjustsFontForContentSizeCategory = true
        cell.textLabel?.numberOfLines = 0
        if indexPath.section == 0 {
            cell.textLabel?.text = indexPath.row == 0 ? "VPN только для выбранных сервисов" : "Выбранные сервисы без VPN"
            cell.accessoryView = indexPath.row == 0 ? only : bypass; cell.selectionStyle = .none
        } else {
            let service = groups[indexPath.section - 1].services[indexPath.row]
            cell.textLabel?.text = "\(service.icon.text)  \(service.name)"
            cell.isAccessibilityElement = true
            cell.accessibilityLabel = service.name
            cell.accessibilityIdentifier = "vpn013.services.item.\(service.id)"
            cell.accessoryType = selection.activeIDs.contains(service.id) ? .checkmark : .none
            cell.accessibilityValue = selection.activeIDs.contains(service.id) ? "Выбрано" : "Не выбрано"
            let supported = !wireGuard || catalog.supportsWireGuard(service.id)
            if !supported { cell.detailTextLabel?.text = "Недоступен для WireGuard"; cell.accessibilityValue = "Недоступен для WireGuard" }
            cell.isUserInteractionEnabled = selection.mode != .unchanged && supported
            cell.contentView.alpha = selection.mode == .unchanged || !supported ? 0.5 : 1
        }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section > 0, selection.mode != .unchanged else { return }
        let id = groups[indexPath.section - 1].services[indexPath.row].id
        guard !wireGuard || catalog.supportsWireGuard(id) else { return }
        selection.toggle(id); tableView.reloadRows(at: [indexPath], with: .none)
    }
    @objc private func save() {
        do {
            if wireGuard { _ = try catalog.resolveWireGuard(selection) } else { _ = try catalog.resolve(selection) }
            navigationItem.rightBarButtonItem?.isEnabled = false
            saveSelection(selection) { [weak self] error in
                guard let self = self else { return }
                self.navigationItem.rightBarButtonItem?.isEnabled = true
                if let error = error { self.show(error) } else { self.navigationController?.popToRootViewController(animated: true) }
            }
        } catch { show(error) }
    }
    private func show(_ error: Error) {
        let alert = UIAlertController(title: "Правила не сохранены", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}

final class WireGuardRoutingProfilesViewController: UITableViewController {
    private let manager: TunnelsManager
    private var targets: [WireGuardRoutingTarget] = []
    private var selected = Set<String>()
    private let all = UIButton(type: .system)
    private var nextButton: UIBarButtonItem!
    init(manager: TunnelsManager) { self.manager = manager; super.init(style: .insetGrouped) }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func viewDidLoad() {
        super.viewDidLoad(); title = "Маршрутизация"; tableView.backgroundColor = VPN013Theme.background
        tableView.tintColor = VPN013Theme.accent
        nextButton = UIBarButtonItem(title: "Далее", style: .done, target: self, action: #selector(nextTapped))
        nextButton.accessibilityIdentifier = "vpn013.routing.next"; navigationItem.rightBarButtonItem = nextButton
        let header = UIView(); all.translatesAutoresizingMaskIntoConstraints = false; header.addSubview(all)
        all.tintColor = VPN013Theme.accent; all.contentHorizontalAlignment = .leading
        all.titleLabel?.font = .preferredFont(forTextStyle: .headline); all.titleLabel?.adjustsFontForContentSizeCategory = true
        all.titleLabel?.numberOfLines = 0; all.accessibilityIdentifier = "vpn013.routing.select-all"
        all.addTarget(self, action: #selector(allTapped), for: .touchUpInside)
        NSLayoutConstraint.activate([all.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 20), all.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -20), all.topAnchor.constraint(equalTo: header.topAnchor, constant: 12), all.bottomAnchor.constraint(equalTo: header.bottomAnchor, constant: -12), all.heightAnchor.constraint(greaterThanOrEqualToConstant: 44)])
        tableView.tableHeaderView = header; refresh()
    }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        do { targets = try manager.serviceRoutingTargets(); selected.formIntersection(targets.map { $0.id }); refresh(); tableView.reloadData() }
        catch { show(error) }
    }
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews(); guard let header = tableView.tableHeaderView else { return }
        let height = header.systemLayoutSizeFitting(CGSize(width: tableView.bounds.width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel).height
        if abs(header.frame.height - height) > 0.5 { header.frame.size = CGSize(width: tableView.bounds.width, height: height); tableView.tableHeaderView = header }
    }
    private func refresh() {
        all.setTitle(!targets.isEmpty && selected.count == targets.count ? "Снять выбор" : "Выбрать все", for: .normal)
        all.isEnabled = !targets.isEmpty; nextButton.isEnabled = !selected.isEmpty
        nextButton.title = selected.isEmpty ? "Далее" : "Далее (\(selected.count))"
        navigationItem.prompt = "WireGuard / AmneziaWG · Выбрано: \(selected.count)"
    }
    @objc private func allTapped() {
        selected = !targets.isEmpty && selected.count == targets.count ? [] : Set(targets.map { $0.id })
        refresh(); tableView.reloadData()
    }
    @objc private func nextTapped() {
        let values = targets.filter { selected.contains($0.id) }; guard !values.isEmpty else { return }
        do { navigationController?.pushViewController(ServiceRoutingViewController(targets: values, manager: manager, catalog: try ServiceRoutingCatalog.shared.get()), animated: true) }
        catch { show(error) }
    }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { max(1, targets.count) }
    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        "Отметьте серверы и нажмите «Далее». Правила остальных серверов сохраняются. Выбор профиля «Авто» относится ко всем серверам внутри этого профиля."
    }
    override func tableView(_ tableView: UITableView, cellForRowAt path: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        cell.backgroundColor = VPN013Theme.surface; cell.textLabel?.textColor = VPN013Theme.text
        cell.textLabel?.font = .preferredFont(forTextStyle: .body); cell.textLabel?.adjustsFontForContentSizeCategory = true; cell.textLabel?.numberOfLines = 0
        guard targets.indices.contains(path.row) else { cell.textLabel?.text = "Сначала добавьте конфигурацию"; cell.selectionStyle = .none; return cell }
        let target = targets[path.row], checked = selected.contains(targets[path.row].id)
        cell.textLabel?.text = target.tunnel.name; cell.isAccessibilityElement = true; cell.accessibilityLabel = target.tunnel.name
        cell.accessibilityIdentifier = "vpn013.routing.wg-server." + target.id
        cell.accessibilityValue = checked ? "Выбран" : "Не выбран"; cell.accessoryType = checked ? .checkmark : .none
        if checked { cell.accessibilityTraits.insert(.selected) }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt path: IndexPath) {
        tableView.deselectRow(at: path, animated: true); guard targets.indices.contains(path.row) else { return }
        let id = targets[path.row].id
        if !selected.insert(id).inserted { selected.remove(id) }
        refresh(); tableView.reloadRows(at: [path], with: .none)
    }
    private func show(_ error: Error) {
        let alert = UIAlertController(title: "Маршрутизация недоступна", message: error.localizedDescription, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Понятно", style: .default)); present(alert, animated: true)
    }
}
