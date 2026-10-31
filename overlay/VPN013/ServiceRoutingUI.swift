// SPDX-License-Identifier: MIT
import UIKit

/// Catalog displays only friendly service metadata. No technical rule is ever
/// rendered here. State stays local until the explicit Save operation.
final class ServiceRoutingViewController: UITableViewController, UISearchResultsUpdating {
    private let entries: [ProxyProfilesManager.Entry]
    private let catalog: ServiceRoutingCatalog
    private var selection: ServiceRoutingSelection
    private var groups: [ServiceCatalogGroup] = []
    private var expanded = Set<String>()
    private let search = UISearchController(searchResultsController: nil)
    private let only = UISwitch()
    private let bypass = UISwitch()

    init(entries: [ProxyProfilesManager.Entry], catalog: ServiceRoutingCatalog) {
        precondition(!entries.isEmpty)
        self.entries = entries; self.catalog = catalog
        self.selection = entries[0].value.routing.serviceSelection ?? ServiceRoutingSelection()
        super.init(style: .insetGrouped)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func viewDidLoad() {
        super.viewDidLoad(); title = "Сервисы"; view.backgroundColor = VPN013Theme.background
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "Сохранить", style: .done, target: self, action: #selector(save))
        navigationItem.rightBarButtonItem?.accessibilityIdentifier = "vpn013.services.save"
        only.accessibilityIdentifier = "vpn013.services.only"; bypass.accessibilityIdentifier = "vpn013.services.bypass"
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
            cell.accessibilityIdentifier = "vpn013.services.item.\(service.id)"
            cell.accessoryType = selection.activeIDs.contains(service.id) ? .checkmark : .none
            cell.accessibilityValue = selection.activeIDs.contains(service.id) ? "Выбрано" : "Не выбрано"
            cell.isUserInteractionEnabled = selection.mode != .unchanged
            cell.contentView.alpha = selection.mode == .unchanged ? 0.5 : 1
        }
        return cell
    }
    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section > 0, selection.mode != .unchanged else { return }
        selection.toggle(groups[indexPath.section - 1].services[indexPath.row].id); tableView.reloadRows(at: [indexPath], with: .none)
    }
    @objc private func save() {
        do {
            _ = try catalog.resolve(selection)
            navigationItem.rightBarButtonItem?.isEnabled = false
            ProxyProfilesManager.shared.update(entries, services: selection) { [weak self] error in
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
