// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import UIKit
import MobileCoreServices
import UserNotifications

class TunnelsListTableViewController: UIViewController {

    var tunnelsManager: TunnelsManager?

    enum TableState: Equatable {
        case normal
        case rowSwiped
        case multiSelect(selectionCount: Int)
    }

    let tableView: UITableView = {
        let tableView = UITableView(frame: CGRect.zero, style: .insetGrouped)
        tableView.estimatedRowHeight = 64
        tableView.rowHeight = UITableView.automaticDimension
        tableView.sectionHeaderHeight = UITableView.automaticDimension
        tableView.estimatedSectionHeaderHeight = 40
        tableView.separatorStyle = .singleLine
        tableView.backgroundColor = VPN013Theme.background
        tableView.separatorColor = VPN013Theme.separator
        tableView.indicatorStyle = .white
        tableView.register(TunnelListCell.self)
        return tableView
    }()

    let centeredAddButton: BorderedTextButton = {
        let button = BorderedTextButton()
        button.title = tr("tunnelsListCenteredAddTunnelButtonTitle")
        button.button.accessibilityIdentifier = "addEmptyStateButton"
        button.isHidden = true
        return button
    }()

    let busyIndicator: UIActivityIndicatorView = {
        let busyIndicator: UIActivityIndicatorView
        busyIndicator = UIActivityIndicatorView(style: .medium)
        busyIndicator.hidesWhenStopped = true
        return busyIndicator
    }()

    private let summaryHeader = UIView()
    private let appTitleLabel = TunnelsListTableViewController.makeLabel(style: .title2, weight: .semibold)
    private let summaryStatusLabel = TunnelsListTableViewController.makeLabel(style: .caption1)
    private let summaryNameLabel = TunnelsListTableViewController.makeLabel(style: .title3, weight: .semibold)
    private let summaryIdentityRow = UIStackView()
    private let summaryModeLabel = TunnelsListTableViewController.makeLabel(style: .subheadline, color: VPN013Theme.secondaryText)
    private let summaryProofLabel = TunnelsListTableViewController.makeLabel(style: .footnote, color: VPN013Theme.secondaryText)
    private let emptyStateLabel = TunnelsListTableViewController.makeLabel(style: .body, color: VPN013Theme.secondaryText)
    private let emptyStateStack = UIStackView()
    private let emptyStateContainer = UIView()
    private let checkAllButton = UIButton(type: .system)
    private let developerFooter = UIView()
    private var summaryObservations: [NSKeyValueObservation] = []
    private var automaticSummaryTimer: Timer?
    private var automaticSummaryRequestInFlight = false
    private var automaticSummaryRequestID = UUID()
    private var automaticSummaryTunnel: TunnelContainer?
    private var automaticSummaryName: String?
    private var automaticSummaryPhase: String?
    private var connectionTestResults: [ObjectIdentifier: String] = [:]

    /// Installed by the real test coordinator. With no coordinator, the action stays hidden.
    var onCheckAllServers: (() -> Void)? {
        didSet {
            guard isViewLoaded else { return }
            checkAllButton.isHidden = onCheckAllServers == nil
            sizeSummaryHeader()
        }
    }

    private static func makeLabel(style: UIFont.TextStyle, weight: UIFont.Weight? = nil, color: UIColor = VPN013Theme.text) -> UILabel {
        let label = UILabel()
        let font = UIFont.preferredFont(forTextStyle: style)
        if let weight = weight {
            let base = UIFont.preferredFont(forTextStyle: style, compatibleWith: UITraitCollection(preferredContentSizeCategory: .large))
            label.font = UIFontMetrics(forTextStyle: style).scaledFont(for: .systemFont(ofSize: base.pointSize, weight: weight))
        } else {
            label.font = font
        }
        label.adjustsFontForContentSizeCategory = true
        label.numberOfLines = 0
        label.textColor = color
        return label
    }

    var detailDisplayedTunnel: TunnelContainer?
    var tableState: TableState = .normal {
        didSet {
            handleTableStateChange()
        }
    }

    override func loadView() {
        view = UIView()
        overrideUserInterfaceStyle = .dark
        view.backgroundColor = VPN013Theme.background
        view.tintColor = VPN013Theme.accent
        busyIndicator.color = VPN013Theme.accent
        centeredAddButton.button.tintColor = VPN013Theme.accent
        centeredAddButton.layer.borderColor = VPN013Theme.accent.cgColor

        tableView.dataSource = self
        tableView.delegate = self

        view.addSubview(tableView)
        tableView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.topAnchor.constraint(equalTo: view.topAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])

        configureSummaryHeader()
        configureDeveloperFooter()

        view.addSubview(busyIndicator)
        busyIndicator.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            busyIndicator.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            busyIndicator.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])

        centeredAddButton.onTapped = { [weak self] in
            guard let self = self else { return }
            self.addButtonTapped(sender: self.centeredAddButton)
        }

        if tunnelsManager == nil { busyIndicator.startAnimating() }
        updateEmptyState()
        updateConnectionSummary()
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        tableState = .normal
        restorationIdentifier = "TunnelsListVC"
        navigationItem.largeTitleDisplayMode = .never
        navigationController?.navigationBar.prefersLargeTitles = false
        navigationItem.standardAppearance = VPN013Theme.navigationAppearance()
        navigationItem.scrollEdgeAppearance = VPN013Theme.navigationAppearance()
        navigationItem.compactAppearance = VPN013Theme.navigationAppearance()
        navigationController?.navigationBar.tintColor = VPN013Theme.accent
    }

    func handleTableStateChange() {
        navigationItem.titleView = nil
        switch tableState {
        case .normal:
            appTitleLabel.text = "VPN013 WG"
            appTitleLabel.numberOfLines = 1
            navigationItem.titleView = appTitleLabel
            let addButton = UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addButtonTapped(sender:)))
            addButton.accessibilityIdentifier = "vpn013.add-profile"
            addButton.accessibilityLabel = "Добавить конфигурацию"
            navigationItem.rightBarButtonItem = addButton
            let settings = UIBarButtonItem(image: UIImage(systemName: "gearshape"), style: .plain, target: self, action: #selector(settingsButtonTapped(sender:)))
            settings.accessibilityLabel = tr("tunnelsListSettingsButtonTitle")
            navigationItem.leftBarButtonItem = settings
        case .rowSwiped:
            navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(doneButtonTapped))
            navigationItem.leftBarButtonItem = UIBarButtonItem(title: tr("tunnelsListSelectButtonTitle"), style: .plain, target: self, action: #selector(selectButtonTapped))
        case .multiSelect(let selectionCount):
            if selectionCount > 0 {
                navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelButtonTapped))
                navigationItem.leftBarButtonItem = UIBarButtonItem(title: tr("tunnelsListDeleteButtonTitle"), style: .plain, target: self, action: #selector(deleteButtonTapped(sender:)))
            } else {
                navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelButtonTapped))
                navigationItem.leftBarButtonItem = UIBarButtonItem(title: tr("tunnelsListSelectAllButtonTitle"), style: .plain, target: self, action: #selector(selectAllButtonTapped))
            }
        }
        if case .multiSelect(let selectionCount) = tableState, selectionCount > 0 {
            navigationItem.title = tr(format: "tunnelsListSelectedTitle (%d)", selectionCount)
        } else {
            navigationItem.title = "VPN013 WG"
        }
        if case .multiSelect = tableState {
            tableView.allowsMultipleSelectionDuringEditing = true
        } else {
            tableView.allowsMultipleSelectionDuringEditing = false
        }
    }

    func setTunnelsManager(tunnelsManager: TunnelsManager) {
        self.tunnelsManager = tunnelsManager
        tunnelsManager.tunnelsListDelegate = self

        busyIndicator.stopAnimating()
        tableView.reloadData()
        observeConnectionSummary()
        updateEmptyState()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if let selectedRowIndexPath = tableView.indexPathForSelectedRow {
            tableView.deselectRow(at: selectedRowIndexPath, animated: false)
        }
        updateConnectionSummary()
        startAutomaticSummaryUpdates()
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        automaticSummaryTimer?.invalidate()
        automaticSummaryTimer = nil
    }

    deinit {
        automaticSummaryTimer?.invalidate()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        sizeSummaryHeader()
        sizeDeveloperFooter()
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        if previousTraitCollection?.preferredContentSizeCategory != traitCollection.preferredContentSizeCategory {
            updateSummaryIdentityLayout()
            sizeSummaryHeader()
            sizeDeveloperFooter()
            tableView.beginUpdates()
            tableView.endUpdates()
        }
    }

    private func configureSummaryHeader() {
        let summary = UIView()
        summary.backgroundColor = VPN013Theme.background
        summary.layer.cornerRadius = 14
        summary.layer.cornerCurve = .continuous
        summary.layer.borderWidth = 1
        summary.layer.borderColor = VPN013Theme.separator.cgColor
        summary.directionalLayoutMargins = NSDirectionalEdgeInsets(top: 16, leading: 16, bottom: 16, trailing: 16)
        summaryIdentityRow.addArrangedSubview(summaryNameLabel)
        summaryIdentityRow.addArrangedSubview(summaryStatusLabel)
        summaryIdentityRow.spacing = 12
        summaryNameLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        summaryStatusLabel.setContentHuggingPriority(.defaultHigh, for: .horizontal)
        updateSummaryIdentityLayout()
        let labels = UIStackView(arrangedSubviews: [summaryIdentityRow, summaryModeLabel, summaryProofLabel])
        labels.axis = .vertical
        labels.spacing = 5
        labels.translatesAutoresizingMaskIntoConstraints = false
        summary.addSubview(labels)
        NSLayoutConstraint.activate([
            labels.topAnchor.constraint(equalTo: summary.layoutMarginsGuide.topAnchor),
            labels.bottomAnchor.constraint(equalTo: summary.layoutMarginsGuide.bottomAnchor),
            labels.leadingAnchor.constraint(equalTo: summary.layoutMarginsGuide.leadingAnchor),
            labels.trailingAnchor.constraint(equalTo: summary.layoutMarginsGuide.trailingAnchor)
        ])
        var configuration = UIButton.Configuration.filled()
        configuration.title = "Проверить все"
        configuration.cornerStyle = .medium
        configuration.baseBackgroundColor = VPN013Theme.accent
        configuration.baseForegroundColor = VPN013Theme.background
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 13, leading: 16, bottom: 13, trailing: 16)
        checkAllButton.configuration = configuration
        checkAllButton.titleLabel?.adjustsFontForContentSizeCategory = true
        checkAllButton.titleLabel?.numberOfLines = 0
        checkAllButton.addTarget(self, action: #selector(checkAllServersTapped), for: .touchUpInside)
        checkAllButton.isHidden = onCheckAllServers == nil
        checkAllButton.accessibilityHint = "Проверить соединение с каждым сервером"
        let minimumButtonHeight = checkAllButton.heightAnchor.constraint(greaterThanOrEqualToConstant: 48)
        minimumButtonHeight.priority = .defaultHigh
        minimumButtonHeight.isActive = true
        emptyStateLabel.textAlignment = .center
        emptyStateLabel.text = "Добавьте конфигурацию сервера, чтобы подключить VPN."
        centeredAddButton.button.titleLabel?.numberOfLines = 0
        centeredAddButton.button.titleLabel?.textAlignment = .center
        emptyStateStack.axis = .vertical
        emptyStateStack.alignment = .center
        emptyStateStack.spacing = 24
        emptyStateStack.addArrangedSubview(emptyStateLabel)
        emptyStateStack.addArrangedSubview(centeredAddButton)
        centeredAddButton.isHidden = false
        emptyStateStack.translatesAutoresizingMaskIntoConstraints = false
        emptyStateContainer.addSubview(emptyStateStack)
        emptyStateContainer.isHidden = true
        emptyStateContainer.clipsToBounds = true
        let emptyBottom = emptyStateStack.bottomAnchor.constraint(equalTo: emptyStateContainer.bottomAnchor)
        emptyBottom.priority = UILayoutPriority(999)
        NSLayoutConstraint.activate([
            emptyStateStack.leadingAnchor.constraint(equalTo: emptyStateContainer.leadingAnchor),
            emptyStateStack.trailingAnchor.constraint(equalTo: emptyStateContainer.trailingAnchor),
            emptyStateStack.topAnchor.constraint(equalTo: emptyStateContainer.topAnchor),
            emptyBottom,
            emptyStateLabel.widthAnchor.constraint(equalTo: emptyStateStack.widthAnchor),
            centeredAddButton.widthAnchor.constraint(lessThanOrEqualTo: emptyStateStack.widthAnchor),
            centeredAddButton.button.leadingAnchor.constraint(greaterThanOrEqualTo: centeredAddButton.leadingAnchor, constant: 16),
            centeredAddButton.button.trailingAnchor.constraint(lessThanOrEqualTo: centeredAddButton.trailingAnchor, constant: -16),
            centeredAddButton.heightAnchor.constraint(greaterThanOrEqualTo: centeredAddButton.button.heightAnchor, constant: 16)
        ])
        let stack = UIStackView(arrangedSubviews: [summary, checkAllButton, emptyStateContainer])
        stack.axis = .vertical
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        summaryHeader.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: summaryHeader.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: summaryHeader.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: summaryHeader.topAnchor, constant: 8),
            stack.bottomAnchor.constraint(equalTo: summaryHeader.bottomAnchor, constant: -8)
        ])
        tableView.tableHeaderView = summaryHeader
    }

    private func updateSummaryIdentityLayout() {
        let accessibilitySize = traitCollection.preferredContentSizeCategory.isAccessibilityCategory
        summaryIdentityRow.axis = accessibilitySize ? .vertical : .horizontal
        summaryIdentityRow.alignment = accessibilitySize ? .leading : .firstBaseline
    }

    private func configureDeveloperFooter() {
        let credit = Self.makeLabel(style: .caption2, color: VPN013Theme.secondaryText)
        credit.text = "Разработчик VPN013 WG"
        credit.textAlignment = .center
        let support = UIButton(type: .system)
        var configuration = UIButton.Configuration.plain()
        configuration.title = "@R013_Support"
        configuration.image = UIImage(systemName: "paperplane.fill")
        configuration.imagePadding = 7
        configuration.preferredSymbolConfigurationForImage = UIImage.SymbolConfiguration(textStyle: .caption1)
        configuration.baseForegroundColor = VPN013Theme.accent
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 10, leading: 14, bottom: 10, trailing: 14)
        configuration.titleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { attributes in
            var result = attributes
            result.font = UIFont.preferredFont(forTextStyle: .caption1)
            return result
        }
        support.configuration = configuration
        support.titleLabel?.adjustsFontForContentSizeCategory = true
        support.titleLabel?.numberOfLines = 0
        support.titleLabel?.textAlignment = .center
        support.accessibilityIdentifier = "vpn013.developer-support"
        support.accessibilityLabel = "Написать разработчику VPN013 WG в Telegram, @R013_Support"
        support.accessibilityHint = "Открыть страницу поддержки"
        support.addTarget(self, action: #selector(developerSupportTapped), for: .touchUpInside)
        support.heightAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
        let stack = UIStackView(arrangedSubviews: [credit, support])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 0
        stack.translatesAutoresizingMaskIntoConstraints = false
        developerFooter.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: developerFooter.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: developerFooter.bottomAnchor, constant: -20),
            stack.leadingAnchor.constraint(equalTo: developerFooter.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: developerFooter.trailingAnchor, constant: -20),
            credit.widthAnchor.constraint(lessThanOrEqualTo: stack.widthAnchor),
            support.widthAnchor.constraint(lessThanOrEqualTo: stack.widthAnchor)
        ])
        tableView.tableFooterView = developerFooter
    }

    private func sizeDeveloperFooter() {
        let width = tableView.bounds.width
        guard width > 0 else { return }
        let size = developerFooter.systemLayoutSizeFitting(CGSize(width: width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel)
        if abs(developerFooter.frame.height - size.height) > 0.5 || developerFooter.frame.width != width {
            developerFooter.frame = CGRect(x: 0, y: 0, width: width, height: size.height)
            tableView.tableFooterView = developerFooter
        }
    }

    @objc private func developerSupportTapped() {
        openConfigurationWebsite("https://t.me/R013_Support")
    }

    private func sizeSummaryHeader() {
        let width = tableView.bounds.width
        guard width > 0 else { return }
        let size = summaryHeader.systemLayoutSizeFitting(CGSize(width: width, height: UIView.layoutFittingCompressedSize.height), withHorizontalFittingPriority: .required, verticalFittingPriority: .fittingSizeLevel)
        if abs(summaryHeader.frame.height - size.height) > 0.5 || summaryHeader.frame.width != width {
            summaryHeader.frame = CGRect(x: 0, y: 0, width: width, height: size.height)
            tableView.tableHeaderView = summaryHeader
        }
    }

    private func observeConnectionSummary() {
        summaryObservations.removeAll()
        for tunnel in tunnelsManager?.mapTunnels(transform: { $0 }) ?? [] {
            summaryObservations.append(tunnel.observe(\.status) { [weak self] _, _ in self?.updateConnectionSummary() })
            summaryObservations.append(tunnel.observe(\.name) { [weak self] _, _ in self?.updateConnectionSummary() })
            summaryObservations.append(tunnel.observe(\.handshakeState) { [weak self] _, _ in self?.updateConnectionSummary() })
        }
        updateConnectionSummary()
    }

    private func updateEmptyState() {
        let hasTunnels = (tunnelsManager?.numberOfTunnels() ?? 0) > 0
        emptyStateContainer.isHidden = tunnelsManager == nil || hasTunnels
        checkAllButton.isEnabled = hasTunnels
        sizeSummaryHeader()
    }

    private func updateConnectionSummary() {
        guard isViewLoaded else { return }
        let tunnels = tunnelsManager?.mapTunnels { $0 } ?? []
        let current = tunnels.first { $0.status == .active } ?? tunnels.first { $0.status != .inactive }
        summaryModeLabel.isHidden = true
        summaryProofLabel.isHidden = true
        summaryStatusLabel.textColor = VPN013Theme.secondaryText
        guard let tunnel = current else {
            automaticSummaryTunnel = nil
            automaticSummaryName = nil
            automaticSummaryPhase = nil
            automaticSummaryRequestID = UUID()
            automaticSummaryRequestInFlight = false
            summaryStatusLabel.text = tunnelsManager == nil ? "Загрузка" : "Не подключено"
            summaryNameLabel.text = tunnelsManager == nil ? "Загружаем серверы…" : (tunnels.isEmpty ? "Добавьте первый сервер" : "Выберите сервер")
            summaryModeLabel.isHidden = tunnels.isEmpty
            summaryModeLabel.text = "Включите переключатель рядом с сервером."
            sizeSummaryHeader()
            return
        }
        if automaticSummaryTunnel !== tunnel {
            automaticSummaryTunnel = tunnel
            automaticSummaryName = nil
            automaticSummaryPhase = nil
            automaticSummaryRequestID = UUID()
            automaticSummaryRequestInFlight = false
        }
        summaryNameLabel.text = tunnel.isVPN013Automatic ? (automaticSummaryName ?? tunnel.name) : tunnel.name
        if tunnel.isVPN013Automatic {
            let count = tunnel.automaticServerCount
            summaryModeLabel.text = "Авто · \(count) \(serverCountWord(count))"
            summaryModeLabel.isHidden = false
        }
        switch tunnel.status {
        case .active:
            updateRunningSummaryStatus(for: tunnel)
            summaryProofLabel.isHidden = false
            if tunnel.isVPN013Automatic {
                summaryProofLabel.text = automaticSummaryPhase ?? "VPN запущен · трафик ещё не проверен"
            } else if tunnel.handshakeState == .confirmed {
                summaryProofLabel.text = "Рукопожатие подтверждено"
            } else {
                summaryProofLabel.text = "VPN запущен · рукопожатие не подтверждено"
            }
        case .activating:
            summaryStatusLabel.text = "Подключение…"
            summaryProofLabel.isHidden = false
            summaryProofLabel.text = tunnel.handshakeState == .waiting ? "Ожидаем ответ сервера" : "Запускаем VPN"
        case .deactivating:
            summaryStatusLabel.text = "Отключение…"
        case .waiting:
            summaryStatusLabel.text = "Ожидание подключения"
        case .restarting, .reasserting:
            summaryStatusLabel.text = "Восстановление подключения…"
        case .inactive:
            summaryStatusLabel.text = "Не подключено"
        }
        sizeSummaryHeader()
        refreshAutomaticSummary()
    }

    private func serverCountWord(_ count: Int) -> String {
        if count % 100 >= 11 && count % 100 <= 14 { return "серверов" }
        switch count % 10 {
        case 1: return "сервер"
        case 2...4: return "сервера"
        default: return "серверов"
        }
    }

    private func startAutomaticSummaryUpdates() {
        automaticSummaryTimer?.invalidate()
        let timer = Timer(timeInterval: 3, repeats: true) { [weak self] _ in self?.refreshAutomaticSummary() }
        automaticSummaryTimer = timer
        RunLoop.main.add(timer, forMode: .common)
        refreshAutomaticSummary()
    }

    private func updateRunningSummaryStatus(for tunnel: TunnelContainer) {
        let confirmed = tunnel.isVPN013Automatic
            ? automaticSummaryPhase?.hasPrefix("Трафик проверен") == true
            : tunnel.handshakeState == .confirmed
        summaryStatusLabel.text = confirmed ? "Подключено" : "VPN запущен"
        summaryStatusLabel.textColor = confirmed ? VPN013Theme.accent : VPN013Theme.secondaryText
    }

    private func refreshAutomaticSummary() {
        guard viewIfLoaded?.window != nil, let tunnel = automaticSummaryTunnel, tunnel.isVPN013Automatic,
              tunnel.status == .active, !automaticSummaryRequestInFlight else { return }
        automaticSummaryRequestInFlight = true
        let requestID = UUID()
        automaticSummaryRequestID = requestID
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self = self, self.automaticSummaryRequestID == requestID else { return }
            self.automaticSummaryRequestInFlight = false
        }
        tunnel.getAutomaticStatus { [weak self, weak tunnel] text in
            guard let self = self, let tunnel = tunnel, self.automaticSummaryTunnel === tunnel,
                  self.automaticSummaryRequestID == requestID, tunnel.status == .active else { return }
            self.automaticSummaryRequestInFlight = false
            let lines = text?.components(separatedBy: "\n") ?? []
            self.automaticSummaryName = lines.first.flatMap { $0.isEmpty ? nil : $0 }
            self.automaticSummaryPhase = lines.count > 1 && !lines[1].isEmpty ? lines[1] : nil
            self.updateRunningSummaryStatus(for: tunnel)
            self.summaryNameLabel.text = self.automaticSummaryName ?? tunnel.name
            self.summaryProofLabel.text = self.automaticSummaryPhase ?? "VPN запущен · трафик ещё не проверен"
            self.sizeSummaryHeader()
        }
    }

    @objc private func checkAllServersTapped() {
        onCheckAllServers?()
    }

    func setConnectionTesting(isRunning: Bool, title: String? = nil) {
        checkAllButton.isEnabled = !isRunning && (tunnelsManager?.numberOfTunnels() ?? 0) > 0
        checkAllButton.configuration?.title = title ?? (isRunning ? "Проверяем серверы…" : "Проверить все")
        checkAllButton.configuration?.showsActivityIndicator = isRunning
        sizeSummaryHeader()
    }

    func setConnectionTestText(_ text: String?, for tunnel: TunnelContainer) {
        connectionTestResults[ObjectIdentifier(tunnel)] = text
        for case let cell as TunnelListCell in tableView.visibleCells where cell.tunnel === tunnel {
            cell.connectionTestText = text
        }
    }

    @objc func addButtonTapped(sender: AnyObject) {
        guard tunnelsManager != nil else { return }

        let alert = UIAlertController(title: "", message: tr("addTunnelMenuHeader"), preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: "Купить конфигурацию", style: .default) { [weak self] _ in
            self?.openConfigurationWebsite("https://t.me/vpn_access_orders_bot")
        })
        alert.addAction(UIAlertAction(title: "1 час бесплатно", style: .default) { [weak self] _ in
            self?.openConfigurationWebsite("https://vpn013.com/")
        })
        let importFileAction = UIAlertAction(title: tr("addTunnelMenuImportFile"), style: .default) { [weak self] _ in
            self?.presentViewControllerForFileImport()
        }
        alert.addAction(importFileAction)

        let automaticAction = UIAlertAction(title: "Создать режим Авто", style: .default) { [weak self] _ in self?.automaticTapped() }
        automaticAction.isEnabled = tunnelsManager?.mapTunnels { $0 }.contains(where: { !$0.isVPN013Automatic }) ?? false
        alert.addAction(automaticAction)

        let scanQRCodeAction = UIAlertAction(title: tr("addTunnelMenuQRCode"), style: .default) { [weak self] _ in
            self?.presentViewControllerForScanningQRCode()
        }
        alert.addAction(scanQRCodeAction)

        let createFromScratchAction = UIAlertAction(title: tr("addTunnelMenuFromScratch"), style: .default) { [weak self] _ in
            if let self = self, let tunnelsManager = self.tunnelsManager {
                self.presentViewControllerForTunnelCreation(tunnelsManager: tunnelsManager)
            }
        }
        alert.addAction(createFromScratchAction)

        let cancelAction = UIAlertAction(title: tr("actionCancel"), style: .cancel)
        alert.addAction(cancelAction)

        if let sender = sender as? UIBarButtonItem {
            alert.popoverPresentationController?.barButtonItem = sender
        } else if let sender = sender as? UIView {
            alert.popoverPresentationController?.sourceView = sender
            alert.popoverPresentationController?.sourceRect = sender.bounds
        }
        present(alert, animated: true, completion: nil)
    }

    private func openConfigurationWebsite(_ address: String) {
        guard let url = URL(string: address), url.scheme == "https" else { return }
        UIApplication.shared.open(url, options: [:]) { [weak self] opened in
            guard !opened else { return }
            DispatchQueue.main.async {
                let alert = UIAlertController(title: "Не удалось открыть ссылку", message: "Откройте в браузере: " + address, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "Скопировать ссылку", style: .default) { _ in UIPasteboard.general.string = address })
                alert.addAction(UIAlertAction(title: "Закрыть", style: .cancel))
                self?.present(alert, animated: true)
            }
        }
    }

    @objc func settingsButtonTapped(sender: UIBarButtonItem) {
        guard tunnelsManager != nil else { return }

        let settingsVC = SettingsTableViewController(tunnelsManager: tunnelsManager)
        let settingsNC = UINavigationController(rootViewController: settingsVC)
        settingsNC.modalPresentationStyle = .formSheet
        present(settingsNC, animated: true)
    }

    func presentViewControllerForTunnelCreation(tunnelsManager: TunnelsManager) {
        let editVC = TunnelEditTableViewController(tunnelsManager: tunnelsManager)
        let editNC = UINavigationController(rootViewController: editVC)
        editNC.modalPresentationStyle = .fullScreen
        present(editNC, animated: true)
    }

    func presentViewControllerForFileImport() {
        let documentTypes = ["com.wireguard.config.quick", String(kUTTypeText), String(kUTTypeZipArchive)]
        let filePicker = UIDocumentPickerViewController(documentTypes: documentTypes, in: .import)
        filePicker.delegate = self
        present(filePicker, animated: true)
    }

    func presentViewControllerForScanningQRCode() {
        let scanQRCodeVC = QRScanViewController()
        scanQRCodeVC.delegate = self
        let scanQRCodeNC = UINavigationController(rootViewController: scanQRCodeVC)
        scanQRCodeNC.modalPresentationStyle = .fullScreen
        present(scanQRCodeNC, animated: true)
    }

    @objc func selectButtonTapped() {
        let shouldCancelSwipe = tableState == .rowSwiped
        tableState = .multiSelect(selectionCount: 0)
        if shouldCancelSwipe {
            tableView.setEditing(false, animated: false)
        }
        tableView.setEditing(true, animated: true)
    }

    @objc func doneButtonTapped() {
        tableState = .normal
        tableView.setEditing(false, animated: true)
    }

    @objc func selectAllButtonTapped() {
        guard tableView.isEditing else { return }
        guard let tunnelsManager = tunnelsManager else { return }
        for index in 0 ..< tunnelsManager.numberOfTunnels() {
            tableView.selectRow(at: IndexPath(row: index, section: 0), animated: false, scrollPosition: .none)
        }
        tableState = .multiSelect(selectionCount: tableView.indexPathsForSelectedRows?.count ?? 0)
    }

    @objc func cancelButtonTapped() {
        tableState = .normal
        tableView.setEditing(false, animated: true)
    }

    @objc func deleteButtonTapped(sender: AnyObject?) {
        guard let sender = sender as? UIBarButtonItem else { return }
        guard let tunnelsManager = tunnelsManager else { return }

        let selectedTunnelIndices = tableView.indexPathsForSelectedRows?.map { $0.row } ?? []
        let selectedTunnels = selectedTunnelIndices.compactMap { tunnelIndex in
            tunnelIndex >= 0 && tunnelIndex < tunnelsManager.numberOfTunnels() ? tunnelsManager.tunnel(at: tunnelIndex) : nil
        }
        guard !selectedTunnels.isEmpty else { return }
        let message = selectedTunnels.count == 1 ?
            tr(format: "deleteTunnelConfirmationAlertButtonMessage (%d)", selectedTunnels.count) :
            tr(format: "deleteTunnelsConfirmationAlertButtonMessage (%d)", selectedTunnels.count)
        let title = tr("deleteTunnelsConfirmationAlertButtonTitle")
        ConfirmationAlertPresenter.showConfirmationAlert(message: message, buttonTitle: title,
                                                         from: sender, presentingVC: self) { [weak self] in
            self?.tunnelsManager?.removeMultiple(tunnels: selectedTunnels) { [weak self] error in
                guard let self = self else { return }
                if let error = error {
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                    return
                }
                self.tableState = .normal
                self.tableView.setEditing(false, animated: true)
            }
        }
    }

    func showTunnelDetail(for tunnel: TunnelContainer, animated: Bool) {
        guard let tunnelsManager = tunnelsManager else { return }
        guard let splitViewController = splitViewController else { return }
        guard let navController = navigationController else { return }

        let tunnelDetailVC = TunnelDetailTableViewController(tunnelsManager: tunnelsManager,
                                                             tunnel: tunnel)
        let tunnelDetailNC = UINavigationController(rootViewController: tunnelDetailVC)
        tunnelDetailNC.restorationIdentifier = "DetailNC"
        if splitViewController.isCollapsed && navController.viewControllers.count > 1 {
            navController.setViewControllers([self, tunnelDetailNC], animated: animated)
        } else {
            splitViewController.showDetailViewController(tunnelDetailNC, sender: self, animated: animated)
        }
        detailDisplayedTunnel = tunnel
        self.presentedViewController?.dismiss(animated: false, completion: nil)
    }
}

extension TunnelsListTableViewController: UIDocumentPickerDelegate {
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let tunnelsManager = tunnelsManager else { return }
        TunnelImporter.importFromFile(urls: urls, into: tunnelsManager, sourceVC: self, errorPresenterType: ErrorPresenter.self)
    }
}

extension TunnelsListTableViewController: QRScanViewControllerDelegate {
    func addScannedQRCode(tunnelConfiguration: TunnelConfiguration, qrScanViewController: QRScanViewController,
                          completionHandler: (() -> Void)?) {
        tunnelsManager?.add(tunnelConfiguration: tunnelConfiguration) { result in
            switch result {
            case .failure(let error):
                ErrorPresenter.showErrorAlert(error: error, from: qrScanViewController, onDismissal: completionHandler)
            case .success:
                completionHandler?()
            }
        }
    }
}

extension TunnelsListTableViewController: UITableViewDataSource {
    func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }

    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return nil // The delegate provides the complete two-column header.
    }

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return (tunnelsManager?.numberOfTunnels() ?? 0)
    }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell: TunnelListCell = tableView.dequeueReusableCell(for: indexPath)
        if let tunnelsManager = tunnelsManager {
            let tunnel = tunnelsManager.tunnel(at: indexPath.row)
            cell.tunnel = tunnel
            cell.connectionTestText = connectionTestResults[ObjectIdentifier(tunnel)]
            cell.onSwitchToggled = { [weak self] isOn in
                guard let self = self, let tunnelsManager = self.tunnelsManager else { return }
                if tunnel.hasOnDemandRules {
                    tunnelsManager.setOnDemandEnabled(isOn, on: tunnel) { error in
                        if error == nil && !isOn {
                            tunnelsManager.startDeactivation(of: tunnel)
                        }
                    }
                } else {
                    if isOn {
                        tunnelsManager.startActivation(of: tunnel)
                    } else {
                        tunnelsManager.startDeactivation(of: tunnel)
                    }
                }
            }
        }
        return cell
    }
}

extension TunnelsListTableViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        guard let count = tunnelsManager?.numberOfTunnels(), count > 0 else { return nil }
        let header = UITableViewHeaderFooterView(reuseIdentifier: nil)
        let title = Self.makeLabel(style: .subheadline, weight: .semibold, color: VPN013Theme.text)
        title.text = "Профили · \(count)"
        let latency = Self.makeLabel(style: .caption1, color: VPN013Theme.secondaryText)
        latency.text = "Задержка"
        latency.textAlignment = .right
        let row = UIStackView(arrangedSubviews: [title, latency])
        let accessibilitySize = traitCollection.preferredContentSizeCategory.isAccessibilityCategory
        let switchColumn = accessibilitySize ? 0 : UISwitch().intrinsicContentSize.width + 10
        row.axis = accessibilitySize ? .vertical : .horizontal
        row.alignment = accessibilitySize ? .leading : .center
        row.spacing = 12
        row.translatesAutoresizingMaskIntoConstraints = false
        header.contentView.addSubview(row)
        title.setContentHuggingPriority(.defaultLow, for: .horizontal)
        latency.setContentHuggingPriority(.required, for: .horizontal)
        NSLayoutConstraint.activate([
            row.leadingAnchor.constraint(equalTo: header.contentView.layoutMarginsGuide.leadingAnchor),
            row.trailingAnchor.constraint(equalTo: header.contentView.layoutMarginsGuide.trailingAnchor, constant: -switchColumn),
            row.topAnchor.constraint(equalTo: header.contentView.topAnchor, constant: 10),
            row.bottomAnchor.constraint(equalTo: header.contentView.bottomAnchor, constant: -10)
        ])
        return header
    }

    func tableView(_ tableView: UITableView, willDisplayHeaderView view: UIView, forSection section: Int) {
        guard let header = view as? UITableViewHeaderFooterView else { return }
        header.textLabel?.textColor = VPN013Theme.secondaryText
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        guard !tableView.isEditing else {
            tableState = .multiSelect(selectionCount: tableView.indexPathsForSelectedRows?.count ?? 0)
            return
        }
        guard let tunnelsManager = tunnelsManager else { return }
        let tunnel = tunnelsManager.tunnel(at: indexPath.row)
        showTunnelDetail(for: tunnel, animated: true)
    }

    func tableView(_ tableView: UITableView, didDeselectRowAt indexPath: IndexPath) {
        guard !tableView.isEditing else {
            tableState = .multiSelect(selectionCount: tableView.indexPathsForSelectedRows?.count ?? 0)
            return
        }
    }

    func tableView(_ tableView: UITableView,
                   trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let deleteAction = UIContextualAction(style: .destructive, title: tr("tunnelsListSwipeDeleteButtonTitle")) { [weak self] _, _, completionHandler in
            guard let tunnelsManager = self?.tunnelsManager else { return }
            let tunnel = tunnelsManager.tunnel(at: indexPath.row)
            tunnelsManager.remove(tunnel: tunnel) { error in
                if error != nil {
                    ErrorPresenter.showErrorAlert(error: error!, from: self)
                    completionHandler(false)
                } else {
                    completionHandler(true)
                }
            }
        }
        return UISwipeActionsConfiguration(actions: [deleteAction])
    }

    func tableView(_ tableView: UITableView, willBeginEditingRowAt indexPath: IndexPath) {
        if tableState == .normal {
            tableState = .rowSwiped
        }
    }

    func tableView(_ tableView: UITableView, didEndEditingRowAt indexPath: IndexPath?) {
        if tableState == .rowSwiped {
            tableState = .normal
        }
    }
}

extension TunnelsListTableViewController: TunnelsManagerListDelegate {
    func tunnelAdded(at index: Int) {
        tableView.insertRows(at: [IndexPath(row: index, section: 0)], with: .automatic)
        observeConnectionSummary()
        updateEmptyState()
    }

    func tunnelModified(at index: Int) {
        if let tunnel = tunnelsManager?.tunnel(at: index) {
            connectionTestResults[ObjectIdentifier(tunnel)] = nil
        }
        tableView.reloadRows(at: [IndexPath(row: index, section: 0)], with: .automatic)
        observeConnectionSummary()
    }

    func tunnelMoved(from oldIndex: Int, to newIndex: Int) {
        tableView.moveRow(at: IndexPath(row: oldIndex, section: 0), to: IndexPath(row: newIndex, section: 0))
    }

    func tunnelRemoved(at index: Int, tunnel: TunnelContainer) {
        tableView.deleteRows(at: [IndexPath(row: index, section: 0)], with: .automatic)
        connectionTestResults[ObjectIdentifier(tunnel)] = nil
        observeConnectionSummary()
        updateEmptyState()
        if detailDisplayedTunnel == tunnel, let splitViewController = splitViewController {
            if splitViewController.isCollapsed != false {
                (splitViewController.viewControllers[0] as? UINavigationController)?.popToRootViewController(animated: false)
            } else {
                let detailVC = UIViewController()
                detailVC.view.backgroundColor = .systemBackground
                let detailNC = UINavigationController(rootViewController: detailVC)
                splitViewController.showDetailViewController(detailNC, sender: self)
            }
            detailDisplayedTunnel = nil
            if let presentedNavController = self.presentedViewController as? UINavigationController, presentedNavController.viewControllers.first is TunnelEditTableViewController {
                self.presentedViewController?.dismiss(animated: false, completion: nil)
            }
        }
    }
}

extension UISplitViewController {
    func showDetailViewController(_ viewController: UIViewController, sender: Any?, animated: Bool) {
        if animated {
            showDetailViewController(viewController, sender: sender)
        } else {
            UIView.performWithoutAnimation {
                showDetailViewController(viewController, sender: sender)
            }
        }
    }
}
