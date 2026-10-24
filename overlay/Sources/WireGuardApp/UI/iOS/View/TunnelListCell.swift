// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import UIKit

enum VPN013Theme {
    static let background = UIColor(red: 12.0 / 255, green: 25.0 / 255, blue: 41.0 / 255, alpha: 1)
    static let surface = background
    static let selected = UIColor(red: 25.0 / 255, green: 53.0 / 255, blue: 74.0 / 255, alpha: 1)
    static let text = UIColor(red: 220.0 / 255, green: 234.0 / 255, blue: 244.0 / 255, alpha: 1)
    static let secondaryText = UIColor(red: 157.0 / 255, green: 178.0 / 255, blue: 197.0 / 255, alpha: 1)
    static let accent = UIColor(red: 232.0 / 255, green: 182.0 / 255, blue: 108.0 / 255, alpha: 1)
    static let separator = UIColor(red: 38.0 / 255, green: 57.0 / 255, blue: 75.0 / 255, alpha: 1)
    static let switchTrack = UIColor(red: 53.0 / 255, green: 72.0 / 255, blue: 91.0 / 255, alpha: 1)

    static func navigationAppearance() -> UINavigationBarAppearance {
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = background
        appearance.shadowColor = .clear
        appearance.titleTextAttributes = [.foregroundColor: text]
        appearance.largeTitleTextAttributes = [.foregroundColor: text]
        return appearance
    }
}

class TunnelListCell: UITableViewCell {
    var tunnel: TunnelContainer? {
        didSet {
            // Bind to the tunnel's name
            nameLabel.text = tunnel?.name ?? ""
            nameObservationToken = tunnel?.observe(\.name) { [weak self] tunnel, _ in
                self?.nameLabel.text = tunnel.name
            }
            // Bind to the tunnel's status
            update(from: tunnel, animated: false)
            statusObservationToken = tunnel?.observe(\.status) { [weak self] tunnel, _ in
                self?.update(from: tunnel, animated: true)
            }
            // Bind to tunnel's on-demand settings
            isOnDemandEnabledObservationToken = tunnel?.observe(\.isActivateOnDemandEnabled) { [weak self] tunnel, _ in
                self?.update(from: tunnel, animated: true)
            }
            hasOnDemandRulesObservationToken = tunnel?.observe(\.hasOnDemandRules) { [weak self] tunnel, _ in
                self?.update(from: tunnel, animated: true)
            }
            handshakeObservationToken = tunnel?.observe(\.handshakeState) { [weak self] tunnel, _ in
                self?.update(from: tunnel, animated: true)
            }
        }
    }
    var onSwitchToggled: ((Bool) -> Void)?
    /// Set only from a completed connection test; nil means no measured result.
    var connectionTestText: String? {
        didSet {
            connectionTestLabel.text = connectionTestText ?? "—"
            connectionTestLabel.accessibilityLabel = connectionTestText.map { "Задержка: " + $0 } ?? "Задержка ещё не измерена"
        }
    }

    let nameLabel: UILabel = {
        let nameLabel = UILabel()
        nameLabel.font = UIFont.preferredFont(forTextStyle: .body)
        nameLabel.adjustsFontForContentSizeCategory = true
        nameLabel.numberOfLines = 0
        nameLabel.textColor = VPN013Theme.text
        return nameLabel
    }()

    let onDemandLabel: UILabel = {
        let label = UILabel()
        label.text = ""
        label.font = UIFont.preferredFont(forTextStyle: .footnote)
        label.adjustsFontForContentSizeCategory = true
        label.numberOfLines = 0
        label.textColor = VPN013Theme.secondaryText
        return label
    }()

    let busyIndicator: UIActivityIndicatorView = {
        let busyIndicator: UIActivityIndicatorView
        busyIndicator = UIActivityIndicatorView(style: .medium)
        busyIndicator.hidesWhenStopped = true
        return busyIndicator
    }()

    let statusSwitch = UISwitch()

    private let connectionTestLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.preferredFont(forTextStyle: .subheadline)
        label.adjustsFontForContentSizeCategory = true
        label.textColor = VPN013Theme.secondaryText
        label.numberOfLines = 0
        label.textAlignment = .right
        label.text = "—"
        label.accessibilityIdentifier = "vpn013.latency"
        label.accessibilityLabel = "Задержка ещё не измерена"
        return label
    }()

    private var nameObservationToken: NSKeyValueObservation?
    private var statusObservationToken: NSKeyValueObservation?
    private var isOnDemandEnabledObservationToken: NSKeyValueObservation?
    private var hasOnDemandRulesObservationToken: NSKeyValueObservation?
    private var handshakeObservationToken: NSKeyValueObservation?
    private let rowStack = UIStackView()
    private var latencyWidthConstraint: NSLayoutConstraint?

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)

        overrideUserInterfaceStyle = .dark
        backgroundColor = VPN013Theme.background
        contentView.layer.cornerRadius = 10
        contentView.layer.cornerCurve = .continuous
        let selectedBackground = UIView()
        selectedBackground.backgroundColor = VPN013Theme.selected
        selectedBackground.layer.cornerRadius = 10
        selectedBackgroundView = selectedBackground
        busyIndicator.color = VPN013Theme.accent
        tintColor = VPN013Theme.accent
        statusSwitch.onTintColor = VPN013Theme.accent
        accessoryType = .none
        contentView.directionalLayoutMargins = NSDirectionalEdgeInsets(top: 16, leading: 16, bottom: 16, trailing: 16)
        let labels = UIStackView(arrangedSubviews: [nameLabel, onDemandLabel])
        labels.axis = .vertical
        labels.spacing = 4
        let controls = UIStackView(arrangedSubviews: [connectionTestLabel, busyIndicator, statusSwitch])
        controls.axis = .horizontal
        controls.alignment = .center
        controls.spacing = 10
        rowStack.addArrangedSubview(labels)
        rowStack.addArrangedSubview(controls)
        rowStack.spacing = 12
        rowStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(rowStack)
        updateRowLayout()
        labels.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        labels.setContentHuggingPriority(.defaultLow, for: .horizontal)
        controls.setContentHuggingPriority(.required, for: .horizontal)
        statusSwitch.setContentHuggingPriority(.required, for: .horizontal)
        statusSwitch.setContentCompressionResistancePriority(.required, for: .horizontal)
        connectionTestLabel.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        // Reserve the measured-result column even before a result exists.
        // The switch keeps UIKit's own size instead of filling the trailing space.
        latencyWidthConstraint = connectionTestLabel.widthAnchor.constraint(greaterThanOrEqualToConstant: UIFontMetrics(forTextStyle: .subheadline).scaledValue(for: 56))
        latencyWidthConstraint?.isActive = true
        statusSwitch.widthAnchor.constraint(equalToConstant: statusSwitch.intrinsicContentSize.width).isActive = true
        NSLayoutConstraint.activate([
            rowStack.topAnchor.constraint(equalTo: contentView.layoutMarginsGuide.topAnchor),
            rowStack.bottomAnchor.constraint(equalTo: contentView.layoutMarginsGuide.bottomAnchor),
            rowStack.leadingAnchor.constraint(equalTo: contentView.layoutMarginsGuide.leadingAnchor),
            rowStack.trailingAnchor.constraint(equalTo: contentView.layoutMarginsGuide.trailingAnchor),
            contentView.heightAnchor.constraint(greaterThanOrEqualToConstant: 64)
        ])
        accessibilityHint = "Открыть параметры сервера"
        statusSwitch.addTarget(self, action: #selector(switchToggled), for: .valueChanged)
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        reset(animated: false)
    }

    override func setEditing(_ editing: Bool, animated: Bool) {
        super.setEditing(editing, animated: animated)
        statusSwitch.isEnabled = !editing
    }

    override func traitCollectionDidChange(_ previousTraitCollection: UITraitCollection?) {
        super.traitCollectionDidChange(previousTraitCollection)
        if previousTraitCollection?.preferredContentSizeCategory != traitCollection.preferredContentSizeCategory {
            latencyWidthConstraint?.constant = UIFontMetrics(forTextStyle: .subheadline).scaledValue(for: 56)
            updateRowLayout()
        }
    }

    private func updateRowLayout() {
        let accessibilitySize = traitCollection.preferredContentSizeCategory.isAccessibilityCategory
        rowStack.axis = accessibilitySize ? .vertical : .horizontal
        rowStack.alignment = accessibilitySize ? .leading : .center
    }

    @objc private func switchToggled() {
        onSwitchToggled?(statusSwitch.isOn)
    }

    private func update(from tunnel: TunnelContainer?, animated: Bool) {
        guard let tunnel = tunnel else {
            reset(animated: animated)
            return
        }
        let status = tunnel.status
        let isOnDemandEngaged = tunnel.isActivateOnDemandEnabled
        let isAwaitingHandshake = tunnel.handshakeState == .waiting

        let shouldSwitchBeOn = ((status != .deactivating && status != .inactive) || isOnDemandEngaged)
        statusSwitch.setOn(shouldSwitchBeOn, animated: animated)
        statusSwitch.accessibilityLabel = tunnel.name
        statusSwitch.onTintColor = VPN013Theme.accent
        statusSwitch.thumbTintColor = shouldSwitchBeOn ? VPN013Theme.background : VPN013Theme.text
        contentView.backgroundColor = status == .active ? VPN013Theme.selected : VPN013Theme.background

        if isAwaitingHandshake {
            onDemandLabel.text = tr("tunnelStatusWaitingForHandshakeHint")
        } else if tunnel.handshakeState == .failed {
            onDemandLabel.text = "Нет ответа от сервера"
        } else if status == .active {
            onDemandLabel.text = !tunnel.isVPN013Automatic && tunnel.handshakeState == .confirmed ? "Рукопожатие подтверждено" : "VPN запущен"
        } else if status == .activating || status == .restarting || status == .reasserting {
            onDemandLabel.text = "Подключение…"
        } else if status == .deactivating {
            onDemandLabel.text = "Отключение…"
        } else if status == .waiting {
            onDemandLabel.text = "Ожидание подключения"
        } else if tunnel.hasOnDemandRules {
            onDemandLabel.text = isOnDemandEngaged ? tr("tunnelListCaptionOnDemand") : ""
        } else {
            onDemandLabel.text = ""
        }
        if isOnDemandEngaged && status == .active {
            onDemandLabel.text = (onDemandLabel.text ?? "") + " · " + tr("tunnelListCaptionOnDemand")
        }
        onDemandLabel.isHidden = onDemandLabel.text?.isEmpty ?? true

        let shouldShowBusyIndicator: Bool
        if isAwaitingHandshake {
            shouldShowBusyIndicator = true
        } else if tunnel.hasOnDemandRules {
            shouldShowBusyIndicator = false
        } else {
            shouldShowBusyIndicator = !(status == .inactive || status == .active)
        }
        if shouldShowBusyIndicator {
            busyIndicator.startAnimating()
        } else {
            busyIndicator.stopAnimating()
        }

        if tunnel.hasOnDemandRules {
            statusSwitch.isUserInteractionEnabled = true
        } else {
            statusSwitch.isUserInteractionEnabled = (status == .inactive || status == .active)
        }

    }

    private func reset(animated: Bool) {
        statusSwitch.thumbTintColor = VPN013Theme.text
        contentView.backgroundColor = VPN013Theme.background
        statusSwitch.setOn(false, animated: animated)
        statusSwitch.isUserInteractionEnabled = false
        busyIndicator.stopAnimating()
        onDemandLabel.text = ""
        onDemandLabel.isHidden = true
        connectionTestText = nil
        nameLabel.text = ""
        onSwitchToggled = nil
        nameObservationToken = nil
        statusObservationToken = nil
        isOnDemandEnabledObservationToken = nil
        hasOnDemandRulesObservationToken = nil
        handshakeObservationToken = nil
    }
}
