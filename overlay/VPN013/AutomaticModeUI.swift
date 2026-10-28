// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension

/// The same persisted setting on every connection section. It does not start a
/// VPN by itself; power remains the single explicit connection action.
final class AutomaticModeRow: UIView {
    static var canChange: () -> Bool = { true }
    static let availabilityChanged = Notification.Name("VPN013AutomaticAvailabilityChanged")
    private let toggle = UISwitch()
    private let explanation = UILabel()
    private var observations: [NSObjectProtocol] = []
    override init(frame: CGRect) {
        super.init(frame: frame)
        let title = UILabel(); title.text = "Режим Авто"
        title.font = .preferredFont(forTextStyle: .headline); title.adjustsFontForContentSizeCategory = true
        title.textColor = VPN013Theme.text; title.numberOfLines = 0
        explanation.text = "Лучший ответ при запуске, сравнение каждые 5 минут. Выключите для ручного выбора."
        explanation.font = .preferredFont(forTextStyle: .footnote); explanation.adjustsFontForContentSizeCategory = true
        explanation.textColor = VPN013Theme.secondaryText; explanation.numberOfLines = 0
        let labels = UIStackView(arrangedSubviews: [title, explanation]); labels.axis = .vertical; labels.spacing = 4
        toggle.onTintColor = VPN013Theme.accent; toggle.accessibilityLabel = "Режим Авто"
        toggle.accessibilityIdentifier = "vpn013.automatic-mode"
        toggle.addTarget(self, action: #selector(changed), for: .valueChanged)
        toggle.setContentCompressionResistancePriority(.required, for: .horizontal)
        let row = UIStackView(arrangedSubviews: [labels, toggle]); row.spacing = 16; row.alignment = .center
        row.translatesAutoresizingMaskIntoConstraints = false; addSubview(row)
        NSLayoutConstraint.activate([row.topAnchor.constraint(equalTo: topAnchor, constant: 12), row.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12), row.leadingAnchor.constraint(equalTo: leadingAnchor), row.trailingAnchor.constraint(equalTo: trailingAnchor), heightAnchor.constraint(greaterThanOrEqualToConstant: 64)])
        for name in [VPN013AutomaticMode.changed, Self.availabilityChanged, .NEVPNStatusDidChange] {
            observations.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in self?.refresh() })
        }
        refresh()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { observations.forEach { NotificationCenter.default.removeObserver($0) } }
    private func refresh() { toggle.isOn = VPN013AutomaticMode.enabled(); toggle.isEnabled = Self.canChange() }
    @objc private func changed() {
        guard Self.canChange() else { refresh(); return }
        VPN013AutomaticMode.setEnabled(toggle.isOn)
    }
}
