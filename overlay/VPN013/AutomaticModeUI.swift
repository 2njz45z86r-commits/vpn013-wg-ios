// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension

/// The same persisted setting on every connection section. It does not start a
/// VPN by itself; power remains the single explicit connection action.
final class AutomaticModeRow: UIView {
    static var canChange: () -> Bool = { true }
    static let availabilityChanged = Notification.Name("VPN013AutomaticAvailabilityChanged")
    private let toggle = UIButton(type: .system)
    private var observations: [NSObjectProtocol] = []
    override init(frame: CGRect) {
        super.init(frame: frame)
        toggle.setTitle("Авто", for: .normal)
        toggle.titleLabel?.font = .systemFont(ofSize: 10, weight: .semibold)
        toggle.layer.cornerRadius = 18; toggle.layer.borderWidth = 1
        toggle.accessibilityLabel = "Режим Авто"
        toggle.accessibilityHint = "Автоматический выбор и сравнение подключений каждые пять минут. Нажмите для переключения."
        toggle.accessibilityIdentifier = "vpn013.automatic-mode"
        toggle.addTarget(self, action: #selector(changed), for: .touchUpInside)
        toggle.translatesAutoresizingMaskIntoConstraints = false; addSubview(toggle)
        NSLayoutConstraint.activate([widthAnchor.constraint(equalToConstant: 44), heightAnchor.constraint(equalToConstant: 44),
            toggle.centerXAnchor.constraint(equalTo: centerXAnchor), toggle.centerYAnchor.constraint(equalTo: centerYAnchor),
            toggle.widthAnchor.constraint(equalToConstant: 36), toggle.heightAnchor.constraint(equalToConstant: 36)])
        // A 36-point visible circle retains a standard 44-point hit target.
        let tap = UITapGestureRecognizer(target: self, action: #selector(changed)); addGestureRecognizer(tap)
        tap.cancelsTouchesInView = true
        for name in [VPN013AutomaticMode.changed, Self.availabilityChanged, .NEVPNStatusDidChange] {
            observations.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in self?.refresh() })
        }
        refresh()
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { observations.forEach { NotificationCenter.default.removeObserver($0) } }
    private func refresh() {
        let enabled = VPN013AutomaticMode.enabled()
        toggle.isSelected = enabled; toggle.isEnabled = Self.canChange()
        toggle.accessibilityValue = enabled ? "1" : "0"
        toggle.backgroundColor = enabled ? VPN013Theme.accent : .clear
        toggle.layer.borderColor = (enabled ? VPN013Theme.accent : VPN013Theme.secondaryText).cgColor
        toggle.setTitleColor(enabled ? VPN013Theme.background : VPN013Theme.secondaryText, for: .normal)
        toggle.alpha = toggle.isEnabled ? 1 : 0.45
    }
    @objc private func changed() {
        guard Self.canChange() else { refresh(); return }
        VPN013AutomaticMode.setEnabled(!VPN013AutomaticMode.enabled())
    }
}
