// SPDX-License-Identifier: MIT
import UIKit
import NetworkExtension

/// Foreground presentation only. Switching is owned by the VPN extension.
final class CrossProtocolObserver {
    var changed: ((CrossProtocolRuntime?, Bool) -> Void)?
    private var timer: Timer?
    private var busy = false
    private var generation = UUID()
    private var local: VPN013LocalStatisticsRead?
    private var manager: NETunnelProviderManager?
    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
        refresh()
    }
    func stop() { timer?.invalidate(); timer = nil; generation = UUID(); busy = false; local?.cancel(); local = nil }
    func refresh() {
        guard !busy else { return }; busy = true
        let token = UUID(); generation = token
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, _ in
            DispatchQueue.main.async {
                guard let self = self, self.generation == token else { return }
                guard let appID = Bundle.main.bundleIdentifier,
                      let manager = managers?.first(where: { item in
                          guard [.connected, .reasserting].contains(item.connection.status),
                                let proto = item.protocolConfiguration as? NETunnelProviderProtocol,
                                proto.providerBundleIdentifier == appID + ".network-extension",
                                let plan = try? proto.privatePayload()?.crossProtocol else { return false }
                          return (try? plan.validate()) != nil
                      }), let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                      let envelope = proto.privateEnvelope,
                      let session = manager.connection as? NETunnelProviderSession else {
                    self.manager = nil; self.busy = false; self.changed?(nil, false); return
                }
                self.manager = manager
                var finished = false, fallbackStarted = false
                let finish: (Data?) -> Void = { data in
                    guard self.generation == token, !finished else { return }; finished = true
                    self.local?.cancel(); self.local = nil; self.busy = false
                    let same = [.connected, .reasserting].contains(manager.connection.status) &&
                        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.privateEnvelope?.ciphertext == envelope.ciphertext
                    self.changed?(same ? data.flatMap(CrossProtocolRuntime.read) : nil, same)
                }
                let fallback = {
                    guard !finished, !fallbackStarted, self.generation == token else { return }; fallbackStarted = true
                    guard let secret = try? PrivateTunnelStore.current.key(for: envelope.id),
                          let credentials = try? VPN013LocalStatisticsCredentials(secret: secret, id: envelope.id, ciphertext: envelope.ciphertext),
                          let read = try? VPN013LocalStatisticsRead(credentials: credentials, operation: 11) else { finish(nil); return }
                    self.local = read; read.start { result in finish(try? result.get()) }
                }
                do { try session.sendProviderMessage(Data([11])) { data in
                    DispatchQueue.main.async { if let data = data, CrossProtocolRuntime.read(data) != nil { finish(data) } else { fallback() } }
                } } catch { fallback() }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.35, execute: fallback)
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { finish(nil) }
            }
        }
    }
    func stopConnection() { manager?.connection.stopVPNTunnel(); refresh() }
}

final class CrossProtocolStatusView: UIView {
    var stop: (() -> Void)?
    private let title = UILabel()
    private let detail = UILabel()
    private let power = UIButton(type: .system)
    override init(frame: CGRect) {
        super.init(frame: frame); backgroundColor = VPN013Theme.selected; layer.cornerRadius = 14
        title.font = .preferredFont(forTextStyle: .headline); title.textColor = VPN013Theme.text
        detail.font = .preferredFont(forTextStyle: .footnote); detail.textColor = VPN013Theme.secondaryText
        for label in [title, detail] { label.numberOfLines = 0; label.adjustsFontForContentSizeCategory = true }
        title.numberOfLines = 2; detail.numberOfLines = 5
        title.accessibilityIdentifier = "vpn013.cross.kind"; detail.accessibilityIdentifier = "vpn013.cross.current"
        power.setTitle("Выключить VPN", for: .normal); power.tintColor = VPN013Theme.accent
        power.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        power.titleLabel?.adjustsFontForContentSizeCategory = true; power.titleLabel?.numberOfLines = 0
        power.accessibilityIdentifier = "vpn013.cross.stop"
        power.addTarget(self, action: #selector(stopTapped), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [title, detail, power]); stack.axis = .vertical; stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false; addSubview(stack)
        NSLayoutConstraint.activate([stack.topAnchor.constraint(equalTo: topAnchor, constant: 12), stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12), stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 14), stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -14), power.heightAnchor.constraint(greaterThanOrEqualToConstant: 44)])
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func preferredHeight(width: CGFloat) -> CGFloat {
        let size = CGSize(width: max(1, width - 28), height: .greatestFiniteMagnitude)
        let heading = min(title.sizeThatFits(size).height, title.font.lineHeight * 2)
        let body = min(detail.sizeThatFits(size).height, detail.font.lineHeight * 5)
        let button = max(44, (power.titleLabel?.sizeThatFits(size).height ?? 20) + 12)
        return ceil(heading + body + button + 36)
    }
    func update(_ value: CrossProtocolRuntime?) {
        title.text = value.map { "Общее Авто · " + $0.kind.title } ?? "Общее Авто"
        if let value = value {
            var lines = [value.name, value.phase]
            if let endpoint = value.endpoint { lines.append(endpoint) }
            if let rx = value.received, let tx = value.sent { lines.append("↓ \(rx) байт · ↑ \(tx) байт") }
            detail.text = lines.joined(separator: "\n")
        } else { detail.text = "VPN запущен, но расширение пока не подтвердило текущую конфигурацию." }
    }
    @objc private func stopTapped() { stop?() }
}
