// SPDX-License-Identifier: MIT
import Foundation
import Network
import NetworkExtension

/// Private extension-owned measurements. No keys/configuration enter app messages.
final class HourlyProbeSupport {
    private let physical: R013UDPDriver
    private let current: R013UDPDriver
    private let coordinator: R013ProbeCoordinator
    private(set) var summary = "Сравнение серверов раз в час"
    private(set) var checkedAt: Date?
    private(set) var currentMilliseconds: Double?
    private(set) var measured = 0
    private var stopping = false

    init?(provider: NEPacketTunnelProvider) {
        guard let physical = R013UDPDriver.physical(provider: provider) else { return nil }
        guard let current = R013UDPDriver.throughTunnel(provider: provider) else {
            physical.invalidate {}; return nil
        }
        guard let coordinator = R013ProbeCoordinator(physical: physical.driverID, throughTunnel: current.driverID, refreshActual: true) else {
            physical.invalidate {}; current.invalidate {}; return nil
        }
        self.physical = physical; self.current = current; self.coordinator = coordinator
        coordinator.metrics = { [weak self] status in
            guard let self = self else { return }
            self.checkedAt = Date(); self.currentMilliseconds = status.after?.milliseconds
            self.measured = status.rows?.filter { $0.status == "measured" }.count ?? 0
            self.summary = "Других VPN проверено: \(self.measured) · задержка DNS"
            self.summary += " · " + DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .short)
            if status.incomplete { self.summary += " · проверка продолжится в следующий час" }
        }
    }
    deinit {
        let values = (coordinator, physical, current)
        DispatchQueue.main.async { Self.release(values.0, values.1, values.2) }
    }
    private static func release(_ coordinator: R013ProbeCoordinator, _ physical: R013UDPDriver, _ current: R013UDPDriver) {
        coordinator.shutdown { released in
            if released { physical.invalidate {}; current.invalidate {} }
            else { DispatchQueue.main.asyncAfter(deadline: .now() + 1) { release(coordinator, physical, current) } }
        }
    }
    func willChange() {
        let change = { self.coordinator.primaryWillChange() }
        if Thread.isMainThread { change() } else { DispatchQueue.main.sync(execute: change) }
    }
    func didChange() {
        DispatchQueue.main.async { [weak self] in self?.coordinator.resumeAfterPrimaryChange() }
    }
    func start(candidates: [TunnelConfiguration], current: @escaping () -> TunnelConfiguration?,
               apply: @escaping (Int, R013PrimaryPermit, @escaping () -> Void) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        let snapshots: [R013ProbeSnapshot] = candidates.enumerated().compactMap { index, config in
            guard let value = WireGuardAdapter.inactiveProbeSnapshot(config) else { return nil }
            return R013ProbeSnapshot(id: String(index), config: value.uapi, source: value.source)
        }
        // One explicit resolver already configured by an imported profile. No
        // OS DNS change, hardcoded public fallback or default socket resolution.
        let resolver = candidates.flatMap { $0.interface.dns }.map { $0.stringRepresentation }.first(where: Self.publicIPv4)
        guard !snapshots.isEmpty, let resolver = resolver else {
            summary = "Часовая проверка недоступна: нужен IPv4 DNS из конфигурации"; return
        }
        summary = "Сравнение \(snapshots.count) VPN: первая проверка через 30 сек, затем раз в час"
        coordinator.startHourly(input: {
            guard current() != nil else { return nil }
            return R013ProbeInput(autoActive: true, resolver: resolver + ":53", startIndex: 0, candidates: snapshots)
        }, apply: { [weak self] snapshot, permit, done in
            guard current() != nil, let index = Int(snapshot.id), candidates.indices.contains(index) else {
                _ = permit.commit(.unknown); done(); return
            }
            self?.summary = "Выбран более быстрый VPN · " + (candidates[index].name ?? "Сервер")
            apply(index, permit, done)
        })
    }
    func stop() {
        dispatchPrecondition(condition: .onQueue(.main))
        coordinator.stopHourly()
    }
    // Adapter must already have stopped and committed actual state. Failure
    // retains ownership and retries; drivers are never discarded while live.
    func shutdown() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopping else { return }; stopping = true
        coordinator.shutdown { [self] released in
            guard released else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.stopping = false; self.shutdown() }; return
            }
            physical.invalidate {}; current.invalidate {}
        }
    }
    private static func publicIPv4(_ value: String) -> Bool {
        guard IPv4Address(value) != nil else { return false }
        let octets = value.split(separator: ".").compactMap { Int($0) }
        guard octets.count == 4 else { return false }
        return octets[0] != 0 && octets[0] != 10 && octets[0] != 127 && octets[0] < 224 &&
            !(octets[0] == 169 && octets[1] == 254) && !(octets[0] == 172 && (16...31).contains(octets[1])) &&
            !(octets[0] == 192 && octets[1] == 168) && !(octets[0] == 100 && (64...127).contains(octets[1]))
    }
}
