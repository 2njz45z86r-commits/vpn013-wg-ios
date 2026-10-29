// SPDX-License-Identifier: MIT
import Foundation

/// One serial owner of the engine transition. Start callbacks are fenced by an
/// epoch; the next engine cannot start until the previous engine reports stop.
final class CrossProtocolCoordinator {
    enum Phase: Equatable { case idle, starting(Int), running(Int), switching(Int), stopped }
    private(set) var phase: Phase = .idle
    private(set) var selection: CrossProtocolSelection
    private(set) var trafficConfirmed = false
    var networkAvailable = true
    var changed: (() -> Void)?
    private let startEngine: (Int, Bool, @escaping (Error?) -> Void) -> Void
    private let stopEngine: (@escaping (Error?) -> Void) -> Void
    private let pauseEngine: (Bool) -> Void
    private let ended: (Error) -> Void
    private var generation = 0
    private var pending: ((Error?) -> Void)?
    init(count: Int, enabled: Bool,
         start: @escaping (Int, Bool, @escaping (Error?) -> Void) -> Void,
         stop: @escaping (@escaping (Error?) -> Void) -> Void,
         pause: @escaping (Bool) -> Void, ended: @escaping (Error) -> Void) {
        selection = CrossProtocolSelection(count: count, enabled: enabled)
        startEngine = start; stopEngine = stop; pauseEngine = pause; self.ended = ended
    }
    func start(completion: @escaping (Error?) -> Void) {
        guard phase == .idle else { completion(NSError(domain: "VPN013.CrossProtocol", code: 1)); return }
        pending = completion; phase = .starting(0); changed?(); launch(0)
    }
    private func launch(_ index: Int) {
        let stamp = generation
        var answered = false
        startEngine(index, selection.enabled) { [weak self] error in
            guard let self = self, self.generation == stamp, !self.selection.stopped, !answered else { return }
            answered = true
            if let error = error {
                if !self.failed() { self.finish(error) }
            } else {
                self.phase = .running(index); self.pauseEngine(self.selection.enabled)
                let done = self.pending; self.pending = nil; done?(nil); self.changed?()
            }
        }
    }
    func verifiedTraffic() {
        guard case .running = phase else { return }; selection.verifiedTraffic(); trafficConfirmed = true
    }
    /// False means the existing group must retain its normal retry schedule.
    @discardableResult func failed() -> Bool {
        guard phase != .idle, phase != .stopped else { return false }
        if case .switching = phase { return true }
        switch selection.failed(networkAvailable: networkAvailable) {
        case .tryGroup(let index):
            trafficConfirmed = false; generation += 1; let stamp = generation; phase = .switching(index); changed?()
            stopEngine { [weak self] error in
                guard let self = self, self.generation == stamp, !self.selection.stopped else { return }
                if let error = error { self.finish(error); return }
                self.phase = .starting(index); self.changed?(); self.launch(index)
            }
            return true
        case .exhausted:
            finish(NSError(domain: "VPN013.CrossProtocol", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Ни одна загруженная конфигурация не подтвердила VPN-трафик. Проверьте интернет, срок доступа и обновите ключ в кабинете провайдера."]))
            return true
        case .paused, .waitForNetwork, .stopped: return false
        }
    }
    func setEnabled(_ enabled: Bool) {
        selection.enabled = enabled
        if case .running = phase { pauseEngine(enabled) }
        changed?()
    }
    private func finish(_ error: Error) {
        guard phase != .stopped else { return }
        generation += 1; let stamp = generation; selection.stop(); phase = .stopped
        stopEngine { [weak self] _ in
            guard let self = self, self.generation == stamp else { return }
            let done = self.pending; self.pending = nil
            if let done = done { done(error) } else { self.ended(error) }
            self.changed?()
        }
    }
    func stop(completion: @escaping () -> Void) {
        generation += 1; selection.stop(); phase = .stopped
        let done = pending; pending = nil
        done?(NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled))
        stopEngine { _ in completion() }; changed?()
    }
}
