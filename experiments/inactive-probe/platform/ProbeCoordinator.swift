// SPDX-License-Identifier: MIT
// Platform coordinator; integration into the released provider is separate.
import Foundation

struct R013ProbeSnapshot: Codable, Equatable {
    let id: String
    let config: String // Memory only. Never log, persist, or send to the app UI.
    let source: String
}
struct R013ProbeInput: Codable {
    let auto_active: Bool
    let resolver: String
    let start_index: Int
    let candidates: [R013ProbeSnapshot]
}
struct R013ProbeMetric: Decodable {
    let milliseconds: Double
    let samples: Int
    let epoch: UInt64
    let method: String
    let target: String
}
struct R013ProbeRow: Decodable {
    let id: String
    let status: String
    let metric: R013ProbeMetric?
}
struct R013ProbeStatus: Decodable {
    let status: String
    let before: R013ProbeMetric?
    let after: R013ProbeMetric?
    let rows: [R013ProbeRow]?
    let choice_id: String?
    let incomplete: Bool
    let next_index: Int
}

enum R013ActualPrimary {
    case unknown
    case idle
    case active(uapi: String)
}

// This permit must cover the WHOLE primary mutation (including stop/start when
// changing optional AWG settings). It is never implicitly committed by deinit.
// Missing completion intentionally keeps probes disabled rather than guessing.
final class R013PrimaryPermit {
    private let controller: UInt64
    private let transition: UInt64
    private let lock = NSLock()
    private var finished = false
    fileprivate init(controller: UInt64, transition: UInt64) {
        self.controller = controller; self.transition = transition
    }
    @discardableResult func commit(_ actual: R013ActualPrimary) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !finished else { return false }; finished = true
        switch actual {
        case .unknown: return R013ProbeCommitChange(controller, transition, 0, nil, 0) == 0
        case .idle: return R013ProbeCommitChange(controller, transition, 1, nil, 0) == 0
        case .active(let uapi):
            guard !uapi.isEmpty, uapi.utf8.count <= 1024 * 1024 else {
                _ = R013ProbeCommitChange(controller, transition, 0, nil, 0); return false
            }
            var data = Data(uapi.utf8)
            return data.withUnsafeMutableBytes { bytes in
                R013ProbeCommitChange(controller, transition, 1, bytes.baseAddress, UInt32(bytes.count)) == 0
            }
        }
    }
}

// The provider MUST route every real start/update/stop/path/failure/Auto switch
// through beginPrimaryChange, then commit only its observed result. This class
// does not intercept WireGuardAdapter itself. Never enable it in a release until
// all those paths are wired and native/device traffic checks pass.
final class R013ProbeCoordinator {
    typealias CurrentInput = () -> R013ProbeInput?
    typealias Apply = (R013ProbeSnapshot, R013PrimaryPermit, @escaping () -> Void) -> Void
    private let controller: UInt64
    private let work = DispatchQueue(label: "com.vpn013.probe.control", qos: .utility)
    private var generation: UInt64 = 0
    private var operation: UInt64 = 0
    private var timer: DispatchWorkItem?
    private var polling: DispatchWorkItem?
    private var currentInput: CurrentInput?
    private var apply: Apply?
    private var stopped = false
    private var nextIndex = 0
    private var autoActive = false
    var metrics: ((R013ProbeStatus) -> Void)? // Typed DNS values only; not ICMP.

    init?(physical: UInt64, throughTunnel: UInt64) {
        let id = R013ProbeCreate(physical, throughTunnel)
        guard id != 0 else { return nil }; controller = id
    }
    private func requireMain() { dispatchPrecondition(condition: .onQueue(.main)) }

    func startHourly(input: @escaping CurrentInput, apply: @escaping Apply) {
        requireMain(); guard !stopped else { return }
        cancelScheduledWork(); autoActive = true
        self.currentInput = input; self.apply = apply
        scheduleHour()
    }
    func stopHourly() {
        requireMain(); autoActive = false; currentInput = nil; apply = nil
        cancelScheduledWork()
    }
    private func cancelScheduledWork(cancelScan: Bool = true) {
        generation &+= 1; timer?.cancel(); timer = nil; polling?.cancel(); polling = nil
        let old = operation; operation = 0
        if old != 0, cancelScan { work.async { [self] in _ = R013ProbeCancelScan(controller, old) } }
    }
    private func scheduleHour() {
        timer?.cancel(); guard autoActive, !stopped else { return }
        let stamp = generation
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, self.generation == stamp else { return }; self.run()
        }
        timer = item
        DispatchQueue.main.asyncAfter(deadline: .now() + 3600, execute: item)
    }
    // Lifecycle mutation cannot begin until Go confirms all candidate/current
    // measurements have genuinely closed. No C wait blocks the main/UDP queue.
    func beginPrimaryChange(completed: @escaping (R013PrimaryPermit?) -> Void) {
        requireMain(); guard !stopped else { completed(nil); return }
        cancelScheduledWork(cancelScan: false) // BeginChange itself cancels/drains; no second10s wait.
        let stamp = generation
        work.async { [self] in
            let transition = R013ProbeBeginChange(controller)
            let acknowledged = DispatchSemaphore(value: 0)
            DispatchQueue.main.async { [self] in
                defer { acknowledged.signal() }
                guard generation == stamp, !stopped, transition != 0 else {
                    if transition != 0 { _ = R013PrimaryPermit(controller: controller, transition: transition).commit(.unknown) }
                    completed(nil); return
                }
                completed(R013PrimaryPermit(controller: controller, transition: transition))
            }
            // Keep the control queue ordered until main has adopted or aborted
            // this permit. A newer manual change cannot race a stale callback
            // and receive Busy merely because that callback hasn't run yet.
            acknowledged.wait()
        }
    }
    func resumeAfterPrimaryChange() { requireMain(); scheduleHour() }

    private func run() {
        requireMain()
        guard autoActive, !stopped, operation == 0, let input = currentInput?(), input.auto_active,
              !input.candidates.isEmpty, input.candidates.count <= 30 else { scheduleHour(); return }
        let rotated = R013ProbeInput(auto_active: true, resolver: input.resolver,
                                    start_index: nextIndex % input.candidates.count, candidates: input.candidates)
        guard let data = try? JSONEncoder().encode(rotated), data.count <= 4 * 1024 * 1024 else { scheduleHour(); return }
        let stamp = generation
        work.async { [self, data] in
            var owned = data
            let id = owned.withUnsafeMutableBytes { bytes in R013ProbeStartScan(controller, bytes.baseAddress, UInt32(bytes.count)) }
            DispatchQueue.main.async { [self] in
                guard generation == stamp, autoActive, !stopped else {
                    if id != 0 { work.async { [self] in _ = R013ProbeCancelScan(controller, id) } }; return
                }
                guard id != 0 else { scheduleHour(); return }
                operation = id; poll(stamp: stamp, id: id, input: rotated)
            }
        }
    }
    private func poll(stamp: UInt64, id: UInt64, input: R013ProbeInput) {
        guard generation == stamp, operation == id, autoActive, !stopped else { return }
        work.async { [self] in
            var data = Data(count: 64 * 1024)
            let size = data.withUnsafeMutableBytes { bytes in R013ProbePollScan(controller, id, bytes.baseAddress, UInt32(bytes.count)) }
            let status: R013ProbeStatus? = size > 0 ? try? JSONDecoder().decode(R013ProbeStatus.self, from: data.prefix(Int(size))) : nil
            DispatchQueue.main.async { [self] in
                guard generation == stamp, operation == id, autoActive, !stopped else { return }
                if let status = status, status.status == "pending" {
                    let item = DispatchWorkItem { [weak self] in self?.poll(stamp: stamp, id: id, input: input) }
                    polling = item; DispatchQueue.main.asyncAfter(deadline: .now() + 0.25, execute: item); return
                }
                operation = 0
                guard let status = status, status.status == "complete" else { scheduleHour(); return }
                // A profile can be edited/deleted without changing the active
                // engine. Do not label fresh UI rows with old snapshot metrics.
                guard let fresh = currentInput?(), fresh.auto_active, fresh.resolver == input.resolver,
                      fresh.candidates == input.candidates else { scheduleHour(); return }
                nextIndex = status.next_index
                metrics?(status)
                guard generation == stamp, autoActive, !stopped, let chosen = status.choice_id,
                      let latest = currentInput?(), latest.auto_active,
                      let snapshot = latest.candidates.first(where: { $0.id == chosen }), let apply = apply else { scheduleHour(); return }
                authorizeChoice(id: id, stamp: stamp, snapshot: snapshot, resolver: latest.resolver, apply: apply)
            }
        }
    }
    private func authorizeChoice(id: UInt64, stamp: UInt64, snapshot: R013ProbeSnapshot, resolver: String, apply: @escaping Apply) {
        let input = R013ProbeInput(auto_active: true, resolver: resolver, start_index: 0, candidates: [snapshot])
        guard let data = try? JSONEncoder().encode(input), data.count <= 4 * 1024 * 1024 else { scheduleHour(); return }
        work.async { [self] in
            var owned = data
            let token = owned.withUnsafeMutableBytes { bytes in R013ProbeBeginChoice(controller, id, bytes.baseAddress, UInt32(bytes.count)) }
            let acknowledged = DispatchSemaphore(value: 0)
            DispatchQueue.main.async { [self] in
                defer { acknowledged.signal() }
                guard generation == stamp, autoActive, !stopped, token != 0 else {
                    if token != 0 { _ = R013PrimaryPermit(controller: controller, transition: token).commit(.unknown) }
                    if generation == stamp { scheduleHour() }; return
                }
                // Caller commits the actual applied configuration on this permit
                // before invoking completion. There is no guessed state restore.
                apply(snapshot, R013PrimaryPermit(controller: controller, transition: token)) { [weak self] in
                    DispatchQueue.main.async {
                        guard let self = self, self.generation == stamp else { return }; self.scheduleHour()
                    }
                }
            }
            acknowledged.wait()
        }
    }
    // On failure the provider must retain this coordinator and retry shutdown;
    // never unregister drivers while Release still owns a live transport.
    func shutdown(completed: @escaping (Bool) -> Void) {
        requireMain(); stopHourly(); stopped = true
        work.async { [self] in
            let released = R013ProbeRelease(controller) == 0
            DispatchQueue.main.async { completed(released) }
        }
    }
    #if R013_PROBE_TESTING
    // Native test drives the same coordinator without sleeping an actual hour.
    // This entry point is excluded from normal builds and claims no iOS timing.
    func runNowForTesting() { requireMain(); timer?.cancel(); timer = nil; run() }
    #endif
}
