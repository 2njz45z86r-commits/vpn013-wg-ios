// SPDX-License-Identifier: MIT
import Foundation

/// Pure decision state. Connection work and probes are serialized by the provider.
struct AutoFailoverPolicy {
    enum Decision: Equatable { case stay, switchTo(Int), wait(TimeInterval), stopped }
    let count: Int
    static let maximumLatencyMilliseconds: Double = 1200
    private(set) var current = 0
    private(set) var failures = 0
    private(set) var visited: Set<Int> = [0]
    private(set) var running = true
    init(count: Int, initialIndex: Int = 0) {
        precondition(count > 0 && (0..<count).contains(initialIndex))
        self.count = count; current = initialIndex; visited = [initialIndex]
    }
    mutating func stop() { running = false }
    mutating func record(healthy: Bool, networkAvailable: Bool, latencyMilliseconds: Double? = nil) -> Decision {
        guard running else { return .stopped }
        guard networkAvailable else { failures = 0; return .wait(15) }
        if healthy, let latency = latencyMilliseconds, latency.isFinite, latency > Self.maximumLatencyMilliseconds {
            failures = 0
            return rotate()
        }
        if healthy { failures = 0; visited = [current]; return .stay }
        failures += 1
        guard failures >= 2 else { return .wait(5) }
        failures = 0
        return rotate()
    }
    private mutating func rotate() -> Decision {
        if visited.count == count { visited = [current]; return .wait(60) }
        for offset in 1..<count {
            let next = (current + offset) % count
            if !visited.contains(next) { current = next; visited.insert(next); return .switchTo(next) }
        }
        return .wait(60)
    }
}
