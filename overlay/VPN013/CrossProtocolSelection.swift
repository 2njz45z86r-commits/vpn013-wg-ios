// SPDX-License-Identifier: MIT
import Foundation

/// No credentials, networking or OS preferences. A successful traffic check
/// opens a fresh recovery cycle; a mere connected flag never does.
struct CrossProtocolSelection {
    enum Decision: Equatable { case tryGroup(Int), waitForNetwork, paused, exhausted, stopped }
    private(set) var current: Int
    private(set) var visited: Set<Int>
    private(set) var stopped = false
    var enabled: Bool
    let count: Int
    init(count: Int, enabled: Bool = true) {
        precondition((1...120).contains(count))
        self.count = count; self.enabled = enabled; current = 0; visited = [0]
    }
    mutating func verifiedTraffic() {
        guard !stopped else { return }; visited = [current]
    }
    mutating func failed(networkAvailable: Bool) -> Decision {
        guard !stopped else { return .stopped }
        guard enabled else { return .paused }
        guard networkAvailable else { return .waitForNetwork }
        guard let next = (0..<count).first(where: { !visited.contains($0) }) else { return .exhausted }
        visited.insert(next); current = next; return .tryGroup(next)
    }
    mutating func stop() { stopped = true }
}
