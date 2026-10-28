// SPDX-License-Identifier: MIT
import Foundation

/// A non-secret user preference. Extension behavior is carried explicitly in
/// the encrypted profile; the extension never reads the host app's preferences.
enum VPN013AutomaticMode {
    static let preferenceKey = "VPN013AutomaticModeEnabledV1"
    static let changed = Notification.Name("VPN013AutomaticModeChanged")
    static func enabled(in defaults: UserDefaults = .standard) -> Bool {
        defaults.object(forKey: preferenceKey) as? Bool ?? true
    }
    static func setEnabled(_ value: Bool, in defaults: UserDefaults = .standard) {
        defaults.set(value, forKey: preferenceKey)
        NotificationCenter.default.post(name: changed, object: nil)
    }
}

/// Compare like-for-like real measurements. ICMP and tunneled HTTP values must
/// never be mixed or presented as the same kind of ping.
struct AutomaticLatencySample: Equatable {
    enum Metric { case endpointICMP, tunneledHTTP }
    let index: Int
    let milliseconds: Double
    let metric: Metric
}
enum AutomaticSelection {
    static let checkInterval: TimeInterval = 300
    static let minimumImprovementMilliseconds: Double = 30
    static let minimumImprovementRatio: Double = 0.20
    static func best(_ samples: [AutomaticLatencySample], count: Int, metric: AutomaticLatencySample.Metric) -> AutomaticLatencySample? {
        samples.filter { (0..<count).contains($0.index) && $0.metric == metric && $0.milliseconds.isFinite && $0.milliseconds >= 0 }
            .min { $0.milliseconds == $1.milliseconds ? $0.index < $1.index : $0.milliseconds < $1.milliseconds }
    }
    static func replacement(current: AutomaticLatencySample?, candidates: [AutomaticLatencySample], count: Int,
                            currentIndex: Int, consecutiveFailures: Int, secondsSinceSwitch: TimeInterval) -> Int? {
        guard (0..<count).contains(currentIndex), let candidate = best(candidates.filter { $0.index != currentIndex }, count: count, metric: .tunneledHTTP) else { return nil }
        if consecutiveFailures >= 2 { return candidate.index }
        guard secondsSinceSwitch >= checkInterval, let current = current, current.index == currentIndex,
              current.metric == .tunneledHTTP, current.milliseconds.isFinite, current.milliseconds >= 0 else { return nil }
        let difference = current.milliseconds - candidate.milliseconds
        let sufficientlyBetter = difference >= minimumImprovementMilliseconds && candidate.milliseconds <= current.milliseconds * (1 - minimumImprovementRatio)
        return sufficientlyBetter ? candidate.index : nil
    }
}
