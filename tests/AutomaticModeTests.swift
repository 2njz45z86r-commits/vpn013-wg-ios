import Foundation
@main struct AutomaticModeTests {
    static func main() {
        let domain = "VPN013.AutomaticModeTest." + UUID().uuidString
        let defaults = UserDefaults(suiteName: domain)!
        defer { defaults.removePersistentDomain(forName: domain) }
        precondition(VPN013AutomaticMode.enabled(in: defaults))
        VPN013AutomaticMode.setEnabled(false, in: defaults)
        precondition(!VPN013AutomaticMode.enabled(in: defaults))
        precondition(!VPN013AutomaticMode.enabled(in: UserDefaults(suiteName: domain)!))
        VPN013AutomaticMode.setEnabled(true, in: defaults)
        precondition(VPN013AutomaticMode.enabled(in: defaults))
        func sample(_ index: Int, _ value: Double, _ metric: AutomaticLatencySample.Metric = .tunneledHTTP) -> AutomaticLatencySample { AutomaticLatencySample(index: index, milliseconds: value, metric: metric) }
        precondition(AutomaticSelection.checkInterval == 300)
        precondition(AutomaticSelection.best([sample(2, 20, .endpointICMP), sample(0, 60, .endpointICMP), sample(1, .nan, .endpointICMP)], count: 3, metric: .endpointICMP)?.index == 2)
        precondition(AutomaticSelection.best([sample(0, 1, .endpointICMP)], count: 2, metric: .tunneledHTTP) == nil)
        precondition(AutomaticSelection.replacement(current: sample(0, 120), candidates: [sample(1, 100)], count: 2, currentIndex: 0, consecutiveFailures: 0, secondsSinceSwitch: 300) == nil)
        precondition(AutomaticSelection.replacement(current: sample(0, 200), candidates: [sample(1, 70)], count: 2, currentIndex: 0, consecutiveFailures: 0, secondsSinceSwitch: 299) == nil)
        precondition(AutomaticSelection.replacement(current: sample(0, 200), candidates: [sample(1, 70)], count: 2, currentIndex: 0, consecutiveFailures: 0, secondsSinceSwitch: 300) == 1)
        precondition(AutomaticSelection.replacement(current: nil, candidates: [sample(1, 70)], count: 2, currentIndex: 0, consecutiveFailures: 1, secondsSinceSwitch: 500) == nil)
        precondition(AutomaticSelection.replacement(current: nil, candidates: [sample(1, 70)], count: 2, currentIndex: 0, consecutiveFailures: 2, secondsSinceSwitch: 0) == 1)
        precondition(AutomaticSelection.replacement(current: sample(0, 200, .endpointICMP), candidates: [sample(1, 70)], count: 2, currentIndex: 0, consecutiveFailures: 0, secondsSinceSwitch: 500) == nil)
        print("Automatic mode preference/selection:13 checks passed; synthetic metrics, no VPN traffic")
    }
}
