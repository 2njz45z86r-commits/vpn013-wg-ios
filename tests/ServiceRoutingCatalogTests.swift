// SPDX-License-Identifier: MIT
import Foundation

@main struct ServiceRoutingCatalogTests {
    static func main() throws {
        var checks = 0
        func check(_ value: Bool, _ message: String) { precondition(value, message); checks += 1 }
        func rejects(_ body: () throws -> Void) {
            do { try body(); preconditionFailure("Invalid catalog/selection accepted") } catch { checks += 1 }
        }
        let path = URL(fileURLWithPath: CommandLine.arguments[1])
        func data(_ name: String) throws -> Data { try Data(contentsOf: path.appendingPathComponent(name + ".json")) }
        let ui = try data("ServiceCatalogUI"), rules = try data("ServiceCatalogRules"), grouped = try data("ServiceCatalogGroups")
        let catalog = try ServiceRoutingCatalog(ui: ui, rules: rules, groups: grouped)
        let all = catalog.groups.flatMap { $0.services }
        check(all.count == 412 && catalog.groups.count == 23, "Actual owner catalog coverage")
        check(Set(all.map { $0.id }).count == 412, "Every service appears once")
        check(catalog.groups.contains { $0.title.contains("Социальные сети") }, "Social group exists")
        check(catalog.groups.contains { $0.title.contains("Мессенджеры") }, "Messenger group exists")
        let facebook = all.first { $0.name == "Facebook" }!
        check(catalog.displayGroups(matching: "fAcEbOoK").flatMap { $0.services }.contains(facebook), "Friendly name search")
        check(catalog.displayGroups(matching: "not-an-existing-service-name").isEmpty, "Empty search is safe")
        var selection = ServiceRoutingSelection()
        check(selection.mode == .unchanged && selection.only.isEmpty && selection.bypass.isEmpty, "No automatic selection")
        check(try catalog.resolve(selection) == nil, "OFF leaves routing unchanged")
        selection.toggle(facebook.id)
        check(selection.only.isEmpty && selection.bypass.isEmpty, "Disabled selection cannot mutate")
        selection.setOnly(true); rejects { _ = try catalog.resolve(selection) }
        selection.toggle(facebook.id)
        let only = try catalog.resolve(selection)!
        check(only.mode == .only && !only.networks.isEmpty, "Selected real rules resolve")
        selection.setBypass(true)
        check(selection.mode == .bypass && selection.only == [facebook.id], "Mutual exclusion retains inactive choices")
        rejects { _ = try catalog.resolve(selection) }
        selection.toggle(facebook.id)
        let bypass = try catalog.resolve(selection)!
        check(bypass.mode == .bypass && bypass.networks == only.networks, "Opposite mode uses the same service")
        selection.setBypass(false)
        check(try catalog.resolve(selection) == nil, "OFF retains baseline even with remembered choices")
        let original = ProxyRoutingPolicy(mode: .bypass, domains: ["example.invalid"], networks: ["192.0.2.0/24"])
        var policy = original; policy.serviceSelection = selection
        let baseline = try policy.resolved()
        check(baseline.mode == original.mode && baseline.domains == original.domains && baseline.networks == original.networks, "Own baseline restored")
        let encoded = try JSONEncoder().encode(policy)
        check(try JSONDecoder().decode(ProxyRoutingPolicy.self, from: encoded) == policy, "Selection survives encrypted payload serialization")
        let legacy = Data(#"{"mode":"all","domains":[],"networks":[]}"#.utf8)
        check(try JSONDecoder().decode(ProxyRoutingPolicy.self, from: legacy).serviceSelection == nil, "Old saved payload remains compatible")
        rejects { _ = try ServiceRoutingCatalog(ui: ui + Data([32]), rules: rules, groups: grouped) }
        rejects { _ = try ServiceRoutingCatalog(ui: ui, rules: rules + Data([32]), groups: grouped) }
        rejects { _ = try ServiceRoutingCatalog(ui: ui, rules: rules, groups: grouped + Data([32])) }
        rejects { _ = try catalog.resolve(ServiceRoutingSelection(mode: .only, only: ["unknown"])) }
        rejects { _ = try catalog.resolve(ServiceRoutingSelection(mode: .only, only: [facebook.id, facebook.id])) }
        selection = ServiceRoutingSelection(mode: .only, only: all.map { $0.id })
        let complete = try catalog.resolve(selection)!
        check(complete.networks.count == 12_478 && complete.domains.count == 8, "Full catalog bounded union")
        let profile = try ProxyProfile.fromURI("vless://00000000-0000-4000-8000-000000000001@example.invalid:443?type=tcp&security=tls", source: .incy)
        for mode in [ServiceRoutingSelection.Mode.only, .bypass] {
            let selected = ServiceRoutingSelection(mode: mode, only: [facebook.id], bypass: [facebook.id])
            let payload = ProxyTunnelPayload(profile: profile, routing: ProxyRoutingPolicy(serviceSelection: selected))
            let config = try JSONSerialization.jsonObject(with: payload.configuration(resolvedHost: "192.0.2.1")) as! [String: Any]
            let compiled = (config["routing"] as! [String: Any])["rules"] as! [[String: Any]]
            let actual = compiled.first { $0["ip"] != nil }!
            check(actual["ip"] as! [String] == only.networks, "Real packet-engine rules contain the selected service")
            check(actual["outboundTag"] as! String == (mode == .bypass ? "vpn013-direct" : "vpn013-proxy"), "Selected packet-engine action")
            check(compiled.last!["outboundTag"] as! String == (mode == .only ? "vpn013-direct" : "vpn013-proxy"), "Complement packet-engine action")
        }
        print("ServiceRoutingCatalogTests: \(checks) checks passed; no VPN or live requests")
    }
}
