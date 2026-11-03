import Foundation

@main struct ServiceRoutingOverlapTests {
    static func expectConflict(_ map: [String: [String]], _ chosen: Set<String>) throws {
        guard let result = try ServiceIPv4Overlap.firstConflict(networks: map, selected: chosen),
              chosen.contains(result.0), !chosen.contains(result.1) else {
            preconditionFailure("Expected a conflict between selected and unselected services")
        }
    }
    static func expectNoConflict(_ map: [String: [String]], _ chosen: Set<String>) throws {
        let result = try ServiceIPv4Overlap.firstConflict(networks: map, selected: chosen)
        precondition(result == nil)
    }
    static func main() throws {
        try expectConflict(["a": ["192.0.2.0/24"], "b": ["192.0.2.128/25"]], ["a"])
        try expectConflict(["a": ["192.0.2.128/25"], "b": ["192.0.2.0/24"]], ["a"])
        try expectConflict(["a": ["0.0.0.0/0"], "b": ["255.255.255.255/32"]], ["a"])
        try expectConflict(["a": ["198.51.100.4/32"], "b": ["198.51.100.4/32"]], ["a"])
        try expectNoConflict(["a": ["192.0.2.0/25"], "b": ["192.0.2.128/25"]], ["a"])
        try expectNoConflict(["a": ["192.0.2.0/24"], "b": ["192.0.2.0/24"]], ["a", "b"])
        for text in ["192.0.2.1/24", "192.0.2.0/33", "01.0.0.0/8", "::/0", "not-ip"] {
            do { _ = try ServiceIPv4Overlap.interval(text, service: "a"); preconditionFailure("Invalid IPv4 range accepted") } catch { }
        }
        do { _ = try ServiceIPv4Overlap.firstConflict(networks: ["a": []], selected: ["missing"]); preconditionFailure("Unknown service accepted") } catch { }

        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        func data(_ name: String) throws -> Data { try Data(contentsOf: root.appendingPathComponent(name + ".json")) }
        let catalog = try ServiceRoutingCatalog(ui: data("ServiceCatalogUI"), rules: data("ServiceCatalogRules"), groups: data("ServiceCatalogGroups"))
        let services = catalog.groups.flatMap { $0.services }
        guard let instagram = services.first(where: { $0.name == "Instagram" }),
              let aeroflot = services.first(where: { $0.name == "Aeroflot" }),
              let codeium = services.first(where: { $0.name == "Codeium" }) else { preconditionFailure("Pinned synthetic test catalog changed") }
        var selection = ServiceRoutingSelection(); selection.setOnly(true); selection.toggle(instagram.id)
        // Existing selections remain resolvable; only a *new save* is refused.
        let prior = try catalog.resolve(selection)
        precondition(prior != nil)
        do {
            try catalog.validateNewSelection(selection)
            preconditionFailure("Shared Instagram networks accepted")
        } catch ServiceCatalogError.overlappingServices(let selected, let other) {
            precondition(selected == "Instagram" && !other.isEmpty)
            precondition(!ServiceCatalogError.overlappingServices(selected, other).localizedDescription.contains("/24"))
        }
        selection.setOnly(false)
        try catalog.validateNewSelection(selection) // turning the mode off is allowed
        var isolated = ServiceRoutingSelection(); isolated.setBypass(true); isolated.toggle(aeroflot.id)
        try catalog.validateNewSelection(isolated) // a nonoverlapping catalog entry remains usable
        var domainOnly = ServiceRoutingSelection(); domainOnly.setOnly(true); domainOnly.toggle(codeium.id)
        do { _ = try catalog.resolveWireGuard(domainOnly); preconditionFailure("WireGuard accepted a domain-only service") }
        catch ServiceCatalogError.wireGuardDomains { }
        print("PASS selected vs unselected IPv4 overlap guard; prior resolution and off retained")
    }
}
