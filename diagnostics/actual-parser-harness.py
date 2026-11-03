"""Compile the pinned patched parser against synthetic Linux model stubs.

This is a parser diagnostic, not an iOS, crypto, or release test. The patcher
checks exact hashes of both upstream input files before modifying a fresh copy.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
upstream = Path(sys.argv[1]).resolve()
destination = Path(sys.argv[2])
sys.path.insert(0, str(repo / 'scripts'))
import patch_primary_resource_swift as patcher

stubs = r'''
import Foundation
public struct Key: Hashable {
    public var base64Key: String
    public init?(base64Key: String) { guard !base64Key.isEmpty else { return nil }; self.base64Key = base64Key }
}
public typealias PrivateKey = Key
public typealias PublicKey = Key
public typealias PreSharedKey = Key
public struct IPAddressRange: Hashable {
    public var stringRepresentation: String
    public init?(from: String) { guard !from.isEmpty else { return nil }; stringRepresentation = from }
}
public struct DNSServer: Hashable {
    public var stringRepresentation: String
    public init?(from: String) { guard !from.isEmpty else { return nil }; stringRepresentation = from }
}
public struct Endpoint: Hashable {
    public var stringRepresentation: String
    public init?(from: String) { guard !from.isEmpty else { return nil }; stringRepresentation = from }
}
extension String {
    func splitToArray(trimmingCharacters: CharacterSet) -> [String] {
        split(separator: ",").map { String($0).trimmingCharacters(in: trimmingCharacters) }
    }
}
final class TunnelConfiguration {
    var name: String?
    var interface: InterfaceConfiguration
    var peers: [PeerConfiguration]
    init(name: String?, interface: InterfaceConfiguration, peers: [PeerConfiguration]) {
        self.name = name; self.interface = interface; self.peers = peers
    }
}
'''
tests = r'''
@main enum ActualParserDiagnostic {
    static func main() throws {
        let base = "[Interface]\nPrivateKey = synthetic\n"
        let plain = try TunnelConfiguration(fromWgQuickConfig: base)
        precondition(!plain.interface.legacyAWG15)
        let old = try TunnelConfiguration(fromWgQuickConfig: base + "I1 = <b 0xF>\n")
        precondition(old.interface.legacyAWG15 && old.interface.specialJunk1 == "<b 0xF>")
        let output = old.asWgQuickConfig()
        precondition(output.contains("# VPN013-AmneziaWG = 1.5") && output.contains("I1 = <b 0xF>"))
        let roundTrip = try TunnelConfiguration(fromWgQuickConfig: output)
        precondition(roundTrip.interface.legacyAWG15 && roundTrip.interface.specialJunk1 == "<b 0xF>")
        let oldPrefix = try TunnelConfiguration(fromWgQuickConfig: base + "I2 = <b 0Xaa>\n")
        precondition(oldPrefix.interface.legacyAWG15)
        let ambiguous = try TunnelConfiguration(fromWgQuickConfig: base + "I1 = <t>\n")
        precondition(!ambiguous.interface.legacyAWG15)
        let selected = try TunnelConfiguration(fromWgQuickConfig: "# VPN013-AmneziaWG = 1.5\n" + base + "I1 = <t>\n")
        precondition(selected.interface.legacyAWG15)
        let oldFields = try TunnelConfiguration(fromWgQuickConfig: base + "J3 = <b 0xAA>\nITime = 30\n")
        precondition(oldFields.interface.legacyAWG15 && oldFields.interface.legacyIntervalSeconds == 30)
        let modern = try TunnelConfiguration(fromWgQuickConfig: base + "S3 = 16\nI1 = <b 0xFF>\nDisableCookies = false\n")
        precondition(!modern.interface.legacyAWG15 && modern.interface.cookieReplyPacketJunkSize == 16)
        do {
            _ = try TunnelConfiguration(fromWgQuickConfig: base + "I1 = <b 0xF><unknown>\n")
            preconditionFailure("invalid tag accepted")
        } catch {}
        let peer = "[Peer]\nPublicKey = synthetic-public\nAllowedIPs = 0.0.0.0/0\nEndpoint = test.example.invalid:8443\n"
        let wg = try TunnelConfiguration(fromWgQuickConfig: base + "Address = 10.0.0.2/32\nDNS = 1.1.1.1\n" + peer)
        precondition(!wg.interface.legacyAWG15 && wg.interface.listenPort == nil && wg.interface.mtu == nil)
        precondition(wg.peers.count == 1 && wg.peers[0].endpoint?.stringRepresentation == "test.example.invalid:8443")
        let wgRound = try TunnelConfiguration(fromWgQuickConfig: wg.asWgQuickConfig())
        precondition(wgRound.interface.listenPort == nil && wgRound.interface.mtu == nil && wgRound.peers.count == 1)
        let awg20 = try TunnelConfiguration(fromWgQuickConfig: base + "S3 = 16\nS4 = 20\nI1 = <b 0xFF>\n" + peer)
        precondition(!awg20.interface.legacyAWG15 && awg20.interface.cookieReplyPacketJunkSize == 16 && awg20.interface.transportPacketJunkSize == 20)
        let awg20Round = try TunnelConfiguration(fromWgQuickConfig: awg20.asWgQuickConfig())
        precondition(awg20Round.interface.specialJunk1 == "<b 0xFF>" && awg20Round.interface.transportPacketJunkSize == 20)
        let awg31 = try TunnelConfiguration(fromWgQuickConfig: base + "S4 = 20\nHeaderProtectionKey = synthetic-header\nRandomTrailers = true\nDisableCookies = false\n" + peer)
        precondition(!awg31.interface.legacyAWG15 && awg31.interface.headerProtectionKey?.base64Key == "synthetic-header" && awg31.interface.randomTrailers == "true")
        let awg31Round = try TunnelConfiguration(fromWgQuickConfig: awg31.asWgQuickConfig())
        precondition(awg31Round.interface.headerProtectionKey?.base64Key == "synthetic-header" && awg31Round.interface.randomTrailers == "true" && awg31Round.interface.disableCookies == "false")
        print("ActualPatchedParser: 12 synthetic scenarios passed with model stubs; not an iOS test")
    }
}
'''
with tempfile.TemporaryDirectory(prefix='vpn013-parser-') as tmp:
    root = Path(tmp)
    pin = '9d5ee60edefa95b933a738dd7cda671dd18021fc'
    for relative in patcher.PINNED_SHA256:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(['git', '-C', str(upstream), 'show', pin + ':' + relative.as_posix()]))
    patcher.patch(root)
    parser = (root / patcher.PARSER).read_text(encoding='utf-8')
    interface = (repo / 'overlay/Sources/WireGuardKit/InterfaceConfiguration.swift').read_text(encoding='utf-8')
    interface = interface.split('extension InterfaceConfiguration: Equatable')[0].replace('import Network', '')
    peer = subprocess.check_output(['git', '-C', str(upstream), 'show', pin + ':Sources/WireGuardKit/PeerConfiguration.swift']).decode('utf-8')
    peer = peer.split('extension PeerConfiguration: Equatable')[0]
    destination.write_text(stubs + '\n' + interface + '\n' + peer + '\n' + parser + '\n' + tests, encoding='utf-8')
