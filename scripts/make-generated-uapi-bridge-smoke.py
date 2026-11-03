from pathlib import Path
source=Path('overlay/Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift').read_text(encoding='utf-8')
a=source.index('    func uapiConfiguration()');b=source.index('    func generateNetworkSettings()',a);generator=source[a:b]
a=source.index('    private class func uapiBool(');b=source.index('\n    }',a)+len('\n    }');boolfunc=source[a:b]
source=Path('overlay/VPN013/ProxyPacketAdapter.swift').read_text(encoding='utf-8');a=source.index('    static func convertedWireGuardSettings(');b=source.index('\n    }',a)+len('\n    }');bridge=source[a:b].replace('    static func ','func ',1)
header=r'''import Foundation
import Darwin
@_silgen_name("R013ProxyConvertWireGuard")
func R013ProxyConvertWireGuard(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
struct Key { let hexKey: String }
struct Address { let stringRepresentation: String }
enum Host { case name(String), numeric }
struct Endpoint { let host: Host; let stringRepresentation: String }
struct ResolutionError: Error {}
typealias EndpointResolutionResult = Result<(Endpoint, Endpoint), ResolutionError>
struct Interface {
    var privateKey: Key
    var legacyAWG15 = false
    var listenPort: Int? = nil
    var junkPacketCount: String? = nil, junkPacketMinSize: String? = nil, junkPacketMaxSize: String? = nil
    var initPacketJunkSize: String? = nil, responsePacketJunkSize: String? = nil, cookieReplyPacketJunkSize: String? = nil, transportPacketJunkSize: String? = nil
    var initPacketMagicHeader: String? = nil, responsePacketMagicHeader: String? = nil, underloadPacketMagicHeader: String? = nil, transportPacketMagicHeader: String? = nil
    var specialJunk1: String? = nil, specialJunk2: String? = nil, specialJunk3: String? = nil, specialJunk4: String? = nil, specialJunk5: String? = nil
    var legacyJunk1: String? = nil, legacyJunk2: String? = nil, legacyJunk3: String? = nil
    var legacyIntervalSeconds: Int? = nil
    var headerProtectionKey: Key? = nil
    var contentPaddingAddition: String? = nil, rekeyAfterTime: String? = nil, rekeyTimeout: String? = nil, rejectAfterTime: String? = nil, keepaliveTimeout: String? = nil, maxHandshakeAttempts: String? = nil
    var randomTrailers: String? = nil, disableCookies: String? = nil
}
struct Peer { var publicKey: Key; var preSharedKey: Key? = nil; var persistentKeepAlive: String? = nil; var allowedIPs: [Address] }
struct TunnelConfiguration { var interface: Interface; var peers: [Peer] }
class Generator {
    let tunnelConfiguration: TunnelConfiguration
    let resolvedEndpoints: [Endpoint?]
    init(_ value: TunnelConfiguration, endpoints: [Endpoint?]) { tunnelConfiguration=value; resolvedEndpoints=endpoints }
    private class func reresolveEndpoint(_ value: Endpoint) -> EndpointResolutionResult { .success((value,value)) }
'''
footer=r'''
}
'''+bridge+r'''
let key=Key(hexKey:String(repeating:"12",count:32))
let peer=Peer(publicKey:key,allowedIPs:[Address(stringRepresentation:"0.0.0.0/0"),Address(stringRepresentation:"::/0")])
let endpoint=Endpoint(host:.numeric,stringRepresentation:"127.0.0.1:8443")
for family in ["wg","classic","legacy15","awg2","awg31"] {
    var iface=Interface(privateKey:key)
    if family != "wg" {
        iface.junkPacketCount="2"; iface.junkPacketMinSize="40"; iface.junkPacketMaxSize="70"
        iface.initPacketJunkSize="16"; iface.responsePacketJunkSize="16"
        iface.initPacketMagicHeader="123456"; iface.responsePacketMagicHeader="654321"
        iface.underloadPacketMagicHeader="777777"; iface.transportPacketMagicHeader="888888"
    }
    if family == "legacy15" { iface.legacyAWG15=true; iface.legacyJunk1="<b 0xa1a2><r 16>"; iface.legacyIntervalSeconds=1 }
    if family == "awg2" || family == "awg31" { iface.cookieReplyPacketJunkSize="12"; iface.specialJunk1="<b 0xf1f2><r 16>" }
    if family == "awg31" { iface.transportPacketJunkSize="20"; iface.headerProtectionKey=key; iface.randomTrailers="on"; iface.disableCookies="off" }
    let g=Generator(TunnelConfiguration(interface:iface,peers:[peer]),endpoints:[endpoint]); let (uapi,_)=g.uapiConfiguration()
    guard let data=convertedWireGuardSettings(uapi:uapi,addresses:["10.0.0.2/32","fd13::2/128"],effectiveMTU:1280),
          let obj=try JSONSerialization.jsonObject(with:data) as? [String:Any],
          let peers=obj["peers"] as? [[String:Any]], peers.count==1, peers[0]["endpoint"] as? String==endpoint.stringRepresentation,
          let awg=obj["vpn013AWG"] as? [String:String] else { fatalError("generated profile rejected") }
    guard awg["r013_legacy15"] == (family == "legacy15" ? "true":"false") else { fatalError("legacy marker changed") }
    if family == "legacy15" { guard awg["i1"] == "" && awg["j1"] == "<b 0xa1a2><r 16>" else { fatalError("legacy fields changed") } }
    if family == "awg31" { guard awg["random_trailers"] == "1" && awg["disable_cookies"] == "0" && awg["header_protection_key"] == key.hexKey else { fatalError("3.1 fields changed") } }
}
var fixed=Interface(privateKey:key);fixed.listenPort=12345
let fixedGenerator=Generator(TunnelConfiguration(interface:fixed,peers:[peer]),endpoints:[endpoint])
guard convertedWireGuardSettings(uapi:fixedGenerator.uapiConfiguration().0,addresses:["10.0.0.2/32"],effectiveMTU:1280)==nil else { fatalError("nonzero local port accepted") }
let multi=Generator(TunnelConfiguration(interface:Interface(privateKey:key),peers:[peer,peer]),endpoints:[endpoint,endpoint])
guard convertedWireGuardSettings(uapi:multi.uapiConfiguration().0,addresses:["10.0.0.2/32"],effectiveMTU:1280)==nil else { fatalError("multi-peer accepted") }
print("Generated UAPI bridge: five synthetic families converted, fixed local port and multi-peer rejected; stub model, no VPN")
'''
Path('build').mkdir(exist_ok=True)
Path('build/generated-uapi-bridge-smoke.swift').write_text(header+generator+boolfunc+footer,encoding='utf-8')
