from pathlib import Path
s=Path('build/generated-uapi-bridge-smoke.swift').read_text(encoding='utf-8')
s=s.replace('import Darwin\n','import Darwin\nimport NetworkExtension\n',1)
s=s.replace('    var privateKey: Key\n','    var privateKey: Key\n    var addresses: [Address] = [Address(stringRepresentation:"10.0.0.2/32"),Address(stringRepresentation:"fd13::2/128")]\n',1)
s=s.replace('struct Peer { var publicKey: Key;','struct Peer { var publicKey: Key; var endpoint: Endpoint? = nil;',1)
s=s.replace('class Generator {','class PacketTunnelSettingsGenerator {',1)
s=s.replace('    private class func reresolveEndpoint(_ value: Endpoint) -> EndpointResolutionResult { .success((value,value)) }\n','''    init(tunnelConfiguration: TunnelConfiguration, resolvedEndpoints: [Endpoint?]) { self.tunnelConfiguration=tunnelConfiguration; self.resolvedEndpoints=resolvedEndpoints }
    func generateNetworkSettings() -> NEPacketTunnelNetworkSettings { let value=NEPacketTunnelNetworkSettings(tunnelRemoteAddress:"127.0.0.1"); value.mtu=1280; return value }
    private class func reresolveEndpoint(_ value: Endpoint) -> EndpointResolutionResult { .success((value,value)) }
''',1)
s=s.replace('Generator(TunnelConfiguration','PacketTunnelSettingsGenerator(TunnelConfiguration')
k='''let peer=Peer(publicKey:key,allowedIPs:[Address(stringRepresentation:"0.0.0.0/0"),Address(stringRepresentation:"::/0")])
let endpoint=Endpoint(host:.numeric,stringRepresentation:"127.0.0.1:8443")'''
assert s.count(k)==1;s=s.replace(k,'''let endpoint=Endpoint(host:.numeric,stringRepresentation:"127.0.0.1:8443")
let peer=Peer(publicKey:key,endpoint:endpoint,allowedIPs:[Address(stringRepresentation:"0.0.0.0/0"),Address(stringRepresentation:"::/0")])''')
s=s.replace('print("Generated UAPI bridge: five synthetic families converted, fixed local port and multi-peer rejected; stub model, no VPN")','')
source=Path('overlay/Sources/WireGuardKit/WireGuardAdapter.swift').read_text(encoding='utf-8');a=source.index('    public static func preciseProfileSnapshot(');b=source.index('\n    }',a)+len('\n    }');snapshot=source[a:b].replace('    public static func ','    static func ',1)
source=Path('overlay/VPN013/ProxyPacketAdapter.swift').read_text(encoding='utf-8');a=source.index('    static func prepareWireGuard(');b=source.index('\n    }',a)+len('\n    }');prepare=source[a:b].replace('    static func ','func ',1)
source=Path('overlay/VPN013/PreciseNetworkSettings.swift').read_text(encoding='utf-8');a=source.index('// Diagnostic implementation:');copy=source[a:]
smoke=r'''
let prepared=prepareWireGuard(TunnelConfiguration(interface:Interface(privateKey:key),peers:[peer]))
guard let prepared=prepared, prepared.settings.mtu?.intValue == 1280,
      let value=try JSONSerialization.jsonObject(with:prepared.converted) as? [String:Any],
      let peers=value["peers"] as? [[String:Any]], peers.count == 1,
      peers[0]["endpoint"] as? String == "127.0.0.1:8443" else { fatalError("snapshot→copy→converter failed") }
guard prepareWireGuard(TunnelConfiguration(interface:fixed,peers:[peer])) == nil,
      prepareWireGuard(TunnelConfiguration(interface:Interface(privateKey:key),peers:[peer,peer])) == nil else { fatalError("unsupported source accepted") }
var namedPeer=peer; namedPeer.endpoint=Endpoint(host:.name("private.example.invalid"),stringRepresentation:"private.example.invalid:8443")
guard prepareWireGuard(TunnelConfiguration(interface:Interface(privateKey:key),peers:[namedPeer])) == nil else { fatalError("unresolved hostname accepted") }
print("Synthetic snapshot→copy→Swift/C/Go chain passed; stub models, no VPN or network settings applied")
'''
Path('build/precise-profile-chain-smoke.swift').write_text(s+'\nclass WireGuardAdapter {\n'+snapshot+'\n}\n'+copy+'\n'+prepare+'\n'+smoke,encoding='utf-8')
