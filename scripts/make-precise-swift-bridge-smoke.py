"""Exercise the exact Swift conversion wrapper through a macOS Go C archive."""
from pathlib import Path

source = Path('overlay/VPN013/ProxyPacketAdapter.swift').read_text(encoding='utf-8')
start = source.index('    static func convertedWireGuardSettings(')
end = source.index('\n    }', start) + len('\n    }')
method = source[start:end].replace('    static func ', 'func ', 1)
smoke = r'''
import Foundation
import Darwin
@_silgen_name("R013ProxyConvertWireGuard")
func R013ProxyConvertWireGuard(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
''' + method + r'''
let key = String(repeating: "12", count: 32)
let uapi = "private_key=\(key)\nr013_legacy15=false\npublic_key=\(key)\nendpoint=127.0.0.1:8443\nallowed_ip=0.0.0.0/0\n"
guard let data = convertedWireGuardSettings(uapi: uapi, addresses: ["10.0.0.2/32"], effectiveMTU: 1280),
      let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      obj["secretKey"] as? String == key,
      let peers = obj["peers"] as? [[String:Any]], peers.count == 1,
      peers[0]["endpoint"] as? String == "127.0.0.1:8443" else { fatalError("valid conversion failed") }
guard convertedWireGuardSettings(uapi: "listen_port=12345\n" + uapi, addresses: ["10.0.0.2/32"], effectiveMTU: 1280) == nil,
      convertedWireGuardSettings(uapi: "bad-secret-marker", addresses: ["10.0.0.2/32"], effectiveMTU: 1280) == nil else { fatalError("invalid conversion accepted") }
print("Swift/C/Go bridge: valid profile converted and invalid profiles rejected; synthetic macOS only")
'''
Path('build/precise-swift-bridge-smoke.swift').write_text(smoke, encoding='utf-8')
print('Staged exact Swift method for synthetic host bridge smoke test')
