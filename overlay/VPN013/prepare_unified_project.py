"""Register the unified client without changing bundle IDs or existing targets."""
from pathlib import Path
import hashlib

p = Path('WireGuard.xcodeproj/project.pbxproj')
s = p.read_text()
app = '6F7774E421718281006A79B3'
extensions = ['35A950238CE7EA1DBD6C5A57', 'B47708F94D16F2FA231D8BDE']
sources = {
    'ProxyProfile.swift': [app, *extensions],
    'ProxyRouting.swift': [app, *extensions],
    'ProxyPreferences.swift': [app, *extensions],
    'ProxyPacketAdapter.swift': extensions,
    'ProxyProfilesManager.swift': [app],
    'UnifiedClientUI.swift': [app],
    'ProxyImportUI.swift': [app],
}
for name, anchors in sources.items():
    fid = hashlib.sha256(('unified-' + name).encode()).hexdigest()[:24].upper()
    assert fid not in s
    s = s.replace('/* End PBXFileReference section */', f'\t\t{fid} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = VPN013/{name}; sourceTree = SOURCE_ROOT; }};\n/* End PBXFileReference section */')
    for anchor in anchors:
        bid = hashlib.sha256((fid + anchor).encode()).hexdigest()[:24].upper()
        s = s.replace('/* End PBXBuildFile section */', f'\t\t{bid} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {fid}; }};\n/* End PBXBuildFile section */')
        original = 'TunnelsListTableViewController.swift' if anchor == app else 'AutoTunnelController.swift'
        needle = f'\t\t\t\t{anchor} /* {original} in Sources */,'
        assert s.count(needle) == 1, needle
        s = s.replace(needle, needle + f'\n\t\t\t\t{bid} /* {name} in Sources */,', 1)
p.write_text(s)
print('Unified client sources registered; original targets and identities retained')
