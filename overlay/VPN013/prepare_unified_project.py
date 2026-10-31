"""Register the unified client without changing bundle IDs or existing targets."""
from pathlib import Path
import hashlib

p = Path('WireGuard.xcodeproj/project.pbxproj')
s = p.read_text()
app = '6F7774E421718281006A79B3'
extensions = ['35A950238CE7EA1DBD6C5A57', 'B47708F94D16F2FA231D8BDE']
sources = {
    'CrossProtocolSelection.swift': [app, *extensions],
    'CrossProtocolCoordinator.swift': extensions,
    'CrossProtocolResolution.swift': extensions,
    'CrossProtocolPlan.swift': [app, *extensions],
    'CrossProtocolUI.swift': [app],
    'Invitation.swift': [app],
    'AutomaticMode.swift': [app, *extensions],
    'AutomaticModeUI.swift': [app],
    'ProxyProfile.swift': [app, *extensions],
    'ProxyRouting.swift': [app, *extensions],
    'ServiceRoutingCatalog.swift': [app, *extensions],
    'ServiceRoutingUI.swift': [app],
    'ProxyPreferences.swift': [app, *extensions],
    'ProxyPacketAdapter.swift': extensions,
    'ProxyAutomaticAdapter.swift': extensions,
    'ProxyProfilesManager.swift': [app],
    'UnifiedClientUI.swift': [app],
    'TrafficDisplay.swift': [app],
    'ProxyImportUI.swift': [app],
    'SubscriptionRequest.swift': [app],
    'ProxySubscriptionDownload.swift': [app],
    'ProxySubscriptionStore.swift': [app],
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
# Pinned inert catalog assets must be present in both app and extensions:
# their process-local Bundle.main is different. No remote data/path is loaded.
for name in ('ServiceCatalogUI.json', 'ServiceCatalogRules.json', 'ServiceCatalogGroups.json'):
    fid = hashlib.sha256(('service-resource-' + name).encode()).hexdigest()[:24].upper()
    assert fid not in s
    s = s.replace('/* End PBXFileReference section */', f'\t\t{fid} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = text.json; path = VPN013/{name}; sourceTree = SOURCE_ROOT; }};\n/* End PBXFileReference section */')
    for phase in ('6F5D0C18218352EF000F85AD', '6FB1BD5B21D2607A00A991BF', '6FB1BD8F21D4BFE600A991BF', '6FF4AC12211EC46F002C96EB'):
        bid = hashlib.sha256((fid + phase).encode()).hexdigest()[:24].upper()
        s = s.replace('/* End PBXBuildFile section */', f'\t\t{bid} /* {name} in Resources */ = {{isa = PBXBuildFile; fileRef = {fid}; }};\n/* End PBXBuildFile section */')
        needle = f'{phase} /* Resources */ = {{\n\t\t\tisa = PBXResourcesBuildPhase;\n\t\t\tbuildActionMask = 2147483647;\n\t\t\tfiles = ('
        assert s.count(needle) == 1, phase
        s = s.replace(needle, needle + f'\n\t\t\t\t{bid} /* {name} in Resources */,')
p.write_text(s)
print('Unified client sources registered; original targets and identities retained')
