"""Register hourly transport/coordinator in both existing extension targets."""
from pathlib import Path
import hashlib
p=Path('WireGuard.xcodeproj/project.pbxproj');s=p.read_text()
for name in ['PhysicalUDPDriver.swift','ProbeCoordinator.swift','HourlyProbeSupport.swift']:
    fid=hashlib.sha256(('hourly-'+name).encode()).hexdigest()[:24].upper()
    assert fid not in s, 'Hourly source already registered'
    s=s.replace('/* End PBXFileReference section */',f'\t\t{fid} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = VPN013/{name}; sourceTree = SOURCE_ROOT; }};\n/* End PBXFileReference section */')
    for original in ['35A950238CE7EA1DBD6C5A57','B47708F94D16F2FA231D8BDE']:
        bid=hashlib.sha256((fid+original).encode()).hexdigest()[:24].upper()
        s=s.replace('/* End PBXBuildFile section */',f'\t\t{bid} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {fid}; }};\n/* End PBXBuildFile section */')
        anchor=f'\t\t\t\t{original} /* AutoTunnelController.swift in Sources */,';assert s.count(anchor)==1
        s=s.replace(anchor,anchor+f'\n\t\t\t\t{bid} /* {name} in Sources */,',1)
p.write_text(s)
print('Hourly Swift sources registered in existing extension targets')
