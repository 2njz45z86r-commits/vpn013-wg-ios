"""Give the installer its own stable identity; retain profiles and shared driver."""
from pathlib import Path
import re,uuid
root=Path(__file__).resolve().parents[1]
p=root/'installer/wireguard.wxs';source=p.read_text(encoding='utf-8')
for original in re.findall(r'(?:UpgradeCode = |Guid=)"([0-9a-f-]{36})"',source):
    if original in ['876b57e4-4490-4442-a983-721ee141b00d','945200da-4a7e-4b02-a06f-00fcd09e48da','220a4807-8e24-4594-9880-92034e062a57','940bb00d-6a17-409c-93c6-0347e2dfed80','c3508d23-3362-47ce-9220-321bdb1a1acc','540cf446-fcc3-4452-b9fb-eb4c02780251','ac88e408-9b78-4eb3-9d2a-99305f2e5a51']:
        source=source.replace(original,str(uuid.uuid5(uuid.NAMESPACE_DNS,'vpn013.com/windows/'+original)))
source=source.replace('Name="AmneziaWG"','Name="VPN013 WG"').replace('Manufacturer="Amnezia"','Manufacturer="R013"')
source=source.replace('amneziawg.exe','VPN013WG.exe').replace('https://amnezia.org/','https://vpn013.com/')
source=source.replace('<Property Id="DISABLEROLLBACK" Value="yes" />','')
if '<Property Id="DO_NOT_LAUNCH"' not in source:
    source=source.replace('<Property Id="DISABLEADVTSHORTCUTS" Value="yes" />','<Property Id="DISABLEADVTSHORTCUTS" Value="yes" />\n\t\t<Property Id="DO_NOT_LAUNCH" Secure="yes" />')
source=source.replace('ProductState=5 AND NOT REMOVE AND NOT DO_NOT_LAUNCH','ProductState=5 AND NOT REMOVE AND NOT REINSTALL AND NOT DO_NOT_LAUNCH')
source=re.sub(r'<Environment Id="PATH"[^>]*/>','',source)
for action in ('RemoveConfigFolder','RemoveAdapters'):
    source=re.sub(r'<Custom Action="'+action+r'"[^>]*/>','<!-- Preserve existing configurations and the shared Wintun driver. -->',source)
p.write_text(source,encoding='utf-8',newline='\n')
p=root/'installer/customactions.c';source=p.read_text(encoding='utf-8')
source=source.replace('AmneziaWGManager','VPN013WGManager').replace('AmneziaWGTunnel$','VPN013WGTunnel$').replace('amneziawg.exe','VPN013WG.exe')
p.write_text(source,encoding='utf-8',newline='\n')
p=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/deterministicguid.go';source=p.read_text(encoding='utf-8')
source=source.replace('Deterministic WireGuard Windows GUID v1 jason@zx2c4.com','Deterministic VPN013 WG Windows GUID v1').replace('Fixed WireGuard Windows GUID v1 jason@zx2c4.com','Fixed VPN013 WG Windows GUID v1')
p.write_text(source,encoding='utf-8',newline='\n')
print('Installer identity isolated; profile deletion and driver removal disabled')
p=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/service.go';source=p.read_text(encoding='utf-8')
source=source.replace('tun.CreateTUNWithRequestedGUID(config.Name,','tun.CreateTUNWithRequestedGUID("VPN013-"+config.Name,')
source=re.sub(r'(runScriptCommand\(config.Interface.\w+, )config.Name\)',r'\1"VPN013-"+config.Name)',source)
p.write_text(source,encoding='utf-8',newline='\n')

