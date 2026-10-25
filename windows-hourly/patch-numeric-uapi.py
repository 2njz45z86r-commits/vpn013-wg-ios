"""Guarantee numeric prepared endpoints bypass the legacy unbounded resolver."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();p=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/conf/dnsresolver_windows.go'
before=hashlib.sha256(p.read_bytes()).hexdigest()
expected='f94362614a4fc719353ff7733272e49d3437f1cac355c91207a0ffbec3b772ef'
assert before==expected,'Unknown native resolver; no numeric shortcut applied'
s=p.read_text();marker='func resolveHostname(name string) (resolvedIPString string, err error) {';assert s.count(marker)==1
s=s.replace(marker,marker+'''\n // Prepared numeric endpoints must not enter GetAddrInfoW or its boot-time
 // retry sleeps. Hostname behavior remains unchanged for ordinary profiles.
 if ip:=net.ParseIP(name);ip!=nil{return ip.String(),nil}''',1)
p.write_text(s,newline='\n');subprocess.run(['gofmt','-w',str(p)],check=True)
record={'before':before,'after':hashlib.sha256(p.read_bytes()).hexdigest(),'scope':'numeric addresses return before native resolver/boot retry; ordinary domain handling unchanged'}
(root.parent/'numeric-uapi-evidence.json').write_text(json.dumps(record,indent=2));print(json.dumps(record))
