"""Keep the exact service-SID restriction with an owned canonical SID copy."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve()
p=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall/helpers.go'
before=hashlib.sha256(p.read_bytes()).hexdigest()
assert before=='bf62f6900727571e11e5116c57bcd555c579e0a7733c187a2eb105c07966e224','Unknown upstream WFP helper; no change'
s=p.read_text()
def replace(old,new):
 global s
 assert s.count(old)==1,(old[:100],s.count(old))
 s=s.replace(old,new,1)
replace('"runtime"','"runtime"\n "strings"')
replace('''		if !g.Sid.IsValid() || g.Sid.IdentifierAuthority() != windows.SECURITY_NT_AUTHORITY || g.Sid.SubAuthorityCount() < 6 || g.Sid.SubAuthority(0) != 80 {
			continue
		}
		sid = g.Sid
		break''','''        if g.Sid==nil || !g.Sid.IsValid(){continue}
        // ConvertSidToStringSid returns canonical S-Revision-Authority-Sub...
        // Preserve the same NT authority5, service80 and >=6 sub-authorities
        // plus the existing exact enabled/default/owner attributes. Avoid
        // native interior pointers returned into a borrowed Go token buffer.
        text:=g.Sid.String()
        if !strings.HasPrefix(text,"S-1-5-80-") || strings.Count(text,"-")<8{continue}
        owned,copyErr:=g.Sid.Copy()
        if copyErr!=nil{return nil,wrapErr(copyErr)}
        sid=owned
        break''')
replace('\tif sid == nil {','\truntime.KeepAlive(gs)\n\tif sid == nil {')
p.write_text(s,newline='\n');subprocess.run(['gofmt','-w',str(p)],check=True)
record={'before':before,'after':hashlib.sha256(p.read_bytes()).hexdigest(),'scope':'same service SID predicate and exact group attributes; owned SID copy; no privilege or ACL relaxation'}
(root.parent/'firewall-sid-evidence.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
