"""Create isolated reference server and original client from pinned public sources."""
from pathlib import Path
import hashlib,json,shutil,subprocess,os
lab=Path(__file__).resolve().parent; m=json.loads((lab/'manifest.json').read_text())
base=Path(os.environ.get('VPN013_DIAGNOSTIC_ROOT','build/awg31-server-diagnostic')).resolve();assert not base.exists();base.mkdir(parents=True)
ref=base/'reference';subprocess.run(['git','clone','--quiet','https://github.com/amnezia-vpn/amneziawg-go.git',str(ref)],check=True)
subprocess.run(['git','-C',str(ref),'checkout','--quiet','--detach',m['referenceCommit']],check=True)
assert subprocess.check_output(['git','-C',str(ref),'rev-parse','HEAD'],text=True).strip()==m['referenceCommit']
upstream=b'github.com/amnezia-vpn/amneziawg-go/v3';servermod=b'vpn013.local/official-awg31';clientmod=b'vpn013.local/official-awg31-original'
for target,name in [(base/'server',servermod),(base/'client',clientmod)]:
 shutil.copytree(ref,target,ignore=shutil.ignore_patterns('.git'),copy_function=shutil.copyfile)
 for p in target.rglob('*'):
  if p.is_file() and (p.suffix=='.go' or p.name=='go.mod'):
   data=p.read_bytes();new=data.replace(upstream,name)
   if new!=data:p.write_bytes(new)
server=base/'server'/'device'
for name,digest in m['before'].items():assert hashlib.sha256((server/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==digest,name
for name,digest in m['after'].items():
 data=(lab/(name+'.txt')).read_bytes().replace(b'\r\n',b'\n');assert hashlib.sha256(data).hexdigest()==digest,name
 if name.endswith('_client_test.go'):continue
 (server/name).write_bytes(data)
case=base/'case';case.mkdir();(case/'go.mod').write_text('''module vpn013.local/server-client-diagnostic

go 1.26

require (
 vpn013.local/official-awg31 v0.0.0
 vpn013.local/official-awg31-original v0.0.0
 golang.org/x/crypto v0.42.0
)
replace vpn013.local/official-awg31 => ../server
replace vpn013.local/official-awg31-original => ../client
''')
(case/'network_test.go').write_bytes((lab/'vpn013_patched_server_original_client_test.go.txt').read_bytes())
(case/'helpers_test.go').write_text('''package dual
import("crypto/rand";"encoding/hex";"strconv";"strings";"testing";"golang.org/x/crypto/curve25519")
func keypair(t *testing.T)(string,string){var k [32]byte;if _,e:=rand.Read(k[:]);e!=nil{t.Fatal(e)};p,e:=curve25519.X25519(k[:],curve25519.Basepoint);if e!=nil{t.Fatal(e)};return hex.EncodeToString(k[:]),hex.EncodeToString(p)}
func port(t *testing.T,v string)int{for _,s:=range strings.Split(v,"\\n"){if x,ok:=strings.CutPrefix(s,"listen_port=");ok{n,e:=strconv.Atoi(x);if e==nil&&n>0{return n}}};t.Fatal("missing local port");return 0}
''')
print('Pinned upstream server/client isolated; test and patch hashes verified. No live VPN used.')
