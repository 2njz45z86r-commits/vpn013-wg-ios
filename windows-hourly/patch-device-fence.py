"""Exact-source optional primary lifecycle hook; retain existing vendored client patches."""
from pathlib import Path
import hashlib, json, shutil, subprocess, sys

root=Path(sys.argv[1]).resolve()
device=root/'vendor/github.com/amnezia-vpn/amneziawg-go/v3/device'
pins={'device.go':'6d013e27d6b33c1ecaae1a1fbc4999e15a3a11252e302c580ea0f9027fa3ec21',
      'uapi.go':'7a88ac0cc50ea932336042d963183760e38a48fd8e055e0c0d00a4324cf1ef32'}
before={f:hashlib.sha256((device/f).read_bytes()).hexdigest() for f in pins}
assert before==pins, ('Unexpected upstream device source; no patch applied',before)
for file, names in [('device.go',['Up','Down','Close']),('uapi.go',['IpcSetOperation'])]:
    text=(device/file).read_text()
    if file=='device.go':
        assert text.count('type Device struct {\n')==1
        text=text.replace('type Device struct {\n','type Device struct {\n\tr013PrimaryFence atomic.Pointer[r013PrimaryFence]\n',1)
    for name in names:
        old='func (device *Device) '+name+'('
        assert text.count(old)==1
        text=text.replace(old,'func (device *Device) r013Unfenced'+name+'(',1)
    (device/file).write_text(text,newline='\n')
(device/'r013_primary_fence.go').write_text('''// SPDX-License-Identifier: MIT
package device

import "io"

type r013PrimaryFence struct { run func(func() error) error }

// SetPrimaryMutationFence installs the process-independent lifecycle fence ONCE
// before primary activation. Candidate devices leave this nil; their owning
// comparison holds the outer platform lease. Read-only IpcGet is never fenced.
// Atomic installation covers an internal asynchronous Close racing startup.
func (device *Device) SetPrimaryMutationFence(run func(func() error) error) bool {
 if run == nil { return false }
 return device.r013PrimaryFence.CompareAndSwap(nil,&r013PrimaryFence{run:run})
}
func (device *Device) r013WithPrimaryFence(work func()error) error {
 if fence:=device.r013PrimaryFence.Load();fence!=nil{return fence.run(work)}
 return work()
}
func (device *Device) Up() error {return device.r013WithPrimaryFence(device.r013UnfencedUp)}
func (device *Device) Down() error {return device.r013WithPrimaryFence(device.r013UnfencedDown)}
func (device *Device) IpcSetOperation(reader io.Reader) error {
 return device.r013WithPrimaryFence(func()error{return device.r013UnfencedIpcSetOperation(reader)})
}
func (device *Device) Close() {
 if err:=device.r013WithPrimaryFence(func()error{device.r013UnfencedClose();return nil});err!=nil{
  device.log.Errorf("Primary lifecycle fence refused close: %v",err)
 }
}
''',newline='\n')
# Include only the missing package from the existing exact pinned module. Do
# not regenerate vendor (which would discard client-specific tunnel patches).
module=json.loads(subprocess.check_output(['go','mod','download','-json','golang.org/x/net@v0.44.0'],cwd=root,text=True))
assert module['Version']=='v0.44.0'
target=root/'vendor/golang.org/x/net/dns/dnsmessage'
assert not target.exists()
target.mkdir(parents=True)
for file in ('message.go',): shutil.copy2(Path(module['Dir'])/'dns/dnsmessage'/file,target/file)
modules=root/'vendor/modules.txt'
text=modules.read_text()
marker='# golang.org/x/net v0.44.0\n## explicit; go 1.24.0\n'
assert text.count(marker)==1
modules.write_text(text.replace(marker,marker+'golang.org/x/net/dns/dnsmessage\n'),newline='\n')
subprocess.run(['gofmt','-w',str(device/'device.go'),str(device/'uapi.go'),str(device/'r013_primary_fence.go')],check=True)
record={'before':before,'after':{f:hashlib.sha256((device/f).read_bytes()).hexdigest() for f in (*pins,'r013_primary_fence.go')},'pinned_dns_package_module_sum':module['Sum'],'scope':'optional hooks installed only by fixture, production service wiring still required'}
(root.parent/'device-fence-evidence.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
