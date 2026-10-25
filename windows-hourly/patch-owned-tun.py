"""Exact-source owned native TUN relay; no switch/coordinator is installed."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve()
paths={
 'service':'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/service.go',
 'native':'vendor/github.com/amnezia-vpn/amneziawg-go/v3/tun/tun_windows.go',
}
pins={'service':'c4fb17ff4dd7ba77be3cbc02aae5d5378eb7566e4dcfb332f10e9ecebc35e471','native':'17bf249a5438f1850ec2aced69b5d1af745129d5194f161373420df19df6e199'}
before={key:hashlib.sha256((root/path).read_bytes()).hexdigest() for key,path in paths.items()}
assert before==pins,('Unknown observed-runtime/native source; no owned-TUN patch applied',before)
texts={key:(root/path).read_text() for key,path in paths.items()}
def replace(s,old,new):
 assert s.count(old)==1,(old[:100],s.count(old))
 return s.replace(old,new,1)
s=texts['service']
s=replace(s,'"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"','"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"\n "github.com/amnezia-vpn/amneziawg-windows-client/r013tun"')
s=replace(s,'\tvar nativeTun *tun.NativeTun','\tvar nativeTun *tun.NativeTun\n var ownedTun *r013tun.Relay')
s=replace(s,'\t\tif dev != nil {\n\t\t\tdev.Close()\n\t\t}', '''\t\tif dev != nil { dev.Close() }
        if ownedTun!=nil { ownedTun.Close() } else if nativeTun!=nil { nativeTun.Close() }''')
s=replace(s,'\t\tnativeTun = wintun.(*tun.NativeTun)','''\t\tnativeTun = wintun.(*tun.NativeTun)
        ownedTun,err=r013tun.New(nativeTun)
        if err!=nil{return err}''')
s=replace(s,'dev = device.NewDevice(wintun, bind, &device.Logger{log.Printf, log.Printf})','''lease,leaseError:=ownedTun.Open()
        if leaseError!=nil{return leaseError}
        dev = device.NewDevice(lease, bind, &device.Logger{log.Printf, log.Printf})''')
texts['service']=s
s=texts['native']
s=replace(s,'\tforcedMTU int','\tforcedMTU atomic.Int32\n eventMutex sync.RWMutex')
s=replace(s,'\t\tforcedMTU: forcedMTU,','')
s=replace(s,'\ttun.session, err = wt.StartSession','\ttun.forcedMTU.Store(int32(forcedMTU))\n\ttun.session, err = wt.StartSession')
s=replace(s,'\t\tclose(tun.events)\n\t})','\t\ttun.eventMutex.Lock()\n close(tun.events)\n tun.eventMutex.Unlock()\n\t})')
s=replace(s,'\treturn tun.forcedMTU, nil','\treturn int(tun.forcedMTU.Load()), nil')
s=replace(s,'''func (tun *NativeTun) ForceMTU(mtu int) {
	if tun.close.Load() {
		return
	}
	update := tun.forcedMTU != mtu
	tun.forcedMTU = mtu
	if update {
		tun.events <- EventMTUUpdate
	}
}''','''func (tun *NativeTun) ForceMTU(mtu int) {
 tun.eventMutex.RLock()
 defer tun.eventMutex.RUnlock()
 if tun.close.Load(){return}
 update:=tun.forcedMTU.Swap(int32(mtu))!=int32(mtu)
 if update {
  // NativeTun emits only MTU notifications. A queued event already makes
  // the newest atomic MTU visible; never block a service mutation on backlog.
  select {case tun.events<-EventMTUUpdate:default:}
 }
}''')
texts['native']=s
for key,path in paths.items():(root/path).write_text(texts[key],newline='\n')
subprocess.run(['gofmt','-w',*[str(root/path) for path in paths.values()]],check=True)
record={'before':before,'after':{key:hashlib.sha256((root/path).read_bytes()).hexdigest() for key,path in paths.items()},'scope':'actual service owns native TUN; backend lease close does not destroy it; no scheduler or conditional switch'}
(root.parent/'owned-tun-evidence.json').write_text(json.dumps(record,indent=2))
print(json.dumps(record))
