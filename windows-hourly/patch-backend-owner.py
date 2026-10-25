"""Exact-source actual service-main-loop owner; producer remains separate."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();base=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
pins={'service.go':'9177b6c513960a5526f5d018fc52ac4f6d84feca8cd83e439a21d2c764ed5059','r013_observation.go':'90ab6abe1bf679c9c84930e1d67dd90be830fac2d99938ad571a523408781ed1'}
before={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in pins};assert before==pins,('Unknown actual service source',before)
p=base/'service.go';s=p.read_text()
s=s.replace('var primarySlot *r013gate.PrimaryDeviceSlot','var primarySlot *r013gate.PrimaryDeviceSlot\n var backendOwner *comparisonBackendOwner',1)
needle='primaryUAPI, err = r013gate.NewObservedPrimaryUAPIServer(context.Background(), primarySlot,'
assert s.count(needle)==1
s=s.replace(needle,'''backendOwner=newComparisonBackendOwner(pathContext,primaryGate,primarySlot,ownedTun,nativeTun,&config,&dev,&watcher,&observation)
 primaryAccess:=&comparisonDeviceAccess{slot:primarySlot,observation:&observation}
 primaryUAPI, err = r013gate.NewObservedPrimaryUAPIServer(context.Background(), primaryAccess,''',1)
needle='\t\tcase <-dev.Wait():\n\t\t\treturn'
assert s.count(needle)==1
s=s.replace(needle,'''        case selection:=<-backendOwner.requests:
          selectionError:=backendOwner.apply(selection)
          if selection!=nil&&selection.reply!=nil{select{case selection.reply<-selectionError:default:}}
          if selectionError!=nil{
            log.Print("R013 Auto: selected backend was not applied")
            if !observation.ready.Load(){err=errBackendUnknown;serviceError=services.ErrorDeviceSetConfig;return}
          }
        case <-dev.Wait():
            return''',1)
p.write_text(s,newline='\n')
p=base/'r013_observation.go';s=p.read_text().replace('ready   atomic.Bool','member atomic.Pointer[r013gate.ConfirmedMember]\n ready   atomic.Bool',1)
s=s.replace('out.Name = cfg.Name','out.Name = cfg.Name\n if state:=o.member.Load();state!=nil{copy:=*state;out.Member=&copy}',1)
p.write_text(s,newline='\n');subprocess.run(['gofmt','-w',str(base/'service.go'),str(p)],check=True)
after={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in pins}
(root.parent/'backend-owner-evidence.json').write_text(json.dumps({'before':before,'after':after,'scope':'actual main-loop conditional backend owner wired; hourly producer/manager synchronization not yet wired'},indent=2));print(json.dumps(after))
