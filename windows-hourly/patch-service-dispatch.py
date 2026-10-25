"""Exact-source dynamic current-device dispatch and immediate bounded SCM stop."""
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path(sys.argv[1]).resolve();p=root/'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/service.go'
before=hashlib.sha256(p.read_bytes()).hexdigest()
assert before=='f71fd0113faecad5d51a4eef8ceae2ecf77276bc3b5ae103c3541d45b0834a51','Unknown owned-TUN service; no dispatch patch applied'
s=p.read_text()
def replace(old,new):
 global s
 assert s.count(old)==1,(old[:100],s.count(old))
 s=s.replace(old,new,1)
replace('\tvar observation comparisonServiceObservation','''\tvar observation comparisonServiceObservation
 var primarySlot *r013gate.PrimaryDeviceSlot
 controls,controlError:=r013gate.NewServiceControl(pathContext,primaryGate,r,func(){observation.ready.Store(false);stopPaths()})
 if controlError!=nil{return services.DetermineErrorCode(controlError,services.ErrorDeviceSetConfig)}
 defer controls.Close(context.Background())''')
replace('''primaryUAPI, err = r013gate.NewObservedPrimaryUAPIServer(context.Background(), dev, func() (r013gate.Observation, error) { return observation.snapshot(primaryGate, dev), nil })''','''primarySlot,err=r013gate.NewPrimaryDeviceSlot(pathContext,primaryGate,dev)
 if err!=nil{return}
 primaryUAPI, err = r013gate.NewObservedPrimaryUAPIServer(context.Background(), primarySlot, func() (r013gate.Observation, error) {
  return primarySlot.Observe(func(current r013gate.PrimaryUAPIDevice)(r013gate.Observation,error){
   actual,ok:=current.(*device.Device)
   if !ok||actual==nil{return r013gate.Observation{},r013gate.ErrUnavailable}
   return observation.snapshot(primaryGate,actual),nil
  })
 })''')
replace('''	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:''','''\tfor {
        if controls.Stopped(){return}
		select {
        case <-controls.StopRequested():return
		case c,ok := <-controls.Requests():
            if !ok{return}
			switch c.Cmd {
			case svc.Interrogate:''')
p.write_text(s,newline='\n');subprocess.run(['gofmt','-w',str(p)],check=True)
record={'before':before,'after':hashlib.sha256(p.read_bytes()).hexdigest(),'scope':'actual service dynamic get/set/observe dispatch and immediate SCM stop; conditional backend and hourly coordinator still absent'}
(root.parent/'service-dispatch-evidence.json').write_text(json.dumps(record,indent=2));print(json.dumps(record))
