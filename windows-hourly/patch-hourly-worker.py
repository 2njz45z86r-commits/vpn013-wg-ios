"""Exact-source service-owned hourly/health loop and read-only capability metadata."""
from pathlib import Path
import hashlib, json, subprocess, sys

root = Path(sys.argv[1]).resolve()
base = root / 'vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel'
pins = {'service.go': '1fc9ce5dda6f1630cb8ae9f51ed6f186dd85e8410385a096e25d4159a53092d5',
        'r013_observation.go': 'fc867d71f585e3b49f406ee2d164ca8276e37c98d6805f1f788cc7800ce2f924'}
before = {name: hashlib.sha256((base/name).read_bytes()).hexdigest() for name in pins}
assert before == pins, ('Unknown worker integration source', before)
p = base/'service.go'
s = p.read_text()
s = s.replace('var backendOwner *comparisonBackendOwner',
              'var backendOwner *comparisonBackendOwner\n var hourlyWorker *comparisonWorker', 1)
needle = '\t\tif primaryUAPI != nil {'
assert s.count(needle) == 1
s = s.replace(needle, '\t\tif hourlyWorker != nil {hourlyWorker.Close()}\n'+needle, 1)
needle = '\tlog.Println("Startup complete")'
assert s.count(needle) == 1
s = s.replace(needle, needle+'''
 hourlyWorker, err = newComparisonWorker(pathContext,backendOwner)
 if err!=nil {log.Println("R013 Auto: background worker unavailable");err=nil}
''', 1)
p.write_text(s, newline='\n')
p = base/'r013_observation.go'
s = p.read_text()
s = s.replace('type comparisonServiceObservation struct {', '''type comparisonServiceObservation struct {
 healthOwned atomic.Bool
 comparing atomic.Bool
 lastCompared atomic.Int64
 lastComparison atomic.Int64
 workerStarted atomic.Int64
''', 1)
needle = '\tout.Name = cfg.Name'
assert s.count(needle) == 1
s = s.replace(needle, needle+'''
 out.HealthOwned=o.healthOwned.Load()
 out.Comparing=o.comparing.Load()
 out.ComparedCount=o.lastCompared.Load()
 out.LastComparisonUnixNano=o.lastComparison.Load()
 out.WorkerStartedUnixNano=o.workerStarted.Load()
''', 1)
p.write_text(s, newline='\n')
subprocess.run(['gofmt','-w',str(base/'service.go'),str(p)],check=True)
after = {name: hashlib.sha256((base/name).read_bytes()).hexdigest() for name in pins}
(root.parent/'hourly-worker-evidence.json').write_text(json.dumps({
    'before':before,'after':after,
    'scope':'actual service-owned worker wired; manager supervision and native compiled Auto acceptance still required'
},indent=2))
print(json.dumps(after))
