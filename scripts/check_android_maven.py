"""Inspect the exact Gradle-resolved runtime graph against the live OSV database."""
import datetime,hashlib,json,os,pathlib,re,subprocess,urllib.request
root=pathlib.Path(__file__).resolve().parents[1];directory=root/'android/output/review';directory.mkdir(parents=True,exist_ok=True)
raw=(root/'android/runtime-dependencies.txt').read_bytes();text=raw.decode()
assert 'FAILED' not in text and 'BUILD SUCCESSFUL' in text
packages=set()
for line in text.splitlines():
 m=re.search(r"([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^\s]+)(?: -> ([^\s]+))?",line)
 if not m:continue
 version=m[4] or m[3]
 assert re.fullmatch(r"[0-9][A-Za-z0-9_.-]*",version), 'Unresolved dependency version'
 packages.add((m[1]+':'+m[2],version))
assert 15<=len(packages)<=500
queries=[{'package':{'ecosystem':'Maven','name':name},'version':version} for name,version in sorted(packages)]
results=[]
for offset in range(0,len(queries),100):
 req=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries[offset:offset+100]}).encode(),headers={'Content-Type':'application/json'},method='POST')
 with urllib.request.urlopen(req,timeout=40) as response:result=json.load(response)['results']
 assert len(result)==len(queries[offset:offset+100]);results.extend(result)
hits=sum(bool(r.get('vulns')) for r in results)
record={'source':os.environ['GITHUB_SHA'],'androidOverlay':subprocess.check_output(['git','rev-parse','HEAD:android-overlay'],cwd=root,text=True).strip(),'atUTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'resolvedGraphSHA256':hashlib.sha256(raw).hexdigest(),'queries':queries,'results':results}
subprocess.run(['go','run','scripts/audit-envelope.go','encrypt','scripts/audit-recipient.pub',str(directory/'android-maven-findings.enc.json')],cwd=root,input=json.dumps(record).encode(),capture_output=True,check=True,timeout=60)
metadata={key:record[key] for key in ['source','androidOverlay','atUTC','resolvedGraphSHA256']};metadata.update(resolvedRuntimePackages=len(queries),affectedPackages=hits,successful=hits==0)
(directory/'android-maven-review.json').write_text(json.dumps(metadata,indent=2))
print(json.dumps({'resolvedRuntimePackages':len(queries),'affectedPackages':hits}))
assert hits==0,'Runtime dependency review requires private assessment'
