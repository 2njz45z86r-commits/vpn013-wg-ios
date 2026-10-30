"""Verify 42 regression cases plus the separately executed new settings case.

The report explicitly describes two executions, not a single 43-case xcresult.
The release still compiles its own app/extension and scans its linked Go core.
"""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, re, subprocess, tempfile, time, zipfile

REPO = '2njz45z86r-commits/vpn013-wg-ios'
SOURCE = '3e9d189cc9a66b7dcceeb5f9115f93b6b6f2b48a'
CASE = 'testSettingsReachableInEveryProxySectionAndPreserveImportText'
RUNS = [
    dict(run=41125942311, job=124304366783, source='6af1610861383648e6e8cf6a581416026ba7b9e8', artifact=13013775243,
         digest='9135c71b374ddbeb9843489311a9aab47fa3465dbccdc98170f16328db4bc73d', count=42, prefix='review/'),
    dict(run=41131895375, job=124324609379, source=SOURCE, artifact=13016811248,
         digest='f18d514b39f2963bcc759d852433b0289e5a5926b511a6b0cc913ef809a9283d', count=1, prefix=''),
]
# Filled from the reviewed immutable source, never from the current worktree.
EXPECTED = {'overlay': 'fd5121b3ab451c4ba338e5717fac145286df07a2', 'branding': 'ca6550800eda39c3cb91f10e8b269eefd2ee9f89', 'experiments': '7dcb7b683890f1c5a79d86c9856245c26f40a57c', 'tests': '027c2b6f0ae36a0552a2ed04b5581b5370a17deb', 'scripts': 'a0ab709bb02c5c5205d6fc158d9202eaa2da5a95', 'build-on-mac.sh': 'f51c6dd02992f3d0f26673282edb71ca62af1281', 'inspect-on-mac.sh': '033bd8c24f5ba675781e55ea2c35105b8ad89ffb', '.github/workflows/native-unified-check.yml': '5c24a59a528e542f649e1c347ce913037a37b110'}

def require(value, message):
    if not value:
        raise RuntimeError(message)

def call(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=120)

def api(path):
    separator = '&' if '?' in path else '?'
    return json.loads(call('gh', 'api', 'repos/'+REPO+'/'+path+separator+'fresh='+str(time.time_ns())))

def successful_summary(summary, count):
    return summary.get('result') == 'Passed' and tuple(summary.get(k) for k in
        ('passedTests','failedTests','skippedTests','totalTestCount')) == (count,0,0,count) and summary.get('testFailures') == []

def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == REPO, 'Project CI required')
    for path, digest in EXPECTED.items():
        require(call('git','rev-parse','HEAD:'+path).strip() == digest, 'Reviewed runtime/test source changed')
    require(len(EXPECTED) >= 8, 'Missing immutable source contract')
    selectors = set(re.findall(r'-only-testing:AutoTunnelUITests/AutoTunnelUITests/(\w+)', Path('inspect-on-mac.sh').read_text()))
    require(len(selectors) == 43 and CASE in selectors, 'Exactly 43 required selectors must remain')
    review=Path('build/review'); review.mkdir(parents=True,exist_ok=True)
    executions=[]; images=0
    for record in RUNS:
        run=api('actions/runs/'+str(record['run']))
        require(run.get('head_sha') == record['source'] and run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Native run not successful at pinned source')
        job=api('actions/jobs/'+str(record['job']))
        require(job.get('run_id') == record['run'] and job.get('conclusion') == 'success', 'Pinned native job not successful')
        artifact=api('actions/artifacts/'+str(record['artifact']))
        require(artifact.get('workflow_run',{}).get('id') == record['run'] and artifact.get('workflow_run',{}).get('head_sha') == record['source'] and not artifact.get('expired'), 'Wrong/expired native evidence')
        require(artifact.get('digest') == 'sha256:'+record['digest'], 'Different native artifact')
        # gh protects interactive terminals from escape codes in compiler logs.
        # Capture to memory only, then discard control bytes before matching.
        execution_log=call('gh','api','--allow-escape-sequences','repos/'+REPO+'/actions/jobs/'+str(record['job'])+'/logs')
        execution_log=''.join(c for c in execution_log if ord(c)>=32 or c in '\n\t')
        executed=set(re.findall(r"Test Case '-\[AutoTunnelUITests\.AutoTunnelUITests (\w+)\]' passed",execution_log))
        expected={CASE} if record['count'] == 1 else selectors-{CASE}
        require(executed == expected, 'Every required selector must have actually passed')
        require(not re.search(r"Test Case '-\[AutoTunnelUITests\.AutoTunnelUITests \w+\]' failed",execution_log), 'Failed native case present')
        with tempfile.TemporaryDirectory(prefix='vpn013-173-evidence-') as temporary:
            archive=Path(temporary)/'evidence.zip'
            with archive.open('xb') as output:
                subprocess.run(['gh','api','repos/'+REPO+'/actions/artifacts/'+str(record['artifact'])+'/zip'],stdout=output,check=True,timeout=120)
            require(archive.stat().st_size <= 40_000_000,'Oversized evidence archive')
            raw=archive.read_bytes(); require(hashlib.sha256(raw).hexdigest() == record['digest'],'Artifact hash mismatch')
            with zipfile.ZipFile(io.BytesIO(raw)) as evidence:
                entries=evidence.infolist(); require(len(entries) <= 1000 and sum(x.file_size for x in entries) <= 100_000_000,'Excessive expanded evidence')
                require(evidence.testzip() is None,'Corrupt native evidence')
                summary=json.loads(evidence.read(record['prefix']+'test-summary.json'))
                require(successful_summary(summary,record['count']),'Incomplete native suite')
                seen=set(); count=0
                for entry in entries:
                    relative=PurePosixPath(entry.filename)
                    require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in entry.filename and (entry.external_attr>>16)&0o170000 != 0o120000,'Unsafe evidence path')
                    require(entry.filename.casefold() not in seen,'Duplicate evidence path'); seen.add(entry.filename.casefold())
                    if entry.is_dir() or relative.suffix != '.png': continue
                    require(entry.file_size <= 15_000_000,'Oversized screenshot')
                    data=evidence.read(entry); require(data.startswith(b'\x89PNG\r\n\x1a\n'),'Invalid native screenshot')
                    target=review/'flow'/str(record['run'])/relative.name
                    target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data); count+=1
                require(count == (64 if record['count'] == 42 else 3),'Missing actual native appearances')
                images+=count
        executions.append(dict(run=record['run'],source=record['source'],artifact=record['artifact'],sha256=record['digest'],
            passedTests=record['count'],failedTests=0,skippedTests=0,selectors=sorted(executed),originalSummary=summary))
    aggregate=dict(reportKind='verified-multiple-native-executions',executionCount=2,result='Passed',passedTests=43,
        failedTests=0,skippedTests=0,totalTestCount=43,testFailures=[],executions=executions)
    (review/'test-summary.json').write_text(json.dumps(aggregate,indent=2))
    (review/'native-test-provenance.json').write_text(json.dumps(dict(exactSourceObjects=EXPECTED,actualCases=43,
        executionCount=2,actualXCUITestImages=images,physicalIPhoneTested=False,iPadTested=False),indent=2))
    (review/'iphone-release-scope.json').write_text(json.dumps(dict(platform='iPhone',nativeScenarios=43,executionCount=2,
        actualXCUITestAttachments=True,sourceRuns=[r['run'] for r in RUNS],physicalIPhoneTested=False,iPadTested=False,
        requiresOwnerSigning=True),indent=2))
    print('Verified 42 existing cases plus one separately executed settings case; 67 actual screenshots. Current app build and linked-core scan remain required.')

if __name__ == '__main__': main()
