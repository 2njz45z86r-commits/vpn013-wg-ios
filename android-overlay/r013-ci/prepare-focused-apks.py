"""Resolve actual Gradle split output names for hosted x86_64 diagnostics only."""
from pathlib import Path
import hashlib, json, os, re, shutil, zipfile

assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('R013_FOCUS_RUNTIME') == 'true'
temporary = Path(os.environ['RUNNER_TEMP'])
proof = {'diagnosticOnly': True, 'expectedABI': 'x86_64', 'fullNativeAcceptance': False, 'published': False, 'apks': {}}
for name, folder, application in (
    ('app', Path('ui/build/outputs/apk/debug'), 'com.vpn013.awg.debug'),
    ('test', Path('ui/build/outputs/apk/androidTest/debug'), 'com.vpn013.awg.debug.test'),
):
    metadata = json.loads((folder / 'output-metadata.json').read_text())
    assert metadata['applicationId'] == application
    elements = metadata['elements']; assert 1 <= len(elements) <= 10
    eligible = []
    for item in elements:
        filters = item.get('filters', [])
        if all(f.get('filterType') == 'ABI' and f.get('value') == 'x86_64' for f in filters):
            eligible.append(item)
    specific = [item for item in eligible if item.get('filters')]
    choices = specific or eligible; assert len(choices) == 1
    filename = choices[0]['outputFile']; assert re.fullmatch(r'[A-Za-z0-9_.-]+\.apk', filename)
    source = (folder / filename).resolve(); assert source.parent == folder.resolve()
    assert 0 < source.stat().st_size <= 268_435_456
    with zipfile.ZipFile(source) as archive:
        assert archive.testzip() is None
        abis = {n.split('/')[1] for n in archive.namelist() if n.startswith('lib/') and n.endswith('.so')}
    assert abis <= {'x86_64'} and (name != 'app' or abis == {'x86_64'})
    shutil.copyfile(source, temporary / ('r013-focused-' + name + '.apk'))
    proof['apks'][name] = {'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'abis': sorted(abis), 'metadataVariant': metadata['variantName']}
Path('output/review/focused-apks.json').write_text(json.dumps(proof))
print('Verified actual Gradle x86_64 split APKs for isolated native diagnostics')
