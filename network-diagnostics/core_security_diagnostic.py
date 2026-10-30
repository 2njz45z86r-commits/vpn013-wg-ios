"""Official public upstream binaries only; retain statuses, never full traces."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

PINNED = {
    'v26.9.30': '96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7',
    'v26.10.29': 'e783b9d2b46ed1ab3617c59b04dfbce38c999322d018c6e060f18d88bf6158aa',
}
directory = Path('core-security-results')
directory.mkdir()
for tag, expected in PINNED.items():
    result = {'upstream_tag': tag, 'expected_binary_sha256': expected, 'analysis_complete': False,
              'scope': 'govulncheck binary symbol scan; not release approval'}
    try:
        with urllib.request.urlopen('https://github.com/XTLS/Xray-core/releases/download/' + tag + '/Xray-linux-64.zip', timeout=45) as response:
            payload = response.read(30 * 1024 * 1024 + 1)
        assert len(payload) <= 30 * 1024 * 1024
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            items = [i for i in archive.infolist() if i.filename == 'xray']
            assert len(items) == 1 and items[0].file_size < 100 * 1024 * 1024
            content = archive.read(items[0])
        actual = hashlib.sha256(content).hexdigest()
        assert actual == expected, 'Upstream binary differs from pinned reviewed artifact'
        binary = directory / ('xray-' + tag)
        binary.write_bytes(content)
        scanner = Path(os.environ['HOME']) / 'go/bin/govulncheck'
        scan = subprocess.run([str(scanner), '-json', '-mode=binary', str(binary)],
            capture_output=True, text=True, timeout=240)
        decoder = json.JSONDecoder()
        text = scan.stdout
        events = []
        while text.strip():
            event, offset = decoder.raw_decode(text.lstrip())
            events.append(event)
            text = text.lstrip()[offset:]
        findings = [e['finding'] for e in events if 'finding' in e]
        symbols = [f for f in findings if any(frame.get('function') for frame in f.get('trace', []))]
        packages = [f for f in findings if any(frame.get('package') for frame in f.get('trace', []))]
        result.update(binary_sha256=actual, scanner_exit_code=scan.returncode,
            analysis_complete=scan.returncode in (0, 3), symbol_finding_count=len(symbols),
            package_finding_count=len(packages), total_finding_count=len(findings),
            binary_scan_clear=scan.returncode == 0 and not symbols,
            scanner_configuration=[e['config'] for e in events if 'config' in e])
        # Raw findings contain exact function locations. Do not publish them.
        binary.unlink()
    except Exception as error:
        result['error_type'] = type(error).__name__
    (directory / (tag + '.json')).write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result.get(k) for k in ('upstream_tag','analysis_complete','scanner_exit_code','symbol_finding_count','binary_scan_clear','error_type')}))
