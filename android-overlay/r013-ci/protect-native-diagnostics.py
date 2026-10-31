"""Bounded hosted synthetic diagnostics; only public-key encrypted bytes retained."""
from pathlib import Path
import json, os, subprocess

assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('GITHUB_REPOSITORY') == '2njz45z86r-commits/vpn013-wg-ios'
temporary = Path(os.environ['RUNNER_TEMP'])
source = Path(__file__).resolve().parents[2]
helper = source / 'scripts/audit-envelope.go'
recipient = source / 'scripts/audit-recipient.pub'
output = Path('output/review/native-diagnostics.enc.json')
paths = {
    'nativeCrash': temporary / 'r013-native-crash.log',
    'nativeRuntime': temporary / 'r013-native-runtime.log',
    'systemServices': Path('output/review/system-service-errors.txt'),
    'javaRuntime': Path('output/review/runtime-errors.txt'),
    'emulator': temporary / 'r013-emulator.log',
}
payload = {}
for name, path in paths.items():
    if path.is_file():
        with path.open('rb') as stream:
            stream.seek(max(0, path.stat().st_size - 1_048_576))
            payload[name] = stream.read(1_048_576).decode('utf-8', errors='replace')
environment = dict(os.environ)
for name in ('GOOS', 'GOARCH', 'CGO_ENABLED', 'CC', 'CXX', 'GOFLAGS', 'CGO_CFLAGS', 'CGO_CPPFLAGS', 'CGO_LDFLAGS'):
    environment.pop(name, None)
result = subprocess.run(['go', 'run', str(helper), 'encrypt', str(recipient), str(output)],
                        input=json.dumps(payload).encode(), capture_output=True, timeout=90, env=environment)
assert result.returncode == 0 and output.is_file(), 'Private native diagnostic protection failed'
print('Bounded synthetic native diagnostics retained with public-key encryption')
