"""Pass only the dedicated, short-lived test profile over stdin; never log it."""
import json
import os
from pathlib import Path
import subprocess

payload = os.environ.pop('CANARY_CONFIG', '')
assert 0 < len(payload.encode()) < 8192, 'Dedicated canary unavailable'
result = subprocess.run(['./plain-wg-check'], input=payload.encode(),
                        capture_output=True, timeout=60)
assert result.returncode == 0, 'Dedicated client exited without credentials logged'
proof = json.loads(result.stdout)
assert isinstance(proof, dict) and 'secretKey' not in proof
Path('proof.json').write_text(json.dumps(proof, indent=2))
print(json.dumps(proof))
assert proof['authenticated_handshake'] and proof['traffic_verified'], 'Network acceptance incomplete'
