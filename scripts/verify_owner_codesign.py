#!/usr/bin/env python3
"""Check ad-hoc archive integrity and declared VPN rights, not distribution signing."""
from pathlib import Path
import plistlib
import subprocess
import sys


def check(app):
    extension = app / "PlugIns/WireGuardNetworkExtension.appex"
    for bundle in (extension, app):
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(bundle)], check=True)
        result = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(bundle)],
                                check=True, capture_output=True)
        rights = plistlib.loads(result.stdout)
        key = "com.apple.developer.networking.networkextension"
        values = rights.get(key) if isinstance(rights, dict) else None
        # This checks our own ad-hoc archive before LCSign. Signed profiles may
        # legitimately add team/application identifiers and need separate review.
        if not isinstance(rights, dict) or set(rights) != {key} or values != ["packet-tunnel-provider"]:
            raise ValueError("Unexpected or missing pre-signing VPN entitlements")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_owner_codesign.py EXTRACTED_APP")
    check(Path(sys.argv[1]))
    print("Ad-hoc integrity and both declared VPN entitlements checked; owner signing still required.")
