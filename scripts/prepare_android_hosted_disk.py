"""Free only unused toolchains on the disposable GitHub-hosted Android runner."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

assert sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
assert os.environ.get("GITHUB_REPOSITORY") == "2njz45z86r-commits/vpn013-wg-ios"
before = shutil.disk_usage(".").free
removed = []
# This job uses Java/Android/Go, never .NET, Haskell or CodeQL. Do not remove
# Android SDK/NDK, Go/module caches, sources, keys, fixtures or test outputs.
for name in ("/usr/share/dotnet", "/opt/ghc", "/usr/local/.ghcup", "/opt/hostedtoolcache/CodeQL"):
    path = Path(name)
    if path.is_dir() and not path.is_symlink() and str(path.resolve()) == name:
        subprocess.run(["sudo", "rm", "-rf", "--", name], check=True, timeout=180)
        removed.append(name)
after = shutil.disk_usage(".").free
Path("android-hosted-disk-preflight.json").write_text(json.dumps({
    "disposableGitHubHostedRunner": True, "bytesBefore": before, "bytesAfter": after,
    "unusedToolchainsRemoved": removed, "androidAndGoPreserved": True
}))
assert after >= 12 * 1024**3, "Insufficient hosted-runner capacity before Android build"
print(json.dumps({"hostedDiskPreflight": "pass", "freeGiB": round(after / 1024**3, 1)}))
