import importlib.util
from pathlib import Path
import plistlib
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify_owner_codesign", Path(__file__).parents[1] / "verify_owner_codesign.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OwnerCodeSignChecks(unittest.TestCase):
    def test_checks_both_signatures_and_entitlements(self):
        rights = plistlib.dumps({"com.apple.developer.networking.networkextension": ["packet-tunnel-provider"]})
        with patch.object(module.subprocess, "run", return_value=SimpleNamespace(stdout=rights)) as run:
            module.check(Path("synthetic/AmneziaWG.app"))
        self.assertEqual(run.call_count, 4)
        self.assertIn("WireGuardNetworkExtension.appex", run.call_args_list[0].args[0][-1])

    def test_refuses_missing_right_in_either_bundle(self):
        good = SimpleNamespace(stdout=plistlib.dumps({"com.apple.developer.networking.networkextension": ["packet-tunnel-provider"]}))
        bad = SimpleNamespace(stdout=plistlib.dumps({}))
        for results in ([good, bad], [bad, good]):
            with self.subTest(results=results):
                with patch.object(module.subprocess, "run", side_effect=[None, results[0], None, results[1]]):
                    with self.assertRaises(ValueError):
                        module.check(Path("synthetic/AmneziaWG.app"))

    def test_refuses_failed_signature(self):
        with patch.object(module.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "codesign")):
            with self.assertRaises(subprocess.CalledProcessError):
                module.check(Path("synthetic/AmneziaWG.app"))

    def test_refuses_wrong_entitlement_type_or_substring(self):
        key = "com.apple.developer.networking.networkextension"
        for value in ("packet-tunnel-provider", "not-packet-tunnel-provider", ["not-packet-tunnel-provider"],
                      ["packet-tunnel-provider", 4], 1):
            with self.subTest(value=value):
                reply = SimpleNamespace(stdout=plistlib.dumps({key: value}))
                with patch.object(module.subprocess, "run", side_effect=[None, reply]):
                    with self.assertRaises(ValueError):
                        module.check(Path("synthetic/AmneziaWG.app"))

    def test_refuses_extra_presigning_entitlements(self):
        key = "com.apple.developer.networking.networkextension"
        for rights in ({key: ["packet-tunnel-provider"], "get-task-allow": True},
                       {key: ["packet-tunnel-provider"], "unexpected.access": True},
                       {key: ["packet-tunnel-provider", "app-proxy-provider"]}):
            with self.subTest(rights=rights):
                reply = SimpleNamespace(stdout=plistlib.dumps(rights))
                with patch.object(module.subprocess, "run", side_effect=[None, reply]):
                    with self.assertRaises(ValueError):
                        module.check(Path("synthetic/AmneziaWG.app"))


if __name__ == "__main__":
    unittest.main()
