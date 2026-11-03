import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("verify_owner_ipa", Path(__file__).parents[1] / "verify_owner_ipa.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

REPORT = {"appID": "com.vpn013.awg", "extensionID": "com.vpn013.awg.network-extension",
          "appleDistributionSigned": False, "adHocIntegrityChecked": True, "physicalDeviceTested": False}
MACHO = bytes.fromhex("cffaedfe0c000001") + b"synthetic"


def create_ipa(path, *, extension_id="com.vpn013.awg.network-extension", extension_version="1.0",
               point="com.apple.networkextension.packet-tunnel", binary=MACHO, extra=None):
    def info(identifier, executable, version="1.0", extension=False):
        result = {"CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
                  "CFBundleShortVersionString": version, "CFBundleVersion": "1"}
        if extension:
            result["NSExtension"] = {"NSExtensionPointIdentifier": point}
        return plistlib.dumps(result)
    with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)
        archive.writestr(module.APP + "/Info.plist", info("com.vpn013.awg", "app"))
        archive.writestr(module.APP + "/app", binary)
        archive.writestr(module.EXTENSION + "/Info.plist", info(extension_id, "extension", extension_version, True))
        archive.writestr(module.EXTENSION + "/extension", MACHO)
        for name, content in (extra or []):
            archive.writestr(name, content)


class OwnerPackageValidation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic.ipa"
        patcher = patch.dict(os.environ, {"SOURCE_SHA": "a" * 40, "RUN_ID": "123"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_valid_structure_reports_owner_signing_and_not_device_tested(self):
        create_ipa(self.path)
        result = module.validate(self.path, REPORT)
        self.assertTrue(result["requiresOwnerSigning"])
        self.assertFalse(result["physicalIPhoneTested"])
        self.assertEqual(result["sourceSha"], "a" * 40)
        self.assertEqual(len(result["sha256"]), 64)

    def test_rejects_wrong_extension_and_wrong_version(self):
        for kwargs in ({"extension_id": "other.extension"}, {"extension_version": "2.0"}, {"point": "wrong"}):
            with self.subTest(kwargs=kwargs):
                create_ipa(self.path, **kwargs)
                with self.assertRaises(ValueError):
                    module.validate(self.path, REPORT)

    def test_rejects_wrong_cpu_and_stale_build_report(self):
        create_ipa(self.path, binary=b"wrong cpu")
        with self.assertRaises(ValueError):
            module.validate(self.path, REPORT)
        create_ipa(self.path)
        with self.assertRaises(ValueError):
            module.validate(self.path, {**REPORT, "adHocIntegrityChecked": False})

    def test_rejects_archive_traversal_extra_app_and_duplicate_entry(self):
        for extra in ([('Payload/../../outside', b'x')], [('Payload/Other.app/Info.plist', b'x')],
                      [(module.APP + '/Info.plist', b'duplicate')]):
            with self.subTest(extra=extra[0][0]):
                create_ipa(self.path, extra=extra)
                with self.assertRaises(ValueError):
                    module.validate(self.path, REPORT)


if __name__ == "__main__":
    unittest.main()
