import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.audit_ipa_secret_markers import audit


class IpaAuditTests(unittest.TestCase):
    def test_detects_private_marker_across_chunks_without_reporting_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Test.app/sample", b"x" * 10 + b"-----BEGIN PRIVATE KEY-----")
            with patch("scripts.audit_ipa_secret_markers.CHUNK_SIZE", 12):
                result = audit(path)
            self.assertEqual(result["matchesByClass"]["private_pem"], 1)
            self.assertNotIn("PRIVATE KEY", str(result))

    def test_public_certificate_is_not_a_private_key(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Test.app/sample", b"-----BEGIN CERTIFICATE-----")
            self.assertEqual(audit(path)["matchCount"], 0)


if __name__ == "__main__":
    unittest.main()
