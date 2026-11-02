"""Keep runtime configuration parse failures free of configuration data."""
from pathlib import Path
import unittest


class RuntimeLoggingTests(unittest.TestCase):
    def test_runtime_parser_failure_logs_only_a_constant(self):
        path = (Path(__file__).resolve().parents[2] /
                'overlay/Sources/WireGuardApp/Tunnel/TunnelsManager.swift')
        source = path.read_text(encoding='utf-8')
        start = source.index('let runtime = try TunnelConfiguration(')
        failure = source.index('} catch {', start)
        end = source.index('completionHandler(self.tunnelConfiguration)', failure)
        block = source[failure:end]
        self.assertIn('wg_log(.error, staticMessage: "Runtime config parse failed")', block)
        self.assertEqual(block.count('wg_log('), 1)
        self.assertNotIn('settings', block)
        self.assertNotIn('\\(error)', block)


if __name__ == '__main__':
    unittest.main()
