"""Synthetic checks for CLI output ownership and bounded build-only retries."""
import unittest
from unittest.mock import patch
import demo
from fixture_reference_coverage import Coverage


class OrchestrationTests(unittest.TestCase):
    def test_nongen_physical_page_permutation_is_not_an_identity_mapping(self):
        coverage = Coverage("40000000000-40000200000 rw-s 03800000 00:01 1 /memfd:java_heap (deleted)", "aarch64", False, 24)
        self.assertEqual(coverage.mapped(0x40000000080), 0x3800080)
        self.assertEqual(coverage.hypothesized(0x40000000080), 128)
        self.assertIsNone(coverage.mapped(0x40000400000))

    def test_gen_arm_reference_coverage(self):
        coverage = Coverage("1000000000-1000200000 rw-s 00000000 00:01 1 /memfd:java_heap (deleted)", "aarch64", True, 24)
        raw = (0x1000000080 << 16) | 0xe000
        self.assertEqual(coverage.mapped(raw), 128)
        self.assertEqual(coverage.hypothesized(raw), 128)
        self.assertIsNone(coverage.hypothesized(0))

    def test_gen_amd64_reference_coverage(self):
        coverage = Coverage("40000000000-40000200000 rw-s 00000000 00:01 1 /memfd:java_heap (deleted)", "amd64", True, 24)
        for bit in range(4):
            raw = (0x40000000080 << (13 + bit)) | (1 << (12 + bit))
            self.assertEqual(coverage.mapped(raw), 128)
            self.assertEqual(coverage.hypothesized(raw), 128)

    def test_cli_preserves_calling_uid_without_loosening_private_permissions(self):
        with patch.object(demo, "command", return_value="ok") as command:
            demo.cli("strings", "/captures/synthetic.raw")
        args = command.call_args.args
        if hasattr(demo.os, "getuid"):
            self.assertEqual(args[args.index("--user") + 1], f"{demo.os.getuid()}:{demo.os.getgid()}")
        self.assertEqual(args[-2:], ("strings", "/captures/synthetic.raw"))

    def test_transient_build_retry_is_bounded(self):
        with patch.object(demo, "command", side_effect=RuntimeError("502 Bad Gateway")) as command, patch.object(demo.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError):
                demo.build_images()
        self.assertEqual(command.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_deterministic_build_failure_is_not_retried(self):
        with patch.object(demo, "command", side_effect=RuntimeError("unit test failed")) as command, patch.object(demo.time, "sleep") as sleep:
            with self.assertRaises(RuntimeError):
                demo.build_images()
        self.assertEqual(command.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
