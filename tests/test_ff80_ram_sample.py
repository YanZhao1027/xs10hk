"""Simulated trials only: verifies FF80 debug-flag restoration, no USB access."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from ff80_ram_sample import controlled_trial, RestrictedFF80, MEM_SIZE


class FakeLink:
    def __init__(self, initial=0, fail_read=False, fail_enable=False,
                 fail_restore_once=False):
        self.flag = initial
        self.log = []
        self.fail_read = fail_read
        self.fail_enable = fail_enable
        self.fail_restore_once = fail_restore_once

    def read_flag(self):
        self.log.append(("read_flag",))
        return self.flag

    def write_flag(self, value):
        self.log.append(("write_flag", value))
        if value == 1 and self.fail_enable:
            raise OSError("simulated partial write failure")
        if value == 0 and self.fail_restore_once:
            self.fail_restore_once = False
            raise OSError("simulated first restore failure")
        self.flag = value

    def read_16(self):
        self.log.append(("read_16",))
        if self.fail_read:
            raise RuntimeError("simulated RAM read denied")
        return bytes(range(MEM_SIZE))


class ControlledRAMTests(unittest.TestCase):
    def test_success_restores(self):
        d = FakeLink()
        self.assertEqual(controlled_trial(d, logger=lambda _: None), bytes(range(16)))
        self.assertEqual(d.flag, 0)
        self.assertEqual([x for x in d.log if x[0] == "write_flag"],
                         [("write_flag", 1), ("write_flag", 0)])

    def test_read_failure_still_restores(self):
        d = FakeLink(fail_read=True)
        with self.assertRaisesRegex(RuntimeError, "RAM read denied"):
            controlled_trial(d, logger=lambda _: None)
        self.assertEqual(d.flag, 0)

    def test_enable_failure_still_restores(self):
        d = FakeLink(fail_enable=True)
        with self.assertRaisesRegex(OSError, "partial write failure"):
            controlled_trial(d, logger=lambda _: None)
        self.assertEqual(d.flag, 0)
        self.assertIn(("write_flag", 0), d.log)

    def test_one_restore_failure_retried(self):
        d = FakeLink(fail_restore_once=True)
        self.assertEqual(len(controlled_trial(d, logger=lambda _: None)), 16)
        self.assertEqual(d.flag, 0)
        self.assertEqual(sum(x == ("write_flag", 0) for x in d.log), 2)

    def test_nonzero_initial_state_no_writes(self):
        d = FakeLink(initial=1)
        with self.assertRaisesRegex(RuntimeError, "initial config state"):
            controlled_trial(d, logger=lambda _: None)
        self.assertEqual(d.flag, 1)
        self.assertFalse([x for x in d.log if x[0] == "write_flag"])


if __name__ == "__main__":
    unittest.main()
