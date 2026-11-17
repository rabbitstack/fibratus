"""Tests for the parts of the UI helpers that can run on any platform."""

import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from systest import ui


class ScreenshotTest(unittest.TestCase):
    def test_path_is_passed_through_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "out" / "desktop.png"
            captured = {}

            def fake_run(cmd, **kwargs):
                captured["cmd"] = cmd
                captured["env"] = kwargs["env"]
                target.write_bytes(b"png")
                return CompletedProcess(cmd, 0, "", "")

            with mock.patch.object(ui.subprocess, "run", fake_run):
                self.assertTrue(ui.screenshot(target))

            # the path must not be appended after -Command, as PowerShell would treat it as part of the command
            self.assertEqual(captured["cmd"][-1], ui._SCREENSHOT_PS)
            self.assertEqual(captured["env"][ui.SCREENSHOT_ENV], str(target.resolve()))
            self.assertIn("$env:" + ui.SCREENSHOT_ENV, ui._SCREENSHOT_PS)
            self.assertNotIn("$args", ui._SCREENSHOT_PS)

    def test_failure_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            failed = CompletedProcess([], 1, "", "boom")
            with mock.patch.object(ui.subprocess, "run", return_value=failed):
                self.assertFalse(ui.screenshot(Path(d) / "desktop.png"))


if __name__ == "__main__":
    unittest.main()
