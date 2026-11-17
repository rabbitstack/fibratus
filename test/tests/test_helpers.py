"""Unit tests for the platform independent parts of the helpers.

Run from the repository root:

    python -m unittest discover -s test/tests -t test
"""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from systest import SystemTestError
from systest.installer import resolve_msi
from systest.logs import LogReader, parse_alerts
from systest.service import parse_state

TEXT_ALERT = (
    'time="2026-11-16T15:03:41+01:00" level=info msg=sending alert: [Credential Manager access via known tools]. '
    "Text:  Event(s): 12 CreateProcess (exe: VaultCmd.exe)"
)
JSON_ALERT = json.dumps({
    "level": "info",
    "msg": "sending alert: [Potential ClickFix infection chain]. Text: Potential infostealer process x Event(s): e\n",
    "time": "2026-11-16T15:03:42+01:00",
})


class ParseAlertsTest(unittest.TestCase):
    def test_text_formatter(self):
        alerts = parse_alerts("noise\n" + TEXT_ALERT + "\n")
        self.assertEqual([a.title for a in alerts], ["Credential Manager access via known tools"])

    def test_json_formatter(self):
        alerts = parse_alerts(JSON_ALERT + "\n")
        self.assertEqual([a.title for a in alerts], ["Potential ClickFix infection chain"])

    def test_no_alerts(self):
        self.assertEqual(parse_alerts('level=info msg=bootstrapping with pid 42\n'), [])


class LogReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fibratus.log"
        self.log = LogReader(self.path)

    def test_missing_file(self):
        self.assertEqual(self.log.mark(), 0)
        self.assertEqual(self.log.alerts_since(0), [])

    def test_only_alerts_after_the_mark_count(self):
        self.path.write_text(TEXT_ALERT + "\n")
        offset = self.log.mark()
        self.assertIsNone(self.log.wait_for_alert("Credential Manager access via known tools", offset, timeout=0))
        with open(self.path, "a") as f:
            f.write(TEXT_ALERT + "\n")
        alert = self.log.wait_for_alert("Credential Manager access via known tools", offset, timeout=0)
        self.assertIsNotNone(alert)

    def test_other_rule_does_not_satisfy_the_wait(self):
        self.path.write_text(JSON_ALERT + "\n")
        self.assertIsNone(self.log.wait_for_alert("Credential Manager access via known tools", 0, timeout=0))

    def test_rotated_file_is_read_from_the_start(self):
        self.path.write_text("x" * 1000)
        offset = self.log.mark()
        self.path.write_text(TEXT_ALERT + "\n")  # shorter than the offset
        self.assertEqual(len(self.log.alerts_since(offset)), 1)

    def test_waits_for_alert_written_later(self):
        self.path.write_text("")

        def writer():
            time.sleep(0.3)
            with open(self.path, "a") as f:
                f.write(TEXT_ALERT + "\n")

        t = threading.Thread(target=writer)
        t.start()
        alert = self.log.wait_for_alert("Credential Manager access via known tools", 0, timeout=5, interval=0.1)
        t.join()
        self.assertIsNotNone(alert)


class ServiceStateTest(unittest.TestCase):
    def test_running(self):
        out = "SERVICE_NAME: Fibratus\n        TYPE               : 10  WIN32_OWN_PROCESS\n" \
              "        STATE              : 4  RUNNING\n"
        self.assertEqual(parse_state(out), "RUNNING")

    def test_stopped(self):
        self.assertEqual(parse_state("        STATE              : 1  STOPPED\n"), "STOPPED")

    def test_not_installed(self):
        self.assertIsNone(parse_state("[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n"))


class ResolveMsiTest(unittest.TestCase):
    def test_wildcard_must_match_exactly_one(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "fibratus-0.0.0-amd64.msi").write_bytes(b"")
            self.assertEqual(resolve_msi(str(Path(d) / "fibratus-*-amd64.msi")).name, "fibratus-0.0.0-amd64.msi")
            (Path(d) / "fibratus-1.0.0-amd64.msi").write_bytes(b"")
            with self.assertRaises(SystemTestError):
                resolve_msi(str(Path(d) / "fibratus-*-amd64.msi"))

    def test_missing(self):
        with self.assertRaises(SystemTestError):
            resolve_msi("does-not-exist.msi")


if __name__ == "__main__":
    unittest.main()
