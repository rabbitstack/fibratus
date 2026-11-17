"""Tests for firing scenarios and summarizing the outcome."""

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from dataclasses import dataclass
from typing import Callable

from systest import SystemTestError, summary
from systest.logs import LogReader
from systest.scenarios import Scenario, run_all


def alert_line(title: str) -> str:
    return (
        f'time="2026-11-16T15:03:41+01:00" '
        f'level=info msg=sending alert: [{title}]. Text: Event(s): x\n'
    )


@dataclass(frozen=True)
class FakeScenario(Scenario):
    """Scenario with an injectable trigger for testing."""

    _trigger: Callable[[], None]

    def trigger(self) -> None:
        self._trigger()


class RunAllTest(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.path = Path(tmp.name) / "fibratus.log"
        self.path.write_text("", encoding="utf-8")
        self.log = LogReader(self.path)

    def emit(self, title: str):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(alert_line(title))

    def scenario(self, rule_name: str, trigger=None):
        return FakeScenario(rule_name, trigger or (lambda: None))

    def run_scenarios(self, scenarios, **kwargs):
        return run_all(
            scenarios,
            self.log,
            timeout=0.3,
            interval=0.02,
            **kwargs,
        )

    def test_all_rules_match(self):
        a = self.scenario("Rule A", lambda: self.emit("Rule A"))
        b = self.scenario("Rule B", lambda: self.emit("Rule B"))

        report = self.run_scenarios([a, b])

        self.assertEqual(
            [r.passed for r in report.results],
            [True, True],
        )
        self.assertEqual(report.failed, [])

    def test_triggers_are_executed_exactly_once(self):
        calls = {"Rule A": 0, "Rule B": 0}

        def trigger(rule_name):
            calls[rule_name] += 1
            self.emit(rule_name)

        scenarios = [
            self.scenario("Rule A", lambda: trigger("Rule A")),
            self.scenario("Rule B", lambda: trigger("Rule B")),
        ]

        report = self.run_scenarios(scenarios)

        self.assertEqual(calls, {"Rule A": 1, "Rule B": 1})
        self.assertTrue(all(r.passed for r in report.results))

    def test_missing_alert_is_reported_without_stopping_others(self):
        ok = self.scenario(
            "Rule OK",
            lambda: self.emit("Rule OK"),
        )
        silent = self.scenario("Rule Silent")

        report = self.run_scenarios([silent, ok])

        by_rule = {r.scenario.rule_name: r for r in report.results}

        self.assertTrue(by_rule["Rule OK"].passed)
        self.assertFalse(by_rule["Rule Silent"].passed)
        self.assertIn(
            "no alert within",
            by_rule["Rule Silent"].detail,
        )

    def test_raising_trigger_does_not_abort_the_run(self):
        def boom():
            raise SystemTestError("the Run dialog didn't show up")

        scenarios = [
            self.scenario("Rule Boom", boom),
            self.scenario(
                "Rule OK",
                lambda: self.emit("Rule OK"),
            ),
        ]

        report = self.run_scenarios(scenarios)

        by_rule = {r.scenario.rule_name: r for r in report.results}

        self.assertFalse(by_rule["Rule Boom"].passed)
        self.assertIn(
            "the Run dialog didn't show up",
            by_rule["Rule Boom"].detail,
        )
        self.assertTrue(by_rule["Rule OK"].passed)

    def test_trigger_failure_does_not_prevent_other_triggers(self):
        calls = []

        def boom():
            calls.append("boom")
            raise SystemTestError("trigger failed")

        def ok():
            calls.append("ok")
            self.emit("Rule OK")

        report = self.run_scenarios([
            self.scenario("Rule Boom", boom),
            self.scenario("Rule OK", ok),
        ])

        self.assertEqual(calls, ["boom", "ok"])
        self.assertTrue(report.results[1].passed)

    def test_alert_can_arrive_after_trigger_returns(self):
        def trigger():
            def delayed_emit():
                time.sleep(0.05)
                self.emit("Rule A")

            threading.Thread(
                target=delayed_emit,
                daemon=True,
            ).start()

        report = self.run_scenarios([
            self.scenario("Rule A", trigger),
        ])

        self.assertTrue(report.results[0].passed)

    def test_alerts_before_the_run_do_not_count(self):
        self.emit("Rule A")

        report = self.run_scenarios([
            self.scenario("Rule A"),
        ])

        self.assertFalse(report.results[0].passed)

    def test_other_alerts_are_listed(self):
        def trigger():
            self.emit("Rule A")
            self.emit("Unrelated rule")

        report = self.run_scenarios([
            self.scenario("Rule A", trigger),
        ])

        self.assertEqual(
            report.other_alerts,
            ["Unrelated rule"],
        )

    def test_missing_log_file(self):
        missing = LogReader(self.path.parent / "nope.log")

        with self.assertRaises(SystemTestError):
            run_all([], missing)


class SummaryTest(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        path = Path(tmp.name) / "fibratus.log"
        path.write_text("", encoding="utf-8")

        def emit():
            with path.open("a", encoding="utf-8") as f:
                f.write(alert_line("Rule OK"))

        self.report = run_all(
            [
                FakeScenario("Rule OK", emit),
                FakeScenario("Rule | Bad", lambda: None),
            ],
            LogReader(path),
            timeout=0.2,
            interval=0.02,
        )

    def test_text(self):
        text = summary.render_text(self.report)

        self.assertIn("1 of 2 rules matched", text)
        self.assertRegex(text, r"MATCHED\s+Rule OK")
        self.assertRegex(text, r"FAILED\s+Rule \\| Bad")

    def test_markdown_escapes_cells(self):
        md = summary.render_markdown(self.report)

        self.assertIn(
            "### Rule detection: 1 of 2 rules matched",
            md,
        )
        self.assertIn("✅ matched", md)
        self.assertIn("❌ failed", md)

    def test_publish_writes_the_job_summary(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "summary.md"

            with mock.patch.dict(
                os.environ,
                {"GITHUB_STEP_SUMMARY": str(target)},
            ):
                summary.publish(self.report)

            self.assertIn(
                "Rule detection",
                target.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
