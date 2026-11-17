"""Scenarios that fire detection rules by performing real actions on the host."""

import logging
import os
import subprocess
import time

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from . import SystemTestError
from .config import ALERT_TIMEOUT, LOG_FILE
from .logs import LogReader

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Scenario(ABC):
    rule_name: str

    @abstractmethod
    def trigger(self) -> None:
        """Execute the actions that trigger the detection rule."""
        ...


@dataclass(frozen=True)
class CredentialManagerAccessViaKnownTools(Scenario):

    def trigger(self) -> None:
        """Rule: Credential Manager access via known tools.

        Spawns vaultcmd.exe with the /list argument, which is how
        adversaries enumerate the vaults holding saved credentials.
        """
        vaultcmd = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "VaultCmd.exe"
        )

        proc = subprocess.run(
            [str(vaultcmd), "/list"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

        # The exit code is irrelevant, the rule is evaluated on process creation.
        log.info("VaultCmd.exe exited with code %d", proc.returncode)


@dataclass(frozen=True)
class PotentialClickFixInfectionChain(Scenario):

    def trigger(self) -> None:
        """Rule: Potential ClickFix infection chain.

        Runs a dummy PowerShell command from the Run dialog.
        """
        from . import ui  # Imported lazily as it is only usable on Windows.

        try:
            ui.run_via_run_dialog(
                'powershell -NoProfile -NonInteractive '
                '-Command "whoami.exe; Start-Sleep -Seconds 2"'
            )
        except SystemTestError:
            ui.close_run_dialog()
            raise


SCENARIOS: dict[str, Scenario] = {
    scenario.rule_name: scenario
    for scenario in (
        CredentialManagerAccessViaKnownTools(
            rule_name="Credential Manager access via known tools",
        ),
        PotentialClickFixInfectionChain(
            rule_name="Potential ClickFix infection chain",
        ),
    )
}

@dataclass
class Result:
    """Outcome of a single scenario."""

    scenario: Scenario
    passed: bool = False
    # seconds between the first successful trigger and the alert
    seconds: float | None = None
    detail: str = ""
    triggered_at: float | None = field(default=None, repr=False)


@dataclass
class Report:
    results: list[Result]
    # titles of alerts that were logged during the run but don't belong to any scenario
    other_alerts: list[str]

    @property
    def failed(self) -> list[Result]:
        return [r for r in self.results if not r.passed]


def run_all(
    selected: list[Scenario],
    log_reader: LogReader | None = None,
    timeout: float = ALERT_TIMEOUT,
    interval: float = 1.0,
) -> Report:
    """Triggers all scenarios once and awaits their alerts.

    All scenarios are triggered first, then their alerts are awaited together.
    A scenario that fails to trigger doesn't prevent the others from running.
    Every rule gets a verdict in the report.
    """
    log_reader = log_reader or LogReader(LOG_FILE)

    if not log_reader.path.exists():
        raise SystemTestError(
            f"the Fibratus log file {log_reader.path} doesn't exist. "
            "Is Fibratus installed?"
        )

    # only alerts written past this point count.
    offset = log_reader.mark()
    results = [Result(s) for s in selected]

    triggered = []

    # trigger each scenario exactly once
    for r in results:
        log.info("[%s] triggering the rule", r.scenario.rule_name)

        try:
            r.scenario.trigger()
        except Exception as e:  # noqa: BLE001
            r.detail = f"trigger failed: {e}"
            log.warning("[%s] %s", r.scenario.rule_name, r.detail)
            continue

        r.detail = ""
        r.triggered_at = time.monotonic()
        triggered.append(r)

    # await alerts
    _await_alerts(triggered, log_reader, offset, timeout, interval)

    for r in results:
        if not r.passed and not r.detail:
            r.detail = f"no alert within {timeout:.0f}s after triggering"

    known = {s.rule_name for s in selected}
    other = sorted(
        {a.title for a in log_reader.alerts_since(offset)} - known
    )

    return Report(results, other)

def _await_alerts(
    pending: list[Result], log_reader: LogReader, offset: int, timeout: float, interval: float
) -> None:
    deadline = time.monotonic() + timeout
    while pending:
        titles = {a.title for a in log_reader.alerts_since(offset)}
        
        for r in list(pending):
            if r.scenario.rule_name in titles:
                r.passed = True
                r.seconds = time.monotonic() - (r.triggered_at or time.monotonic())
                log.info("[%s] alert received after %.1fs", r.scenario.rule_name, r.seconds)
                pending.remove(r)
        
        if not pending or time.monotonic() >= deadline:
            return
        
        time.sleep(interval)
