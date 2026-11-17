"""Querying the state of the Fibratus Windows service."""

import logging
import re
import subprocess
import time

from . import SystemTestError

log = logging.getLogger(__name__)

STATE_RE = re.compile(r"STATE\s*:\s*\d+\s+(?P<state>[A-Z_]+)")


def parse_state(output: str) -> str | None:
    """Extracts the service state (e.g. RUNNING) from the `sc query` output."""
    m = STATE_RE.search(output)
    return m.group("state") if m else None


def query_state(name: str) -> str | None:
    """Returns the service state, or None if the service isn't installed."""
    proc = subprocess.run(["sc.exe", "query", name], capture_output=True, text=True, check=False)
    return parse_state(proc.stdout)


def wait_until_running(name: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = query_state(name)
        if state == "RUNNING":
            log.info("service %s is running", name)
            return
        time.sleep(1)
    raise SystemTestError(f"service {name} didn't reach the RUNNING state within {timeout:.0f}s (last state: {state})")


def ensure_stays_running(name: str, period: float) -> None:
    """Fails if the service leaves the running state during the given period.

    Catches the sensor crashing right after the start, e.g. due to
    a misconfigured event source or a failure loading the rules.
    """
    deadline = time.monotonic() + period
    while time.monotonic() < deadline:
        state = query_state(name)
        if state != "RUNNING":
            raise SystemTestError(f"service {name} stopped being RUNNING (state: {state})")
        time.sleep(1)
    log.info("service %s stayed running for %.0fs", name, period)
