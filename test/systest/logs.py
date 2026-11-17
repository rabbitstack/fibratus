"""Reading the Fibratus log file and detecting alerts."""

import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path, PurePath

log = logging.getLogger(__name__)

# Fibratus logs "sending alert: [<rule name>]. Text: ..." right before
# the alert is handed over to the alert senders. Works for both the text
# and JSON log formatters since the title is never escaped.
ALERT_RE = re.compile(r"sending alert: \[(?P<title>[^\]]*)\]\. Text:")


@dataclass(frozen=True)
class Alert:
    """An alert extracted from the log file."""

    title: str
    line: str


def parse_alerts(text: str) -> list[Alert]:
    """Extracts all alerts from the given chunk of log text."""
    alerts = []
    for line in text.splitlines():
        m = ALERT_RE.search(line)
        if m:
            alerts.append(Alert(title=m.group("title"), line=line))
    return alerts


class LogReader:
    """Reads the Fibratus log file incrementally.

    Alerts are only searched for past an offset taken before the rule is
    triggered, so alerts produced by earlier steps can't satisfy the check.
    """

    def __init__(self, path: PurePath):
        self.path = Path(path)

    def mark(self) -> int:
        """Returns the current end of the log file."""
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def read_from(self, offset: int) -> str:
        """Returns the log content starting at the given offset."""
        try:
            with open(self.path, "rb") as f:
                if f.seek(0, 2) < offset:
                    # the file shrank, which means it was rotated
                    offset = 0
                f.seek(offset)
                return f.read().decode("utf-8", errors="replace")
        except (FileNotFoundError, PermissionError):
            return ""

    def alerts_since(self, offset: int) -> list[Alert]:
        return parse_alerts(self.read_from(offset))

    def wait_for_alert(self, title: str, since: int, timeout: float, interval: float = 1.0) -> Alert | None:
        """Waits for the alert with the given rule name. Returns None on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            for alert in self.alerts_since(since):
                if alert.title == title:
                    return alert
            if time.monotonic() >= deadline:
                return None
            time.sleep(interval)

    def wait_for_text(self, text: str, timeout: float, interval: float = 1.0) -> bool:
        """Waits until the given text appears anywhere in the log file."""
        deadline = time.monotonic() + timeout
        while True:
            if text in self.read_from(0):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)
