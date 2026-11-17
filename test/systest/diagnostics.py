"""Gathers the evidence needed to debug a failed system test run."""

import logging
import shutil
import subprocess
from pathlib import Path

from . import ui
from .config import INSTALL_DIR

log = logging.getLogger(__name__)


def _capture(output: Path, name: str, cmd: list) -> None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
        (output / name).write_text(proc.stdout + proc.stderr, encoding="utf-8")
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("unable to capture %s: %s", name, e)


def collect(output: Path) -> None:
    """Best effort. Never raises, since it runs after the real failure."""
    output.mkdir(parents=True, exist_ok=True)

    logs_dir = Path(INSTALL_DIR / "Logs")
    if logs_dir.is_dir():
        shutil.copytree(logs_dir, output / "fibratus-logs", dirs_exist_ok=True)

    # the verbose installer log, if the install step got that far
    for msi_log in Path.cwd().glob("*.log"):
        shutil.copy(msi_log, output / msi_log.name)

    _capture(output, "processes.txt", ["tasklist.exe", "/V"])

    # shows whether the Run dialog really made it to the screen
    ui.screenshot(output / "desktop.png")
    log.info("diagnostics written to %s", output)
