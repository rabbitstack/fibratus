"""Installing Fibratus from the MSI package."""

import glob
import logging
import subprocess
from pathlib import Path

from . import SystemTestError
from .config import MSI_SUCCESS_CODES

log = logging.getLogger(__name__)


def resolve_msi(pattern: str) -> Path:
    """Resolves the MSI path. The pattern may contain wildcards but has to match exactly one file."""
    matches = sorted(glob.glob(pattern))
    if len(matches) != 1:
        raise SystemTestError(f"expected exactly one MSI package for '{pattern}', found {len(matches)}: {matches}")
    return Path(matches[0]).resolve()


def install(msi_pattern: str, log_path: Path) -> None:
    """Silently installs the MSI package and verifies that msiexec reported success."""
    msi = resolve_msi(msi_pattern)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["msiexec.exe", "/i", str(msi), "/qn", "/norestart", "/l*v", str(log_path)]
    log.info("installing %s", msi)
    proc = subprocess.run(cmd, check=False)

    if proc.returncode not in MSI_SUCCESS_CODES:
        _dump_tail(log_path)
        raise SystemTestError(f"msiexec failed with exit code {proc.returncode}")

    log.info("msiexec finished with exit code %d", proc.returncode)


def _dump_tail(log_path: Path, lines: int = 200) -> None:
    try:
        # msiexec writes the verbose log in UTF-16 when it can
        raw = log_path.read_bytes()
        text = raw.decode("utf-16", errors="replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode(
            "utf-8", errors="replace")
        log.error("last %d lines of the installer log:\n%s", lines, "\n".join(text.splitlines()[-lines:]))
    except OSError as e:
        log.error("unable to read the installer log %s: %s", log_path, e)
