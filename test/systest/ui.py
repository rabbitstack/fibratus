"""Driving the interactive desktop through the Win32 API.

The ClickFix rule only fires for processes spawned by explorer.exe via the Run dialog,
so the dialog has to be opened for real: Win+R, type the command, press Enter. This
needs an interactive desktop session with explorer.exe running.
"""

import ctypes
import logging
import os
import subprocess
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

from . import SystemTestError
from .config import RUN_DIALOG_TITLE

log = logging.getLogger(__name__)

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

VK_RETURN = 0x0D
VK_ESCAPE = 0x1B
VK_LWIN = 0x5B
VK_R = 0x52

# per-character delay so the dialog's edit control doesn't drop keystrokes
TYPING_DELAY = 0.02


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    # the union has to contain the largest member (mouse) so sizeof(INPUT) matches the native one
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


def _user32():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int)
    user32.SendInput.restype = wintypes.UINT
    user32.FindWindowW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR)
    user32.FindWindowW.restype = wintypes.HWND
    return user32


def _send_key(vk: int = 0, scan: int = 0, flags: int = 0) -> None:
    inp = _INPUT(type=INPUT_KEYBOARD)
    inp.ki = _KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags, time=0, dwExtraInfo=0)
    sent = _user32().SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))
    if sent != 1:
        raise SystemTestError(f"SendInput failed (error {ctypes.get_last_error()}). Is there an interactive desktop?")


def _tap(vk: int) -> None:
    _send_key(vk=vk)
    _send_key(vk=vk, flags=KEYEVENTF_KEYUP)


def _type_text(text: str) -> None:
    for ch in text:
        code = ord(ch)
        _send_key(scan=code, flags=KEYEVENTF_UNICODE)
        _send_key(scan=code, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)
        time.sleep(TYPING_DELAY)


def _wait_for(condition: Callable[[], bool], timeout: float, interval: float = 0.25) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return False


def _run_dialog_open() -> bool:
    return bool(_user32().FindWindowW("#32770", RUN_DIALOG_TITLE))


def _explorer_running() -> bool:
    proc = subprocess.run(
        ["tasklist.exe", "/FI", "IMAGENAME eq explorer.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, check=False)
    return "explorer.exe" in proc.stdout.lower()


def ensure_explorer() -> None:
    """Makes sure the shell is running, since it owns the Run dialog."""
    if _explorer_running():
        return
    log.warning("explorer.exe is not running, starting the shell")
    subprocess.Popen(["explorer.exe"])
    if not _wait_for(lambda: bool(_user32().FindWindowW("Shell_TrayWnd", None)), timeout=30):
        raise SystemTestError("explorer.exe didn't come up. There might be no interactive desktop session")


def run_via_run_dialog(command: str) -> None:
    """Executes the command by typing it into the Run dialog (Win+R) of explorer.exe."""
    ensure_explorer()

    _send_key(vk=VK_LWIN)
    _tap(VK_R)
    _send_key(vk=VK_LWIN, flags=KEYEVENTF_KEYUP)

    if not _wait_for(_run_dialog_open, timeout=10):
        raise SystemTestError(f"the '{RUN_DIALOG_TITLE}' dialog didn't show up after pressing Win+R")
    # let the dialog take the focus
    time.sleep(0.5)

    log.info("typing the command into the Run dialog: %s", command)
    _type_text(command)
    time.sleep(0.3)
    _tap(VK_RETURN)

    if not _wait_for(lambda: not _run_dialog_open(), timeout=10):
        raise SystemTestError("the Run dialog is still open after submitting the command")


def close_run_dialog() -> None:
    """Dismisses the Run dialog if it's left open by a failed attempt."""
    if _run_dialog_open():
        _tap(VK_ESCAPE)


# The target path is handed over through the environment. With `powershell -Command`, trailing
# arguments are not bound to $args, they are appended to the command text instead.
SCREENSHOT_ENV = "SYSTEST_SCREENSHOT_PATH"

_SCREENSHOT_PS = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
try {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    } finally {
        $g.Dispose()
    }
    $bmp.Save($env:SYSTEST_SCREENSHOT_PATH, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $bmp.Dispose()
}
"""


def screenshot(path: Path) -> bool:
    """Saves a screenshot of the desktop. Best effort, used for diagnostics only."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _SCREENSHOT_PS],
            env={**os.environ, SCREENSHOT_ENV: str(path)},
            capture_output=True, text=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("unable to take a screenshot: %s", e)
        return False
    if proc.returncode != 0:
        log.warning("unable to take a screenshot: %s", (proc.stderr or proc.stdout).strip())
        return False
    return path.exists()
