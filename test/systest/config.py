"""Locations and constants shared by the system test helpers."""

import os
from pathlib import PureWindowsPath

# Name of the Windows service registered by the MSI package
SERVICE_NAME = "Fibratus"

# The MSI installs Fibratus under %ProgramFiles%\Fibratus
INSTALL_DIR = PureWindowsPath(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Fibratus"

# The logger writes to <install dir>\Logs\fibratus.log by default
LOG_FILE = INSTALL_DIR / "Logs" / "fibratus.log"

# Exit codes msiexec uses to report success. The reboot ones are not
# a failure, the installation did complete.
MSI_SUCCESS_CODES = (0, 1641, 3010)

# How long to wait for the service to reach the running state
SERVICE_START_TIMEOUT = 60.0

# For how long the service has to stay in the running state to be considered healthy
SERVICE_STABILITY_PERIOD = 10.0

# How long to wait for the alert to show up in the log after triggering the rule
ALERT_TIMEOUT = 30.0

# Title of the Run dialog box. Assumes the English locale, which is what
# the hosted runners use.
RUN_DIALOG_TITLE = "Run"
