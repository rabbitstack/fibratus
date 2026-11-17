"""Helpers and scenarios for the Fibratus system tests.

The system tests exercise the whole sensor as an end user would: the MSI package is
installed, the Windows service is started, and a couple of detection rules are fired
by performing real actions on the host. The outcome is verified by inspecting the
"sending alert" lines Fibratus writes to its log file.

Only the Python standard library is used so the tests run on a vanilla CI runner.
"""


class SystemTestError(Exception):
    """Raised when a system test step fails."""
