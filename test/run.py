"""Entrypoint for the system tests.

Each subcommand maps to one CI step so failures are easy to attribute:

    python test/run.py install --msi fibratus-0.0.0-amd64.msi
    python test/run.py check-service
    python test/run.py check-rules
    python test/run.py collect-diagnostics
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from systest import SystemTestError, diagnostics, installer, scenarios, service, summary
from systest.config import (
    LOG_FILE,
    SERVICE_NAME,
    SERVICE_STABILITY_PERIOD,
    SERVICE_START_TIMEOUT,
)
from systest.logs import LogReader

log = logging.getLogger("test")


def cmd_install(args: argparse.Namespace) -> None:
    installer.install(args.msi, Path(args.install_log))


def cmd_check_service(_: argparse.Namespace) -> None:
    service.wait_until_running(SERVICE_NAME, SERVICE_START_TIMEOUT)
    service.ensure_stays_running(SERVICE_NAME, SERVICE_STABILITY_PERIOD)
    # the logger is initialized before the event source is opened
    if not LogReader(LOG_FILE).wait_for_text("bootstrapping with pid", timeout=30):
        raise SystemTestError(f"the sensor didn't report that it is bootstrapped in {LOG_FILE}")


def cmd_check_rules(args: argparse.Namespace) -> None:
    selected = [scenarios.SCENARIOS[key] for key in (args.only or scenarios.SCENARIOS)]
    report = scenarios.run_all(selected)
    summary.publish(report)
    if report.failed:
        names = ", ".join(f"'{r.scenario.rule_name}'" for r in report.failed)
        raise SystemTestError(f"{len(report.failed)} of {len(report.results)} rules didn't match: {names}")


def cmd_collect_diagnostics(args: argparse.Namespace) -> None:
    diagnostics.collect(Path(args.output_dir))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fibratus system tests")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("install", help="install Fibratus from the MSI package via msiexec")
    p.add_argument("--msi", required=True, help="path to the MSI package (may contain a wildcard)")
    p.add_argument("--install-log", default="install.log", help="where msiexec writes its verbose log")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("check-service", help="verify that the Fibratus service is running")
    p.set_defaults(func=cmd_check_service)

    p = sub.add_parser("check-rules", help="fire the rules, await their alerts and summarize which matched")
    p.add_argument("--only", nargs="+", choices=sorted(scenarios.SCENARIOS), help="run only the given scenarios")
    p.set_defaults(func=cmd_check_rules)

    p = sub.add_parser("collect-diagnostics", help="gather logs and screenshots for troubleshooting")
    p.add_argument("--output-dir", default="test-output")
    p.set_defaults(func=cmd_collect_diagnostics)

    return parser


def main(argv=None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        stream=sys.stdout,
    )

    args = build_parser().parse_args(argv)

    try:
        args.func(args)
    except SystemTestError as e:
        log.error("%s", e)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=test {args.command}::{e}", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
