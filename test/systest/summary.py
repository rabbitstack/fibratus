"""Rendering the outcome of the rule scenarios."""

import logging
import os

from .scenarios import Report, Result

log = logging.getLogger(__name__)


def _verdict(r: Result) -> str:
    return "MATCHED" if r.passed else "FAILED"


def render_text(report: Report) -> str:
    matched = len(report.results) - len(report.failed)
    lines = [f"Rule detection: {matched} of {len(report.results)} rules matched"]
    width = max((len(r.scenario.rule_name) for r in report.results), default=0)
    for r in report.results:
        timing = f"{r.seconds:.1f}s" if r.seconds is not None else "-"
        line = f"  {_verdict(r):<8} {r.scenario.rule_name:<{width}}  time={timing}"
        if r.detail:
            line += f"  ({r.detail})"
        lines.append(line)
    if report.other_alerts:
        lines.append("Other alerts logged during the run: " + ", ".join(report.other_alerts))
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    matched = len(report.results) - len(report.failed)
    lines = [
        f"### Rule detection: {matched} of {len(report.results)} rules matched",
        "",
        "| Rule | Result | Time to alert | Details |",
        "|------|--------|---------------|---------|",
    ]
    for r in report.results:
        icon = "✅ matched" if r.passed else "❌ failed"
        timing = f"{r.seconds:.1f}s" if r.seconds is not None else ""
        detail = r.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {r.scenario.rule_name} | {icon} | {timing} | {detail} |")
    if report.other_alerts:
        lines += ["", "Other alerts logged during the run: " + ", ".join(f"`{t}`" for t in report.other_alerts)]
    return "\n".join(lines) + "\n"


def publish(report: Report) -> None:
    """Prints the summary to the console and, on GitHub Actions, to the job summary page."""
    log.info("\n%s", render_text(report))
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(render_markdown(report))
