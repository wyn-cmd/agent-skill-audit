"""Command line front end for the audit engine."""

import argparse
import json
import os
import sys

from . import __version__
from .engine import scan_tree
from .rules import RULES, SEVERITY_ORDER, SEVERITY_RANK


def build_parser():
    parser = argparse.ArgumentParser(
        prog="skillscan",
        description="Audit an agent skill folder or MCP configuration tree for risky capability grants.",
    )
    parser.add_argument("path", nargs="?", help="directory to scan")
    parser.add_argument("--json", action="store_true", help="print the report as json")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="low",
        help="hide findings below this severity (default: low, everything is shown)",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default="medium",
        help="exit 1 when a reported finding is at or above this severity (default: medium)",
    )
    parser.add_argument("--list-rules", action="store_true", help="print every rule and exit")
    parser.add_argument("--version", action="version", version=f"agent-skill-audit {__version__}")
    return parser


def print_rules():
    print(f"{len(RULES)} rules")
    for rule in RULES:
        scopes = ",".join(rule.scopes)
        print(f"{rule.rule_id}  {rule.severity:<6} {rule.title}  [{scopes}]")


def render(report, min_severity):
    out = [
        f"agent-skill-audit {__version__}",
        f"scanning {report.root}",
        f"scanned {report.files_scanned} files, skipped {report.files_skipped}, ignored {report.files_ignored}, {len(report.findings)} findings",
    ]

    if report.findings:
        out.append("")
        for finding in report.findings:
            label = finding.severity.upper()
            out.append(f"[{label}] {finding.rule_id} {finding.title}")
            matches = "match" if finding.count == 1 else "matches"
            out.append(f"  {finding.path} ({finding.count} {matches})")
            for line, text in finding.samples:
                where = f"line {line}" if line else "no line number"
                out.append(f"        {where}: {text}")
            out.append(f"  fix: {finding.advice}")
            out.append("")
    else:
        out.append("no findings at or above the requested severity")

    counts = report.counts()
    tally = ", ".join(f"{counts[severity]} {severity}" for severity in reversed(SEVERITY_ORDER))
    out.append(f"summary: {tally}")

    if report.warnings:
        out.append("")
        out.append(f"{len(report.warnings)} warnings")
        for warning in report.warnings[:20]:
            out.append(f"  {warning}")
        if len(report.warnings) > 20:
            out.append(f"  and {len(report.warnings) - 20} more")

    return "\n".join(out)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print_rules()
        return 0

    if not args.path:
        parser.print_usage(sys.stderr)
        print("skillscan: error: a directory to scan is required", file=sys.stderr)
        return 2

    if not os.path.exists(args.path):
        print(f"skillscan: error: no such path: {args.path}", file=sys.stderr)
        return 2
    if not os.path.isdir(args.path):
        print(f"skillscan: error: not a directory: {args.path}", file=sys.stderr)
        return 2

    try:
        report = scan_tree(args.path, min_severity=args.min_severity)
    except (ValueError, OSError) as exc:
        print(f"skillscan: error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render(report, args.min_severity))

    floor = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK[finding.severity] >= floor for finding in report.findings):
        return 1
    return 0