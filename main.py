"""Command-line entry point for AI Code Security Scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scanner.engine import scan_github_repository, scan_path
from utils.github_loader import GitHubRepositoryError
from utils.reporter import print_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Scan AI-generated code and text files for common security risks."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a file or directory for secrets, risky code, and prompt leaks.",
    )
    scan_parser.add_argument("path", help="File or directory to scan.")
    scan_parser.add_argument(
        "--json",
        dest="json_output",
        help="Optional path to write a JSON report.",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only a compact summary.",
    )

    scan_repo_parser = subparsers.add_parser(
        "scan-repo",
        help="Download and scan a public GitHub repository.",
    )
    scan_repo_parser.add_argument("url", help="GitHub repository URL to scan.")
    scan_repo_parser.add_argument(
        "--json",
        dest="json_output",
        help="Optional path to write a JSON report.",
    )
    scan_repo_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only a compact summary.",
    )

    return parser


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command not in {"scan", "scan-repo"}:
        parser.print_help()
        return 1

    try:
        if args.command == "scan":
            report = scan_path(Path(args.path))
        else:
            report = scan_github_repository(args.url)
    except (FileNotFoundError, GitHubRepositoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_report(report, quiet=args.quiet)

    if args.json_output:
        write_json_report(report, Path(args.json_output))
        if not args.quiet:
            print(f"\nJSON report written to: {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
