"""
secimport CLI — parse, detect, enrich, and export security data.

Usage::

    secimport parse <file>
    secimport detect <file>
    secimport list-connectors
    secimport list-parsers
    secimport run --config config.yaml
    secimport gap --source-a crowdstrike --source-b qualys --config config.yaml
"""

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="secimport",
        description="Parse, detect, and enrich security data imports.",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # parse
    p_parse = sub.add_parser("parse", help="Parse a file and output normalized records")
    p_parse.add_argument("file", help="Path to the file to parse")
    p_parse.add_argument("--parser", help="Force a specific parser (skip auto-detection)")
    p_parse.add_argument(
        "--format", choices=["json", "jsonl"], default="jsonl", help="Output format"
    )

    # detect
    p_detect = sub.add_parser("detect", help="Detect the source type of a file")
    p_detect.add_argument("file", help="Path to the file to analyze")

    # list-connectors
    sub.add_parser("list-connectors", help="List all registered connectors")

    # list-parsers
    sub.add_parser("list-parsers", help="List all registered parsers")

    # run
    p_run = sub.add_parser("run", help="Run multi-source ingestion from config")
    p_run.add_argument("--config", required=True, help="Path to YAML config file")

    # gap
    p_gap = sub.add_parser("gap", help="Run gap analysis between two sources")
    p_gap.add_argument("--source-a", required=True, help="First source name")
    p_gap.add_argument("--source-b", required=True, help="Second source name")
    p_gap.add_argument("--config", required=True, help="Path to YAML config file")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    try:
        if args.command == "parse":
            return _cmd_parse(args)
        elif args.command == "detect":
            return _cmd_detect(args)
        elif args.command == "list-connectors":
            return _cmd_list_connectors()
        elif args.command == "list-parsers":
            return _cmd_list_parsers()
        elif args.command == "run":
            return _cmd_run(args)
        elif args.command == "gap":
            return _cmd_gap(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    """Parse a file and print normalized records."""
    from ..detectors import parse_file

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"File not found: {file_path}", file=sys.stderr)
        return 1

    records, result = parse_file(str(file_path), parser_name=args.parser)

    items = list(records)
    if args.format == "json":
        print(json.dumps([r.model_dump(exclude_none=True) for r in items], indent=2, default=str))
    else:
        for record in items:
            print(json.dumps(record.model_dump(exclude_none=True), default=str))

    print(
        f"\n--- {result.source_type} | {result.data_type} | "
        f"{result.parsed_count} parsed, {result.error_count} errors ---",
        file=sys.stderr,
    )
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    """Detect the source type of a file."""
    from ..detectors import detect_all

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"File not found: {file_path}", file=sys.stderr)
        return 1

    matches = detect_all(str(file_path))
    if not matches:
        print("No matching parser found.", file=sys.stderr)
        return 1

    for parser_cls, score in matches:
        print(f"{parser_cls.source}/{parser_cls.data_type} (confidence: {score:.0%})")
    return 0


def _cmd_list_connectors() -> int:
    """List all registered connectors."""
    from ..connectors.base import ConnectorRegistry

    connectors = ConnectorRegistry.list_connectors()
    print(f"Registered connectors ({len(connectors)}):\n")
    for name, cls in sorted(connectors.items()):
        print(f"  {name:<30} {cls.vendor:<15} {cls.description}")
    return 0


def _cmd_list_parsers() -> int:
    """List all registered parsers."""
    from ..parsers.base import ParserRegistry

    parsers = ParserRegistry.list_parsers()
    print(f"Registered parsers ({len(parsers)}):\n")
    for name, cls in sorted(parsers.items()):
        print(f"  {name:<30} [{cls.data_type}]")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    """Run multi-source ingestion from config."""
    from ..runner import IngestionRunner

    runner = IngestionRunner.from_config(args.config)
    runner.run()
    return 0


def _cmd_gap(args: argparse.Namespace) -> int:
    """Run gap analysis between two sources."""
    from ..runner import IngestionRunner

    runner = IngestionRunner.from_config(args.config)
    runner.run()
    report = runner.correlator.gap_analysis(args.source_a, args.source_b)

    print(f"\nGap Analysis: {report.source_a} vs {report.source_b}")
    print(f"  In {report.source_a} only:  {len(report.in_a_not_b)}")
    print(f"  In {report.source_b} only:  {len(report.in_b_not_a)}")
    print(f"  In both:                     {len(report.in_both)}")
    print(f"  Coverage {report.source_a}→{report.source_b}: {report.coverage_a_to_b:.1%}")
    print(f"  Coverage {report.source_b}→{report.source_a}: {report.coverage_b_to_a:.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
