import argparse
from pathlib import Path
import sys

from .parser import MAX_BYTES, ReportError, parse_report
from .render import plain, render, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline reader of existing Nmap XML. Never scans.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("parse", "summary", "export"):
        command = sub.add_parser(name)
        command.add_argument("input", type=Path)
        command.add_argument("--max-bytes", type=int, default=MAX_BYTES)
        if name == "export":
            command.add_argument("--format", choices=("json", "csv", "markdown"), required=True)
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = parse_report(args.input, args.max_bytes)
        if args.command != "export":
            sys.stdout.write(render(report, "json") if args.command == "parse" else summary(report))
            return 0
        output = args.output
        if output.resolve() == args.input.resolve() or (output.exists() and output.samefile(args.input)):
            raise ReportError("Output must differ from input")
        content = render(report, args.format)
        try:
            # Exclusive creation prevents races from silently overwriting existing files.
            with output.open("x", encoding="utf-8", newline="") as stream:
                stream.write(content)
        except FileExistsError:
            # No --force switch: every replacement requires an interactive confirmation.
            if output.is_symlink() or not output.is_file():
                raise ReportError("Refusing to overwrite symlink or non-file")
            if not sys.stdin.isatty():
                raise ReportError("Output exists; choose another path or confirm in an interactive terminal")
            if input(f"Replace {plain(output)}? Type yes: ").strip().lower() != "yes":
                raise ReportError("Overwrite cancelled")
            with output.open("w", encoding="utf-8", newline="") as stream:
                stream.write(content)
        print(f"Saved: {plain(output)}")
        return 0
    except (OSError, ReportError, EOFError) as exc:
        print(f"Error: {plain(exc)}", file=sys.stderr)
        return 2
