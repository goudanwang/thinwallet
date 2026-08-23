#!/usr/bin/env python3
"""Generate the paper's frontier cut-class table from a trace schema."""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import frontier  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "schema",
        nargs="?",
        default=os.path.join(ROOT, "schemas", "spartan_hyrax_stock.json"),
    )
    parser.add_argument("--output", help="write LaTeX rows to this file")
    parser.add_argument("--no-repair", action="store_true")
    args = parser.parse_args()

    result = frontier.analyse(
        frontier.load_schema(args.schema),
        allow_repair=not args.no_repair,
    )
    table = frontier.render_latex(result) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(table)
    else:
        sys.stdout.write(table)


if __name__ == "__main__":
    main()
