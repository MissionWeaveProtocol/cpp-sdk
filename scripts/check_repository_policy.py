#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


SHORT_DISPLAY_NAME = "".join(("Mission", "Weave"))
SHORT_MACHINE_NAME = "".join(("mission", "weave"))

RULES = (
    ("retired acronym", re.compile(r"\b" + "".join(("AW", "GP")) + r"\b", re.IGNORECASE)),
    (
        "retired expanded name",
        re.compile(r"\b" + r"[\s_-]+".join(("Agent", "Workgroup", "Protocol")) + r"\b", re.IGNORECASE),
    ),
    ("incomplete product name", re.compile(re.escape(SHORT_DISPLAY_NAME) + r"(?!Protocol)")),
    ("incomplete machine identifier", re.compile(re.escape(SHORT_MACHINE_NAME) + r"(?!protocol)")),
    ("retired decision-record shorthand", re.compile(r"\b" + "".join(("A", "DR")) + r"s?\b", re.IGNORECASE)),
    (
        "retired decision-record phrase",
        re.compile(r"\b" + r"[\s_-]+".join(("architecture", "decision", "record")) + r"s?\b", re.IGNORECASE),
    ),
)

FORBIDDEN_PATHS = (
    re.compile(r"^(?:build|out|cmake-build-[^/]+)(?:/|$)"),
    re.compile(r"(?:^|/)\.DS_Store$"),
)


def tracked_files() -> list[str]:
    output = subprocess.check_output(("git", "ls-files", "-z"))
    return [entry.decode("utf-8") for entry in output.split(b"\0") if entry]


def inspect(label: str, value: str, failures: list[str]) -> None:
    for line_number, line in enumerate(value.splitlines(), start=1):
        for rule_label, pattern in RULES:
            if pattern.search(line):
                failures.append(f"{label}:{line_number}: {rule_label}")


def main() -> int:
    failures: list[str] = []
    files = tracked_files()

    for filename in files:
        if any(pattern.search(filename) for pattern in FORBIDDEN_PATHS):
            failures.append(f"path:{filename}: generated or local-only content is tracked")

        inspect(f"path:{filename}", filename, failures)
        contents = pathlib.Path(filename).read_bytes()
        if b"\0" not in contents:
            try:
                text = contents.decode("utf-8")
            except UnicodeDecodeError:
                continue
            inspect(filename, text, failures)

    if failures:
        print("Repository policy violations:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"Repository policy passed for {len(files)} tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
