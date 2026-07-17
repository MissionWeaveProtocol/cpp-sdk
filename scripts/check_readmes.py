#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
READMES = (
    "README.md",
    "README.zh-CN.md",
    "README.zh-TW.md",
    "README.ja.md",
    "README.es.md",
    "README.fr.md",
    "README.de.md",
)
LANGUAGE_LABELS = ("English", "简体中文", "繁體中文", "日本語", "Español", "Français", "Deutsch")
REQUIRED_FACTS = (
    "MissionWeaveProtocol",
    "missionweaveprotocol",
    "43/43",
    "00964ea9064cbf1f0eca8af21a0c57367ee14752",
    "281fb1ec9b73e07f7a2897e576dbbad021085cf7293c1e9450ba3fbdec7f2cda",
)


def main() -> int:
    failures: list[str] = []
    for filename in READMES:
        path = ROOT / filename
        if not path.is_file():
            failures.append(f"missing {filename}")
            continue
        contents = path.read_text(encoding="utf-8")
        for label in LANGUAGE_LABELS:
            if label not in contents:
                failures.append(f"{filename}: missing language label {label}")
        for fact in REQUIRED_FACTS:
            if fact not in contents:
                failures.append(f"{filename}: missing required fact {fact}")
        for linked in READMES:
            if linked != filename and linked not in contents:
                failures.append(f"{filename}: missing switcher link to {linked}")

    if failures:
        print("README verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("Verified seven localized README files and their language switchers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
