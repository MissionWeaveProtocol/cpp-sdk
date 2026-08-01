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
    "58/58",
    "62 cryptography evaluations",
    "30 admission evaluations",
    "KeyRegistrySnapshot",
    "organization_wide",
    "organization_id",
    "AdmissionService",
    "admission/README.md",
    "f7e70a72c76bbeb5014c186cd820aac2112f0dde",
    "c95fc8f8334947dacf51a2c6e84d9b13f5b39b7d3827591569a1e2c5acfe47d7",
    "sha256:39971bfafb68ef6c18f9026220cccc4f023fd4d5c8074f8ff0276cb1129cd0a0",
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
