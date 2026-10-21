#!/usr/bin/env python3
"""Verify that a pass backup tree only contains source-file backups."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ALLOWED_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def emit(payload: dict, exit_code: int) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify that a backup root only contains source-file edits."
    )
    parser.add_argument(
        "backup_root",
        help="Per-pass backup dir or overall /tmp/profile-once-fuzz-folds/<timestamp> root",
    )
    args = parser.parse_args()

    backup_root = Path(args.backup_root).expanduser().resolve()
    if not backup_root.exists():
        return emit(
            {
                "ok": False,
                "valid": False,
                "error": f"backup_root does not exist: {backup_root}",
            },
            1,
        )

    touched_files = sorted(path for path in backup_root.rglob("*") if path.is_file())
    invalid_files = [
        str(path.relative_to(backup_root))
        for path in touched_files
        if path.suffix.lower() not in ALLOWED_SUFFIXES
    ]

    payload = {
        "ok": True,
        "valid": not invalid_files,
        "backup_root": str(backup_root),
        "touched_file_count": len(touched_files),
        "invalid_files": invalid_files,
        "allowed_suffixes": sorted(ALLOWED_SUFFIXES),
    }
    return emit(payload, 0 if not invalid_files else 1)


if __name__ == "__main__":
    sys.exit(main())
