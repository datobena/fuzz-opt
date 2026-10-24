#!/usr/bin/env python3
"""Register an account's year-long `claude setup-token` for sandboxed optimizers.

Each new optimizer round looks up the account the host CLI is logged in as (the
`oauthAccount` cswap writes into ~/.claude.json on every switch) in this map and
hands the agent that account's long-lived token -- see sandbox/egress.py
account_token(). The token is read with a hidden prompt, never from argv, and
the map is written with mode 600.

    python3 tools/add_account_token.py              # active account, prompts for the token
    python3 tools/add_account_token.py --email someone@example.com
    python3 tools/add_account_token.py --list       # accounts mapped (no tokens shown)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandbox import egress  # noqa: E402


def _load(path: Path) -> dict:
    if not path.is_file():
        return {}
    mapping = json.loads(path.read_text())
    if not isinstance(mapping, dict):
        sys.exit(f"{path}: expected a JSON object of account -> token")
    return mapping


def _save(path: Path, mapping: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".account_tokens.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(mapping, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--email", help="account email (default: the account the "
                    "host is logged in as now)")
    ap.add_argument("--list", action="store_true", help="list mapped accounts")
    args = ap.parse_args()
    path = egress.ACCOUNT_TOKENS_PATH
    mapping = _load(path)
    active = (egress.active_account().get("emailAddress") or "").strip()

    if args.list:
        for email in sorted(mapping):
            mark = "  <- active" if email.lower() == active.lower() else ""
            print(f"{email}{mark}")
        if not mapping:
            print(f"(no accounts mapped in {path})")
        return

    email = (args.email or active).strip()
    if not email:
        sys.exit("no --email given and no active account in "
                 f"{egress.CLAUDE_CONFIG_PATH}")
    token = getpass.getpass(f"year-long token for {email} (input hidden): ").strip()
    if not token.startswith("sk-ant-oat"):
        sys.exit("that does not look like a `claude setup-token` token "
                 "(expected sk-ant-oat...); nothing written")
    mapping = {k: v for k, v in mapping.items() if k.lower() != email.lower()}
    mapping[email] = token
    _save(path, mapping)
    print(f"mapped {email} (id {egress.credential_fingerprint(token)}) in {path}")


if __name__ == "__main__":
    main()
