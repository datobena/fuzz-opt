#!/usr/bin/env python3
"""Build an offline profiler image from an existing Ubuntu base and host perf.

For this Linux server: host kernel-matched linux-tools must already be installed.
Copies perf and its shared libraries; never installs packages or pulls a base.
"""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", default="ubuntu:24.04")
    p.add_argument("--tag", default="bench-sandbox/profiler")
    p.add_argument("--perf", type=Path)
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", args.base):
        p.error("invalid local base image reference")
    subprocess.run(["docker", "image", "inspect", args.base], check=True, capture_output=True)
    kernel = subprocess.check_output(["uname", "-r"], text=True).strip()
    perf = args.perf or Path("/usr/lib/linux-tools") / kernel / "perf"
    if not perf.is_file():
        p.error(f"kernel-matched perf missing: {perf}; install linux-tools separately or supply --perf")
    with tempfile.TemporaryDirectory(prefix="local-profiler-") as tmp:
        context = Path(tmp)
        binary = context / "rootfs/usr/lib/linux-tools" / kernel / "perf"
        binary.parent.mkdir(parents=True)
        shutil.copy2(perf, binary)
        for line in subprocess.check_output(["ldd", str(perf)], text=True).splitlines():
            match = re.search(r"=>\s+(/\S+)", line) or re.search(r"^\s*(/\S+)", line)
            if match:
                source = Path(match.group(1))
                # Preserve SONAMEs but follow merged-/usr directory symlinks.
                dest = context / "rootfs" / source.resolve().parent.relative_to("/") / source.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, dest)
        (context / "Dockerfile").write_text(f"FROM {args.base}\nCOPY rootfs/ /\n")
        subprocess.run(["docker", "build", "--pull=false", "-t", args.tag, str(context)], check=True)


if __name__ == "__main__":
    main()
