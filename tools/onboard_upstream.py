#!/usr/bin/env python3
"""Onboard a current OSS-Fuzz project as an `upstream` benchmark target.

Each step reads and writes prework/upstream/<P>/ (the image definition) and,
for builds, a work dir <work>/<P>/:

  bases     resolve the base-builder refs OSS-Fuzz Dockerfiles use to digests
            -> prework/upstream/bases.json (an existing entry is kept unless
            --refresh)
  vendor    `git archive` projects/<P> of a pinned OSS-Fuzz commit into
            prework/upstream/<P>/ossfuzz/, plus the digest-pinned Dockerfile,
            meta.json and pins.json
  build     docker build bench-upstream/<p>, labelled with the definition hash;
            refused when an image with that label exists unless --rebuild
  compile   OSS-Fuzz `compile` with FUZZING_ENGINE=afl for one sanitizer, the
            image's own $SRC/<srcdir>, /out -> <work>/<P>/<S>/out; then harness
            discovery -> meta.json harnesses[S] and <work>/<P>/<S>/harnesses.json
  pins      the HEAD of every git/hg checkout under $SRC in the image
            -> pins.json checkouts
  manifest  one manifest entry per (project, sanitizer, harness); local ids
            from prework/upstream/local_ids.json, never reassigned
  run       vendor -> build -> pins -> compile per sanitizer (address first);
            every step skipped when its output is already there
  report    markdown table of the onboarded projects

Nothing of OSS-Fuzz's build is changed: the image is the project's Dockerfile
with only FROM pinned, and the build is `compile` (prework_build
.upstream_compile_args, --network none).
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The pipeline modules live at the repo root, one level up; Python only puts
# THIS script's directory on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from prework.build_image import read_pin  # noqa: E402
from prework.prework_build import restore_ownership, upstream_compile_args  # noqa: E402
from prework.upstream_image import (  # noqa: E402
    BASES_FILE, DEFINITION_LABEL, RESULT_FILE, UPSTREAM_DIR, build_upstream_image,
    definition_hash, load_meta, load_pins, pinned_dockerfile, upstream_image_tag,
)

BASE_BUILDER = "gcr.io/oss-fuzz-base/base-builder"
# The FROM refs in use by the shortlisted projects. The plain base-builder is
# the 20.04 image every other kind is built on: its digest is prework/base.pin.
BASE_REFS = (
    BASE_BUILDER,
    f"{BASE_BUILDER}:ubuntu-24-04",
    "gcr.io/oss-fuzz-base/base-builder-rust",
    "gcr.io/oss-fuzz-base/base-builder-go",
)
SANITIZERS = ("address", "undefined", "memory")
LOCAL_IDS_FILE = "local_ids.json"
FIRST_LOCAL_ID = 970001
COMPILE_TIMEOUT = 5400
HARNESS_SYMBOL = b"LLVMFuzzerTestOneInput"

# `pins`: one "<dir> <revision>" line per checkout under $SRC; an empty
# revision when the VCS tool is missing or refuses.
CHECKOUTS_SCRIPT = (
    'for d in $SRC/*/; do d=${d%/}; '
    'if [ -e "$d/.git" ]; then printf \'%s %s\\n\' "$(basename "$d")" '
    '"$(git -c safe.directory=\'*\' -C "$d" rev-parse HEAD 2>/dev/null)"; '
    'elif [ -d "$d/.hg" ]; then printf \'%s %s\\n\' "$(basename "$d")" '
    '"$(hg id -i -R "$d" 2>/dev/null)"; fi; done'
)


# --------------------------------------------------------------------------
# docker wrappers (the only places docker runs; tests replace them)
# --------------------------------------------------------------------------

def _docker(args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          errors="replace", timeout=timeout, check=False)


def resolve_base(ref: str) -> str:
    """``ref`` as ``<repo>@sha256:<digest>``: the local image's RepoDigest when
    the image is present (what a build would use), else the registry's
    linux/amd64 manifest digest."""
    repo = ref.rsplit(":", 1)[0] if ":" in ref.rsplit("/", 1)[-1] else ref
    r = _docker(["image", "inspect", "--format", "{{json .RepoDigests}}", ref])
    if r.returncode == 0:
        for d in json.loads(r.stdout or "null") or []:
            if d.split("@", 1)[0] == repo:
                return d
    r = _docker(["manifest", "inspect", "-v", ref], timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"cannot resolve {ref}: {r.stderr.strip()[-300:]}")
    m = json.loads(r.stdout)
    if isinstance(m, list):
        m = next((x for x in m if x.get("Descriptor", {}).get("platform", {})
                  .get("architecture") == "amd64"), None)
        if m is None:
            raise RuntimeError(f"cannot resolve {ref}: no linux/amd64 manifest")
    return f"{repo}@{m['Descriptor']['digest']}"


def image_label(tag: str) -> str | None:
    """The definition label of ``tag``; None when there is no such image, ""
    when it has no label."""
    r = _docker(["image", "inspect", "--format", "{{json .Config.Labels}}", tag])
    if r.returncode != 0:
        return None
    return (json.loads(r.stdout or "null") or {}).get(DEFINITION_LABEL, "")


def image_has_dir(tag: str, path: str) -> bool:
    return _docker(["run", "--rm", "--network", "none", "--entrypoint", "test",
                    tag, "-d", path]).returncode == 0


def image_checkouts_output(tag: str) -> str:
    r = _docker(["run", "--rm", "--network", "none", "--entrypoint", "bash",
                 tag, "-lc", CHECKOUTS_SCRIPT], timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"pins: {r.stderr.strip()[-300:]}")
    return r.stdout


def run_logged(cmd: list[str], log: str | Path, timeout: int) -> int | None:
    """Run ``cmd`` with stdout+stderr to ``log``; the return code, or None on a
    timeout (the named container is removed: killing the docker client does
    not stop it)."""
    with open(log, "w") as f:
        try:
            return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                                  timeout=timeout, check=False).returncode
        except subprocess.TimeoutExpired:
            f.write(f"\n[onboard] timed out after {timeout}s\n")
    if "--name" in cmd:
        _docker(["rm", "-f", cmd[cmd.index("--name") + 1]])
    return None


def restore_out_ownership(tag: str, out: Path) -> None:
    restore_ownership(tag, [str(out)])


def build_image(project_dir: Path, cpuset: str | None = None) -> tuple[bool, str]:
    return build_upstream_image(project_dir, cpuset=cpuset)


# --------------------------------------------------------------------------
# pure parts
# --------------------------------------------------------------------------

def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    tmp.replace(path)


def _read_json(path: Path, default=None):
    return json.loads(path.read_text()) if path.is_file() else default


def write_bases(path: Path = BASES_FILE, *, refresh: bool = False) -> dict:
    bases = _read_json(path, {})
    for ref in BASE_REFS:
        if ref in bases and not refresh:
            continue
        bases[ref] = read_pin("base.pin") if ref == BASE_BUILDER else resolve_base(ref)
    _write_json(path, bases)
    return bases


def sanitizers_of(project_yaml: dict) -> list[str]:
    """project.yaml's sanitizers (an entry may be ``{memory: {experimental:
    true}}``), only those this benchmark builds, ``address`` first."""
    listed = []
    for s in project_yaml.get("sanitizers") or []:
        name = next(iter(s)) if isinstance(s, dict) else str(s)
        if name in SANITIZERS and name not in listed:
            listed.append(name)
    return ["address"] + [s for s in listed if s != "address"]


def srcdir_of(project_yaml: dict, project: str) -> str:
    repo = str(project_yaml.get("main_repo") or "").rstrip("/")
    name = repo.rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name or project


class _Recording(dict):
    """A bases dict that remembers which refs pinned_dockerfile looked up."""
    def __init__(self, *a):
        super().__init__(*a)
        self.used: dict = {}

    def __getitem__(self, k):
        v = super().__getitem__(k)
        self.used[k] = v
        return v


def vendor(project: str, *, oss_fuzz: str | Path, commit: str,
           upstream_dir: Path = UPSTREAM_DIR, srcdir: str | None = None) -> dict:
    """projects/<project> at ``commit`` -> <upstream_dir>/<project>/ossfuzz/
    (replacing a previous copy), the pinned Dockerfile, meta.json, pins.json.
    An unknown FROM ref raises KeyError before anything is replaced."""
    oss_fuzz, upstream_dir = Path(oss_fuzz), Path(upstream_dir)
    sha = subprocess.run(["git", "-C", str(oss_fuzz), "rev-parse", "--verify",
                          f"{commit}^{{commit}}"], capture_output=True, text=True,
                         check=True).stdout.strip()
    bases = _Recording(_read_json(upstream_dir / "bases.json", {}))
    d = upstream_dir / project
    d.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=d, prefix=".vendor-") as tmp:
        tar = Path(tmp) / "p.tar"
        subprocess.run(["git", "-C", str(oss_fuzz), "archive", "--format=tar",
                        "-o", str(tar), sha, f"projects/{project}"],
                       capture_output=True, text=True, check=True)
        subprocess.run(["tar", "-xf", str(tar), "-C", tmp], check=True)
        tree = Path(tmp) / "projects" / project
        dockerfile = pinned_dockerfile((tree / "Dockerfile").read_text(), bases)
        py = yaml.safe_load((tree / "project.yaml").read_text()) or {}
        shutil.rmtree(d / "ossfuzz", ignore_errors=True)
        tree.rename(d / "ossfuzz")
    (d / "Dockerfile").write_text(dockerfile)
    old = _read_json(d / "meta.json", {})
    meta = {"project": project,
            "srcdir": srcdir or srcdir_of(py, project),
            "language": py.get("language") or "c++",
            "sanitizers": sanitizers_of(py),
            "harnesses": {},
            # written by hand while onboarding; a re-vendor keeps them
            "deviations": old.get("deviations", [])}
    _write_json(d / "meta.json", meta)
    _write_json(d / "pins.json", {"ossfuzz_commit": sha, "bases": bases.used,
                                  "checkouts": {}})
    return meta


def _is_harness(path: Path) -> bool:
    if path.name.startswith("afl-") or path.name == "llvm-symbolizer":
        return False
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or st.st_size < 4:
        return False
    with open(path, "rb") as f:
        if f.read(4) != b"\x7fELF":
            return False
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return m.find(HARNESS_SYMBOL) != -1


def discover_harnesses(out_dir: str | Path) -> list[str]:
    """Regular executable ELF files directly in /out that contain
    LLVMFuzzerTestOneInput, except AFL++'s own tools and llvm-symbolizer."""
    return sorted(p.name for p in Path(out_dir).iterdir() if _is_harness(p))


def parse_checkouts(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        name, _, rev = line.partition(" ")
        out[name] = rev.strip() or None
    return out


def _ordered(sans) -> list[str]:
    sans = list(sans)
    return (["address"] if "address" in sans else []) + [s for s in sans if s != "address"]


def write_manifest(projects: list[str], out: str | Path, *,
                   upstream_dir: Path = UPSTREAM_DIR) -> list[dict]:
    """One entry per (project, sanitizer with a non-empty harness list,
    harness). A sanitizer onboard_result.json records as not compiled is left
    out. Ids: local_ids.json keyed "P/S/H", a new key gets max(all ids so far)
    + 1, so an id once handed out is never handed out again."""
    upstream_dir = Path(upstream_dir)
    ids_file = upstream_dir / LOCAL_IDS_FILE
    ids = _read_json(ids_file, {})
    next_id = max([FIRST_LOCAL_ID - 1, *ids.values()]) + 1
    entries = []
    for p in projects:
        d = upstream_dir / p
        meta = load_meta(d)
        result = _read_json(d / RESULT_FILE, {}) or {}
        for s in _ordered(meta.get("harnesses", {})):
            if result.get("sanitizers", {}).get(s, {}).get("status", "compiled") != "compiled":
                continue
            for h in sorted(meta["harnesses"][s]):
                key = f"{p}/{s}/{h}"
                if key not in ids:
                    ids[key] = next_id
                    next_id += 1
                lid = ids[key]
                entries.append({
                    "project": meta["srcdir"], "ossfuzz_project": p, "kind": "upstream",
                    "sanitizer": s, "language": meta.get("language") or "c++",
                    "fuzz_target": h, "image": upstream_image_tag(p),
                    "local_id": lid, "cve": f"upstream-{lid}"})
    _write_json(ids_file, dict(sorted(ids.items())))
    entries.sort(key=lambda e: e["local_id"])
    _write_json(Path(out), entries)
    return entries


# --------------------------------------------------------------------------
# steps
# --------------------------------------------------------------------------

def build(project: str, *, upstream_dir: Path = UPSTREAM_DIR, cpuset: str | None = None,
          rebuild: bool = False, log: Path | None = None) -> tuple[bool, str]:
    d = Path(upstream_dir) / project
    tag = upstream_image_tag(project)
    if not rebuild and image_label(tag) == definition_hash(d):
        return False, f"{tag} is up to date with {d} (--rebuild to build anyway)"
    ok, out = build_image(d, cpuset=cpuset)
    if log is not None:
        Path(log).parent.mkdir(parents=True, exist_ok=True)
        Path(log).write_text(out)
    return ok, out


def pins(project: str, *, upstream_dir: Path = UPSTREAM_DIR) -> dict:
    d = Path(upstream_dir) / project
    p = load_pins(d)
    p["checkouts"] = parse_checkouts(image_checkouts_output(upstream_image_tag(project)))
    _write_json(d / "pins.json", p)
    return p["checkouts"]


def _set_harnesses(d: Path, sanitizer: str, harnesses: list[str] | None) -> None:
    meta = load_meta(d)
    if harnesses is None:
        meta.get("harnesses", {}).pop(sanitizer, None)
    else:
        meta.setdefault("harnesses", {})[sanitizer] = harnesses
    _write_json(d / "meta.json", meta)


def compile_sanitizer(project: str, sanitizer: str, *, work: str | Path,
                      upstream_dir: Path = UPSTREAM_DIR,
                      cpuset: str | None = None) -> dict:
    d = Path(upstream_dir) / project
    meta = load_meta(d)
    tag = upstream_image_tag(project)
    sd = Path(work) / project / sanitizer
    out, log, hfile = sd / "out", sd / "compile.log", sd / "harnesses.json"
    hfile.unlink(missing_ok=True)
    if not image_has_dir(tag, f"/src/{meta['srcdir']}"):
        _set_harnesses(d, sanitizer, None)
        return {"status": "srcdir_missing", "srcdir_verified": False,
                "reason": f"/src/{meta['srcdir']} is not a directory in {tag}"}
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    name = f"onboard-{project.lower()}-{sanitizer}-{os.getpid()}"
    cmd = ["docker", "run", "--rm", "--privileged", "--name", name]
    if cpuset is not None:
        cmd += ["--cpuset-cpus", str(cpuset)]
    cmd += ["--ulimit", "core=0",
            *upstream_compile_args(image=tag, source_dir=None, out_dir=str(out),
                                   project=meta["srcdir"], sanitizer=sanitizer,
                                   language=meta.get("language") or "c++")]
    t0 = time.time()
    rc = run_logged(cmd, log, COMPILE_TIMEOUT)
    secs = round(time.time() - t0)
    restore_out_ownership(tag, out)
    rec = {"srcdir_verified": True, "log": str(log), "returncode": rc, "secs": secs}
    if rc != 0:
        _set_harnesses(d, sanitizer, None)
        why = "timed out" if rc is None else f"compile exited {rc}"
        return {"status": "compile_failed", "reason": why, **rec}
    harnesses = discover_harnesses(out)
    if not harnesses:
        _set_harnesses(d, sanitizer, None)
        return {"status": "compile_failed", "reason": "no harnesses in /out", **rec}
    _set_harnesses(d, sanitizer, harnesses)
    _write_json(hfile, harnesses)
    return {"status": "compiled", "harnesses": harnesses, **rec}


def run_project(project: str, *, sanitizers: str, work: str | Path,
                upstream_dir: Path = UPSTREAM_DIR, oss_fuzz: str | Path | None = None,
                commit: str | None = None, srcdir: str | None = None,
                cpuset: str | None = None) -> dict:
    """vendor -> build -> pins -> compile, each step skipped when its output
    exists. A (re)build invalidates what was derived from the old image: the
    checkouts and every sanitizer's harnesses.json."""
    upstream_dir, work = Path(upstream_dir), Path(work)
    d, wd = upstream_dir / project, work / project
    wd.mkdir(parents=True, exist_ok=True)
    tag = upstream_image_tag(project)
    res = _read_json(wd / RESULT_FILE, {}) or {}
    res.update({"project": project, "image": tag})
    res.setdefault("sanitizers", {})

    def save(status: str | None = None) -> dict:
        if status:
            res["status"] = status
        res["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        _write_json(wd / RESULT_FILE, res)
        if d.is_dir():
            _write_json(d / RESULT_FILE, res)
        return res

    if not (d / "ossfuzz").is_dir():
        if oss_fuzz is None or commit is None:
            res["reason"] = "not vendored and no --oss-fuzz/--commit given"
            return save("vendor_failed")
        try:
            vendor(project, oss_fuzz=oss_fuzz, commit=commit,
                   upstream_dir=upstream_dir, srcdir=srcdir)
        except (KeyError, subprocess.CalledProcessError, FileNotFoundError) as e:
            res["reason"] = f"vendor: {type(e).__name__}: {e}"
            return save("vendor_failed")
        save("vendored")

    want = definition_hash(d)
    if image_label(tag) != want:
        ok, why = build(project, upstream_dir=upstream_dir, cpuset=cpuset,
                        rebuild=True, log=wd / "build.log")
        res["build_log"] = str(wd / "build.log")
        if not ok:
            res["reason"] = why.strip().splitlines()[-1] if why.strip() else "docker build failed"
            return save("image_failed")
        res["definition_hash"] = want
        res["sanitizers"] = {}
        for h in wd.glob("*/harnesses.json"):
            h.unlink()
        p = load_pins(d)
        p["checkouts"] = {}
        _write_json(d / "pins.json", p)
        meta = load_meta(d)
        meta["harnesses"] = {}
        _write_json(d / "meta.json", meta)
        save("image_built")
    res["definition_hash"] = want

    if not load_pins(d).get("checkouts"):
        pins(project, upstream_dir=upstream_dir)

    meta = load_meta(d)
    sans = ["address"] if sanitizers == "address" else _ordered(meta["sanitizers"])
    for s in sans:
        hfile = wd / s / "harnesses.json"
        if hfile.is_file():
            hs = json.loads(hfile.read_text())
            prev = res["sanitizers"].get(s) or {}
            if prev.get("status") != "compiled":
                prev = {"status": "compiled", "srcdir_verified": True,
                        "log": str(wd / s / "compile.log")}
            res["sanitizers"][s] = {**prev, "harnesses": hs}
            _set_harnesses(d, s, hs)
            continue
        res["sanitizers"][s] = compile_sanitizer(project, s, work=work,
                                                 upstream_dir=upstream_dir, cpuset=cpuset)
        save()
        if s == "address" and res["sanitizers"][s]["status"] != "compiled":
            return save(res["sanitizers"][s]["status"])
    res.pop("reason", None)
    return save("compiled")


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def _preflights(preflight_dir: Path | None) -> dict:
    found = {}
    if preflight_dir and Path(preflight_dir).is_dir():
        for f in sorted(Path(preflight_dir).rglob("preflight_*.json")):
            try:
                r = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            if r.get("local_id") is not None:
                found[str(int(r["local_id"]))] = r
    return found


def _preflight_cells(r: dict | None) -> tuple[str, str]:
    if r is None:
        return "-", "-"
    stages = r.get("stages", {})
    eps = stages.get("smoke", {}).get("execs_per_sec")
    eps = f"{eps:.0f}" if isinstance(eps, (int, float)) else "-"
    if r.get("ok"):
        return "READY", eps
    failed = next((k for k, v in stages.items() if not v.get("ok")), "?")
    return f"NOT READY ({failed})", eps


def render_report(projects: list[str] | None = None, *, upstream_dir: Path = UPSTREAM_DIR,
                  preflight_dir: Path | None = None,
                  intro_rows: str | Path | None = None) -> str:
    upstream_dir = Path(upstream_dir)
    if not projects:
        projects = sorted(p.name for p in upstream_dir.iterdir()
                          if (p / "meta.json").is_file()) if upstream_dir.is_dir() else []
    ids = _read_json(upstream_dir / LOCAL_IDS_FILE, {})
    pre = _preflights(preflight_dir)
    intro = {}
    for row in _read_json(Path(intro_rows), []) if intro_rows else []:
        intro[str(row[0]).lower()] = row

    head = ["Project", "Srcdir", "Sanitizer", "Harness", "local_id", "Onboard",
            "Preflight", "execs/s", "Fuzzers (intro)", "Coverage % (intro)", "Lines (intro)"]
    lines = ["# Upstream targets", "",
             "Generated by `tools/onboard_upstream.py report`.", "",
             "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    deviations = []
    for p in projects:
        d = upstream_dir / p
        meta = load_meta(d)
        res = _read_json(d / RESULT_FILE, {}) or {}
        row = intro.get(p.lower()) or intro.get(str(meta.get("srcdir", "")).lower())
        icells = ([str(row[1]), str(row[4]), str(row[5])] if row else ["-", "-", "-"])
        sans = res.get("sanitizers") or {s: {"status": "-", "harnesses": h}
                                         for s, h in meta.get("harnesses", {}).items()}
        rows = []
        for s in _ordered(sans):
            rec = sans[s]
            status = rec.get("status", "-")
            hs = (rec.get("harnesses") or []) if status in ("compiled", "-") else []
            for h in hs:
                lid = ids.get(f"{p}/{s}/{h}")
                pf, eps = _preflight_cells(pre.get(str(lid)) if lid else None)
                rows.append([p, meta["srcdir"], s, h, str(lid or "-"), status, pf, eps])
            if not hs:
                why = rec.get("reason", "")
                rows.append([p, meta["srcdir"], s, "-", "-",
                             status + (f": {why}" if why else ""), "-", "-"])
        if not rows:
            why = res.get("reason", "")
            rows.append([p, meta["srcdir"], "-", "-", "-",
                         res.get("status", "not run") + (f": {why}" if why else ""), "-", "-"])
        for r in rows:
            lines.append("| " + " | ".join(c.replace("|", "\\|") for c in r + icells) + " |")
        for dev in meta.get("deviations") or []:
            deviations.append(f"- **{p}**: {dev}")
    lines += ["", "## Deviations from OSS-Fuzz", ""]
    lines += deviations or ["None."]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bases", help="resolve base-builder refs -> bases.json")
    b.add_argument("--refresh", action="store_true", help="re-resolve existing entries")

    def proj(name, **kw):
        p = sub.add_parser(name, **kw)
        p.add_argument("--project", required=True, help="OSS-Fuzz project name")
        return p

    v = proj("vendor", help="vendor projects/<P> at a pinned OSS-Fuzz commit")
    for p in (v, r := proj("run", help="vendor, build, pins, compile (resumable)")):
        p.add_argument("--oss-fuzz", required=p is v, help="OSS-Fuzz checkout")
        p.add_argument("--commit", required=p is v, help="OSS-Fuzz commit-ish")
        p.add_argument("--srcdir", help="clone dir under $SRC when it is not "
                                        "the main_repo basename")
    bd = proj("build", help="docker build the image")
    bd.add_argument("--rebuild", action="store_true")
    c = proj("compile", help="OSS-Fuzz compile for one sanitizer + harness discovery")
    c.add_argument("--sanitizer", required=True, choices=SANITIZERS)
    for p in (bd, c, r):
        p.add_argument("--cpuset", default=None)
    for p in (c, r):
        p.add_argument("--work", required=True)
    r.add_argument("--sanitizers", choices=("all", "address"), default="all")
    proj("pins", help="record $SRC checkout revisions -> pins.json")
    m = sub.add_parser("manifest", help="write the upstream manifest")
    m.add_argument("--projects", required=True, help="comma-separated")
    m.add_argument("--out", default="data/manifests/manifest_upstream.json")
    rp = sub.add_parser("report", help="markdown table of the onboarded projects")
    rp.add_argument("--projects", default="", help="comma-separated (default: all)")
    rp.add_argument("--out", default="docs/UPSTREAM_TARGETS.md")
    rp.add_argument("--preflight-dir", default="results/preflight-upstream")
    rp.add_argument("--intro-rows", default=None)
    a = ap.parse_args(argv)

    if a.cmd == "bases":
        print(json.dumps(write_bases(refresh=a.refresh), indent=2))
    elif a.cmd == "vendor":
        print(json.dumps(vendor(a.project, oss_fuzz=a.oss_fuzz, commit=a.commit,
                                srcdir=a.srcdir), indent=2))
    elif a.cmd == "build":
        ok, out = build(a.project, cpuset=a.cpuset, rebuild=a.rebuild)
        print(out[-4000:])
        return 0 if ok else 1
    elif a.cmd == "compile":
        rec = compile_sanitizer(a.project, a.sanitizer, work=a.work, cpuset=a.cpuset)
        print(json.dumps(rec, indent=2))
        return 0 if rec["status"] == "compiled" else 1
    elif a.cmd == "pins":
        print(json.dumps(pins(a.project), indent=2))
    elif a.cmd == "manifest":
        entries = write_manifest([p for p in a.projects.split(",") if p], a.out)
        print(f"{len(entries)} entries -> {a.out}")
    elif a.cmd == "run":
        res = run_project(a.project, sanitizers=a.sanitizers, work=a.work,
                          oss_fuzz=a.oss_fuzz, commit=a.commit, srcdir=a.srcdir,
                          cpuset=a.cpuset)
        print(json.dumps(res, indent=2))
        return 0 if res["status"] == "compiled" else 1
    elif a.cmd == "report":
        text = render_report([p for p in a.projects.split(",") if p],
                             preflight_dir=Path(a.preflight_dir), intro_rows=a.intro_rows)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(text)
        print(f"-> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
