#!/usr/bin/env python3
"""Find 'good' ARVO candidates for the optimization benchmark.

Filters on MEASUREMENT properties only (not code/optimizability):
  - x86_64 (the perf profiler can't symbolize 32-bit i386 builds)
  - libFuzzer engine (not AFL)
  - AddressSanitizer (so it reproduces in the benchmark's ASAN pipeline;
    MSAN/UBSAN-only bugs like unrar don't reproduce here)
  - has a usable fuzz_target

Crash-speed ("not too fast like librawspeed") cannot be known from metadata;
that requires a short baseline run, done as a second screen.
"""
import json
import re
import sys
import time

from lib.arvo import fetch_arvo_issue, get_arvo_fuzz_target, get_arvo_crash_type

USED = {
    "CVE-2021-36084", "CVE-2022-1441", "CVE-2017-20006", "CVE-2018-25017",
    "CVE-2019-17534", "CVE-2019-17547", "CVE-2019-18218", "CVE-2019-18224",
    "CVE-2023-50246", "CVE-2021-38593",
}


def parse_cves(path):
    seen = {}
    for line in open(path):
        m = re.search(r"cve='([^']+)':\s*localId=(\d+)", line)
        if m:
            cve, lid = m.group(1), int(m.group(2))
            seen.setdefault(cve, lid)  # lowest local_id per CVE
    return seen


def main():
    seen = parse_cves("cves.txt")
    candidates = [(c, l) for c, l in sorted(seen.items()) if c not in USED]
    print(f"# screening {len(candidates)} candidate CVEs", flush=True)

    rows = []
    for i, (cve, lid) in enumerate(candidates):
        issue = fetch_arvo_issue(lid)
        rec = {"cve": cve, "local_id": lid}
        if not issue:
            rec.update(status="fetch_failed")
            rows.append(rec)
            print(f"[{i+1}/{len(candidates)}] {cve} {lid}: FETCH FAILED", flush=True)
            time.sleep(1)
            continue
        job_type = issue.get("job_type", "")
        parts = job_type.split("_")
        engine = parts[0] if parts else ""
        sanitizer = parts[1] if len(parts) > 1 else ""
        arch = "i386" if "_i386" in job_type else "x86_64"
        ft = get_arvo_fuzz_target(issue) or ""
        ct = get_arvo_crash_type(issue) or ""
        rec.update(
            project=issue.get("project", ""),
            fuzz_target=ft,
            job_type=job_type,
            engine=engine,
            sanitizer=sanitizer,
            arch=arch,
            crash_type=ct,
        )
        # measurement-only filter
        good = (
            engine == "libfuzzer"
            and arch == "x86_64"
            and sanitizer == "asan"
            and bool(ft)
        )
        rec["good"] = good
        rows.append(rec)
        print(f"[{i+1}/{len(candidates)}] {cve} {lid}: "
              f"{rec['project']}/{ft} {engine}/{sanitizer}/{arch} "
              f"crash='{ct}' -> {'GOOD' if good else 'skip'}", flush=True)
        time.sleep(1)

    json.dump(rows, open("arvo_candidates.json", "w"), indent=2)
    good = [r for r in rows if r.get("good")]
    print(f"\n# {len(good)} measurement-good candidates (x86_64 libFuzzer ASAN):",
          flush=True)
    for r in sorted(good, key=lambda r: r["project"]):
        print(f"  {r['project']:18} {r['cve']:18} {r['fuzz_target']:30} "
              f"local_id={r['local_id']} crash='{r['crash_type']}'", flush=True)


if __name__ == "__main__":
    sys.exit(main())
