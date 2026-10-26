#!/usr/bin/env python3
"""Coverage growth and throughput on a WALL-CLOCK axis, with the dead time shown.

Two corrections that matter for an honest comparison:

1. Common instrument. The arms execute different binaries, so AFL's own
   edges_found counts edges of two different programs. coverage_growth.py
   replays BOTH arms' corpora on the BASELINE build; this plots that.

2. Wall-clock, not run_time. AFL's clock (plot_data relative_time, and the
   queue/crash `time:` fields) is run_time -- it does not advance while the
   process is stopped. The online arm is stopped at every hot swap, so plotting
   against AFL's clock silently DELETES that downtime and makes the arm look as
   though it fuzzed for the full wall-clock window. Each trial's samples are
   therefore shifted by the wall-clock it lost before them -- MEASURED per
   segment from both clocks (axis_windows), not summed from the logged swap
   downtime, which misses the minutes a relaunched AFL spends re-calibrating
   before its clock resumes -- the stopped intervals are drawn explicitly
   (exec/s = 0, coverage flat), and the optimizer's own CPU cost is overlaid.
   The baseline goes through the same conversion (its start-up lag).

3. No grey bands by default. They shaded the MEDIAN trial's charge windows and
   pinned the optimized throughput to exactly zero inside them -- but the ten
   trials pay at ten different instants. In four of libxml2's five on-axis
   bands only 2-5 of the 10 trials were actually stopped, and the unmasked
   aggregate there ran 400-630 exec/s, not 0; the arm-wide mean lost ~12% of
   its drawn throughput (760 -> 670 exec/s) to a stop most trials were not in.
   The green overlay already shows WHERE the cost is paid, and it is the same
   windows, so the shading only cost accuracy. --bands restores it.

    python3 analysis/plot_coverage_growth.py --experiment-id online-24h-b1-wolfssl
"""
from __future__ import annotations

import argparse
import bisect
import csv
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config
from lib import cpu_ledger

ARMS = {"baseline": ("#4C72B0", "Baseline"), "optimized": ("#DD8452", "Online-optimized")}
HOURS = 24.0
# 30 s bins. Must be SHORTER than the shortest stopped interval (~100 s for a
# hot swap), or a bin straddles the gap edge, averages inserted zeros with
# real throughput, and the stop never reaches zero on the plot.
GRID = np.arange(0, HOURS * 3600 + 30, 30, dtype=float)


# Files whose mtime marks the end of a round, besides the sandbox session's own
# files. round_provenance.json is written by run_round AFTER the replay gate, so
# it is the round's true finish; the *_meta.json files are written by rounds that
# bail out before the agent ever runs (no mutations, crash filter failed), which
# have no sandbox and no provenance. Named files only -- never an rglob of the
# iter dir, whose bin/ and corpus/ trees are huge and are touched again by later
# analyses (bisects, crash replays), which would move the "finish" by days.
_ROUND_END_FILES = ("round_provenance.json", "live_mutation_meta.json",
                    "round_corpus_meta.json", "corpus_snapshot_meta.json",
                    "source_diff/setup_metadata.json")


def _round_finishes(tdir: Path) -> dict[int, float]:
    """{iter: wall-clock finish} of one optimizer's rounds, from its iter dirs.

    round_provenance.json when the round wrote one: run_round writes it after
    the replay gate, so it IS the finish. The sandbox's own files are NOT
    consulted then. Its agent transcripts keep growing after the round has
    ended -- the session outlives the deadline the orchestrator capped the
    round to (php r2 trials 2, 4, 6 round 6: provenance at 24.0 h, transcripts
    at 24.1-24.45 h) or keeps running orphaned (bug-bloaty trial_05 round 1:
    broker_audit.log 3.2 h after provenance) -- and taking their max pushed
    the charge past the budget, where it shifted nothing drawn.

    Without provenance, the sandbox session's last write (max mtime, /memory/
    excluded: carried-forward memory keeps its old mtimes) together with the
    named end files; a round that bailed out before the agent ran has only
    the *_meta.json files. iter_00 is the baseline copy every trial starts
    from, not a round.
    """
    out: dict[int, float] = {}
    for idir in tdir.glob("iter_*"):
        m = re.fullmatch(r"iter_(\d+)", idir.name)
        if not m or int(m.group(1)) == 0:
            continue
        prov = idir / "round_provenance.json"
        if prov.is_file():
            out[int(m.group(1))] = prov.stat().st_mtime
            continue
        times = []
        sb = idir / "sandbox"
        if sb.is_dir():
            times += [f.stat().st_mtime for f in sb.rglob("*")
                      if f.is_file() and "/memory/" not in str(f)]
        times += [(idir / n).stat().st_mtime for n in _ROUND_END_FILES
                  if (idir / n).is_file()]
        if times:
            out[int(m.group(1))] = max(times)
    return out


# Old ledgers' broker rows carry no trial_id, but every sandbox session keeps
# its own broker_audit.log, one "===== <op> @ <unix ts> =====" header per audit
# write. Each broker op writes its last audit entry just before its ledger row
# closes: smoke and replay immediately (rounding to whole seconds is the only
# slack), build before restore_ownership's docker run and, once per session,
# the reference-binary copy (php r2: 0-3 s; r2 mbedtls: up to 6.5 s). A 5 s
# lead missed those owners, and whoever else finished a build in that second
# became the sole candidate of both rows -- all three of r2 mbedtls's
# "two-broker" flags. 10 s, with each entry backing at most one row
# (_AuditMatcher.resolve), takes the owner in without handing it the stranger.
_BROKER_OPS = {"broker_build": ("build",), "broker_smoke": ("smoke",),
               "broker_replay": ("replay", "replay-bracket")}
_AUDIT_LEAD = {"broker_build": 10.0}
_AUDIT_HEADER = re.compile(r"^===== (\S+) @ (\d+) =====$", re.M)


def read_broker_audit(tdirs: dict) -> dict:
    """{(trial, iter): [(ts, op), ...]} from every round's broker_audit.log.

    ``tdirs``: {trial: optimizer dir}. A session missing its log just has no
    entries, and its rows fall back to the session-overlap split.
    """
    out: dict[tuple, list] = {}
    for t, d in tdirs.items():
        for log in Path(d).glob("iter_*/sandbox/broker_audit.log"):
            m = re.fullmatch(r"iter_(\d+)", log.parent.parent.name)
            if not m:
                continue
            try:
                text = log.read_text(errors="replace")
            except OSError:
                continue
            out[(t, int(m.group(1)))] = sorted(
                (int(ts), op) for op, ts in _AUDIT_HEADER.findall(text))
    return out


class _AuditMatcher:
    """Which sandbox session served one untagged broker row.

    A session is a CANDIDATE when its log holds an entry of the row's op in
    [t_end - lead, t_end + 1] (and not before t_start - 1). One candidate is a
    match. Several are told apart by:

      * ONE ENTRY, ONE ROW: an audit entry closes one request. A row left with
        one candidate, backed there by a single entry, owns that entry, and it
        stops backing that session in any other row. Two such rows on the same
        entry cannot both be its owner and nothing says which is, so the
        session is dropped from both (they fall back to the split).
      * CONSISTENT: the owner logged nothing else while the row ran -- no entry
        of another op strictly inside (t_start, t_end), and no second
        build/smoke entry;
      * NOT BUSY: a session that owns a row (by a single candidate) was busy for
        that row's whole span, so it cannot own another row overlapping it.
        Repeated to a fixpoint, this settles most coincidences between
        concurrent trials (r2 mbedtls: 53% -> 87% of broker core-s matched).

    The last two hold only for a session with ONE broker. Some older sessions
    had two -- a retried agent session, or an orphaned one still sending
    requests, both auditing into the same log (bug-bloaty: 10 of 35 sessions; a
    1543 s build with a replay completing inside it). A session that shows it --
    a single-candidate row that fails the consistency test, or two such rows
    that overlap -- is exempt from both rules, so its own rows are never pinned
    on someone else. The exemption is SYMMETRIC: a row in which a flagged
    session fails a rule holds none of its candidates to that rule. Exempting
    only the flagged one let it win any row its rival also failed -- and a
    rival fails for the same reason, two brokers nobody flagged (bug-php
    trial_02 round 3: two builds closing in one second, 3474 core-s handed to
    flagged trial_00). Rows whose sessions are genuinely interchangeable
    (trials that start round 1 in lockstep and finish identical builds in the
    same second) stay ambiguous.
    """

    def __init__(self, audit: dict):
        self.audit = audit
        self.ts = {k: [ts for ts, _ in v] for k, v in audit.items()}
        self.flagged: set = set()       # two-broker sessions, set by resolve()
        self.by_op: dict[str, tuple] = {}
        for key, ents in audit.items():
            for i, (ts, op) in enumerate(ents):
                self.by_op.setdefault(op, []).append((ts, (key, i)))
        for op, v in self.by_op.items():
            v.sort(key=lambda x: x[0])
            self.by_op[op] = ([ts for ts, _ in v], [k for _, k in v])

    def support(self, r: dict) -> dict:
        """{session: {entry index, ...}} -- the audit entries that make each
        session a candidate for row r."""
        stage = str(r.get("stage", ""))
        ops = _BROKER_OPS.get(stage)
        if not ops:
            return {}
        a, e = _span(r)
        lo, hi = max(e - _AUDIT_LEAD.get(stage, 1.5), a - 1.0), e + 1.0
        out: dict[tuple, set] = {}
        for op in ops:
            ts, ents = self.by_op.get(op, ([], []))
            for key, i in ents[bisect.bisect_left(ts, lo):bisect.bisect_right(ts, hi)]:
                out.setdefault(key, set()).add(i)
        return out

    def candidates(self, r: dict) -> list:
        return sorted(self.support(r))

    def consistent(self, key, r: dict) -> bool:
        stage = str(r.get("stage", ""))
        ops = _BROKER_OPS[stage]
        a, e = _span(r)
        own = 0
        ents = self.audit[key]
        for ts, op in ents[bisect.bisect_right(self.ts[key], a + 0.5):]:
            if ts >= e + 0.5:
                break
            if op not in ops:
                if ts < e - 0.5:
                    return False
                continue
            own += 1
        return stage == "broker_replay" or own <= 1

    def resolve(self, rows: list) -> list:
        """Candidate sessions per row, in order; a single entry is a match."""
        spans = [_span(r) for r in rows]
        sup = [self.support(r) for r in rows]
        backs: dict[tuple, list] = {}       # (session, entry) -> rows it backs
        for i, s in enumerate(sup):
            for k, ids in s.items():
                for e in ids:
                    backs.setdefault((k, e), []).append(i)

        def settle() -> bool:
            # One entry, one row (class docstring).
            claims: dict[tuple, list] = {}
            for i, s in enumerate(sup):
                if len(s) == 1:
                    (k, ids), = s.items()
                    if len(ids) == 1:
                        claims.setdefault((k, next(iter(ids))), []).append(i)
            changed = False
            for (k, e), owners in claims.items():
                for j in backs[(k, e)]:
                    s = sup[j]
                    if e in s.get(k, ()) and (len(owners) > 1 or j != owners[0]):
                        s[k] = s[k] - {e}
                        if not s[k]:
                            del s[k]
                        changed = True
            return changed

        def drop(s: dict, failed: set, multi: set) -> bool:
            # Symmetric exemption (class docstring): if a flagged session needs
            # it here, nobody in this row is held to the rule.
            if not failed or failed & multi:
                return False
            for k in failed:
                del s[k]
            return True

        while settle():
            pass
        ok = [{k: self.consistent(k, r) for k in s} for r, s in zip(rows, sup)]
        multi, sole = set(), {}
        for s, sp, o in zip(sup, spans, ok):
            if len(s) == 1:
                k = next(iter(s))
                sole.setdefault(k, []).append(sp)
                if not o[k]:
                    multi.add(k)
        for k, v in sole.items():
            v.sort()
            if any(y[0] < x[1] for x, y in zip(v, v[1:])):
                multi.add(k)
        self.flagged = multi
        # Every rule to a fixpoint: a row whose flagged candidate is settled
        # elsewhere is held to the rules again.
        changed = True
        while changed:
            changed = settle()
            for s, o in zip(sup, ok):
                if len(s) > 1:
                    changed |= drop(s, {k for k in s if not o[k]}, multi)
            busy: dict[tuple, list] = {}
            for s, sp in zip(sup, spans):
                if len(s) == 1:
                    busy.setdefault(next(iter(s)), []).append(sp)
            for s, (a, e) in zip(sup, spans):
                if len(s) > 1:
                    changed |= drop(s, {k for k in s if any(
                        x < e and a < y for x, y in busy.get(k, ()))}, multi)
        return [sorted(s) for s in sup]


def _span(r: dict) -> tuple[float, float]:
    a = float(r.get("t_start") or 0.0)
    b = r.get("t_end")
    return a, (float(b) if b is not None else a + float(r.get("wall_s") or 0.0))


def attribute_ledger(rows: list, *, optimizers, finishes: dict,
                     campaign_start: float, audit: dict | None = None) -> dict:
    """Split every counted core-second of the ledger over (trial, round).

    CONSERVATION is the contract: the per-trial charges plus the setup share sum
    to the ledger's counted total, exactly -- no row is dropped, none counted
    twice. The plot used to charge ~8.8h/trial on php r2 against a true 13.8h,
    because (1) every orchestrator row of every round said iter 0 and was all
    charged at the FIRST round's finish, (2) each round's broker CPU was split
    over all ten optimizers but only charged to the trials that ran that round
    (round 6 ran on 5 of 10 trials: half its 28,946 core-s vanished), and (3)
    the setup builds, ~46 of php r2's 137.7 core-h, were never charged at all.

    ``optimizers``: the trial ids that ran an optimizer. ``finishes``:
    {trial: {iter: wall finish}} (_round_finishes). ``campaign_start``: the
    earliest trial start, wall-clock.

    Two ledger generations, detected per ledger:

    new (Oct 2026+)  every row names its trial_id and iter, broker rows
                     included (lib/cpu_ledger.py, sandbox/broker.py). Used as is.
    old              trial-tagged rows all say iter 0 and broker rows carry no
                     trial_id. Re-derived:
                       * a trial-tagged row belongs to the round of ITS trial
                         whose window (previous finish, this finish] holds its
                         t_start;
                       * a broker row matched to exactly one sandbox session by
                         that session's broker_audit.log (``audit``, see
                         _AuditMatcher) belongs to that session's trial and
                         round, whole;
                       * otherwise (no log entry fits, or several sessions'
                         do) it belongs to the trial(s) whose agent_wait
                         (the agent session it served) overlaps it, split evenly
                         when sessions overlap, in the round of that agent_wait;
                       * a broker row overlapping no session is split evenly over
                         the optimizers active at that moment -- never dropped.
                     The even split was off by up to +-10% per trial and +-25%
                     per round on php r2, where the audit logs place 97.5% of
                     the broker core-s exactly (87-99.9% across campaigns).

    SETUP rows (no trial, counted, started before any trial did: the ccache
    template builds) are one campaign-wide cost; each optimizer is charged
    1/len(optimizers) of it, at run_time 0, because that is when it was spent.
    A trial-tagged row with no round (iter 0 in a new ledger) folds into that
    trial's first round, so nothing but setup shifts before the first finish.

    Returns {"charges": {trial: {round_key: core_s}}, "positions": {trial:
    {round_key: wall finish}}, "setup_core_s", "setup_stages", "ledger_core_s",
    "style", "split_by_session", "split_by_activity", "untagged_core_s"} --
    round_key is the iter, or a negative synthetic key for work after a trial's
    last recorded finish. ``untagged_core_s`` splits the untagged campaign rows'
    core-s into "matched" (by audit log), "ambiguous" (several sessions fit)
    and "unmatched" (none did); the last two took the fallback split.
    """
    opt = sorted(int(t) for t in optimizers)
    optset = set(opt)
    counted = [r for r in rows if r.get("counts")
               and float(r.get("core_s") or 0.0) > 0.0]
    ledger_core_s = sum(float(r["core_s"]) for r in counted)
    tagged = [r for r in rows if r.get("trial_id") in optset]
    new_style = any((r.get("iter") or 0) >= 1 for r in tagged) or any(
        str(r.get("stage", "")).startswith("broker_")
        and r.get("trial_id") in optset for r in rows)

    fin = {t: sorted((finishes.get(t) or {}).items(), key=lambda kv: kv[1])
           for t in opt}

    def round_at(t: int, when: float):
        """The round of trial t whose window (prev finish, finish] holds `when`;
        a synthetic key -1 past its last recorded finish."""
        for it, f in fin[t]:
            if when <= f:
                return it
        return -1

    def first_round(t: int):
        return min((it for it, _ in fin[t]), default=-1)

    # Each optimizer's active span, for broker rows no session overlaps.
    active: dict[int, list] = {}
    for r in tagged:
        a, b = _span(r)
        s = active.setdefault(r["trial_id"], [a, b])
        s[0], s[1] = min(s[0], a), max(s[1], b)
    sessions = [r for r in tagged if r.get("stage") == "agent_wait"]

    def key_of(r: dict):
        t = r["trial_id"]
        if new_style:
            it = r.get("iter")
            return it if isinstance(it, int) and it >= 1 else first_round(t)
        return round_at(t, _span(r)[0])

    charges = {t: {} for t in opt}
    own_end = {t: {} for t in opt}      # latest end of the trial's OWN rows
    setup_core_s, setup_stages = 0.0, set()
    by_session = by_activity = 0
    untagged = {"matched": 0.0, "ambiguous": 0.0, "unmatched": 0.0}

    def add(t, k, cs):
        charges[t][k] = charges[t].get(k, 0.0) + cs

    def is_setup(r):
        return (_span(r)[0] < campaign_start
                and not str(r.get("stage", "")).startswith("broker_"))

    # Untagged work during the campaign (an old ledger's broker rows), matched
    # to its sandbox session up front: resolve() reasons across all of them.
    loose = [r for r in counted
             if r.get("trial_id") not in optset and not is_setup(r)]
    owners_of = {}
    if audit and loose:
        matcher = _AuditMatcher({k: v for k, v in audit.items() if k[0] in optset})
        owners_of = {id(r): c for r, c in zip(loose, matcher.resolve(loose))}

    for r in counted:
        cs = float(r["core_s"])
        a, b = _span(r)
        t = r.get("trial_id")
        if t in optset:
            k = key_of(r)
            add(t, k, cs)
            own_end[t][k] = max(own_end[t].get(k, b), b)
            continue
        if is_setup(r):
            setup_core_s += cs
            setup_stages.add(r.get("stage"))
            continue
        owners = owners_of.get(id(r), [])
        if len(owners) == 1:
            untagged["matched"] += cs
            add(owners[0][0], owners[0][1], cs)
            continue
        untagged["ambiguous" if owners else "unmatched"] += cs
        hits: dict[int, dict] = {}
        for s in sessions:
            sa, sb = _span(s)
            if sa <= b and a <= sb:
                prev = hits.get(s["trial_id"])
                ov = min(b, sb) - max(a, sa)
                if prev is None or ov > prev[0]:
                    hits[s["trial_id"]] = (ov, s)
        if hits:
            by_session += 1
            for tt, (_, s) in hits.items():
                add(tt, key_of(s), cs / len(hits))
            continue
        by_activity += 1
        mid = (a + b) / 2.0
        act = [tt for tt in opt if tt in active
               and active[tt][0] <= mid <= active[tt][1]] or opt
        for tt in act:
            add(tt, round_at(tt, a), cs / len(act))

    positions: dict[int, dict] = {}
    for t in opt:
        files = dict(fin[t])
        pos = {}
        for k in charges[t]:
            cands = [x for x in (files.get(k), own_end[t].get(k)) if x is not None]
            if not cands:
                # Only shares of untagged rows past the last finish: the
                # trial's own last activity is the best bound available.
                cands = [active.get(t, [campaign_start, campaign_start])[1]]
            pos[k] = max(cands)
        positions[t] = pos
    return {"charges": charges, "positions": positions,
            "setup_core_s": setup_core_s, "setup_stages": sorted(setup_stages),
            "ledger_core_s": ledger_core_s,
            "style": "new" if new_style else "old",
            "split_by_session": by_session, "split_by_activity": by_activity,
            "untagged_core_s": untagged}


def per_trial_charge_windows(exp_dir: Path, stops_by_trial: dict,
                             report: bool = True,
                             info: dict | None = None) -> dict:
    """{trial: [(run_time, charge_s)]} -- each trial's OWN optimizer CPU, charged
    at the run_time each round FINISHED. Setup is NOT charged (see below).

    ``stops_by_trial``: {trial: [(run_time, duration)]}, the windows that turn
    that trial's run_time into wall-clock (axis_windows, or the logged swap
    stops); wall -> run_time is their exact inverse (to_run_time), so a charge
    sits on the same axis as the samples it shifts.

    History, so none of it comes back:
      * Position is the round's FINISH, never its start minus the cumulative
        charge: the optimizer runs on separate cores in parallel and never pauses
        the trial's clock, so wall -> run_time subtracts ONLY the time the trial
        itself was stopped before it. (Charging at start - cumulative clamped
        piles of charge to t=0 and faked an early coverage deficit, Oct 2026.)
      * Magnitude comes from the CPU ledger, never from sandbox-mtime spans
        scaled by a CPU/wall factor (a 2-file measurement, k=0.79..1.03).
      * Attribution is per (trial, round) and CONSERVES the ledger total
        (attribute_ledger). The previous version took per-round totals / 10
        from cpu_cost.json, but every trial-tagged row said iter 0, so it put
        each trial's whole orchestrator cost at its first finish, dropped the
        shares of trials that did not run a round, and never charged setup:
        php r2 plotted ~8.8 h/trial against a true 13.8 h.

    Each round's charge sits at its finish (_round_finishes, or the round's own
    rows' latest end). A rejected round still ran and still burned CPU, so it is
    charged at its own finish like an accepted one. run_time = (finish - this
    trial's start) - the stops before it. A finish past the 24 h budget (a
    round that overran it, or older campaigns that started rounds up to the
    deadline) is CLAMPED to the budget's end and printed. The clamp does NOT
    make the curves pay for it: a charge only shifts the samples after it, and
    nothing after the 24 h mark is drawn, so CPU spent past the budget moves no
    plotted point either way -- it is counted only in the caption's total. What
    clamping buys is that the printout names it, per trial, instead of it
    vanishing silently.

    Setup -- the ccache template builds and the preflight profile, which run
    before any trial starts -- is attributed (so the ledger still conserves) but
    NOT charged: both arms start fuzzing at the same instant after it, and the
    charge is meant to cover the rounds and what each round imposes. Charging
    it at run_time 0 (Oct 20-25 2026) delayed every online curve by setup / n
    (12 min on harfbuzz, 20 min on PROJ) for work done before the clock started.

    ``info``, when given, is filled with the attribution summary the caption
    needs ("setup_core_s", "optimizers").
    """
    online = exp_dir / "optimized" / "online"
    rows = cpu_ledger.load(online / "cpu_ledger.jsonl")
    if not rows:
        return {}
    starts = {}
    for m in (exp_dir / "optimized").glob("trial_*/metadata.json"):
        try:
            starts[_trial_id(m)] = float(json.loads(m.read_text()).get("start_time") or 0)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
    starts = {t: s for t, s in starts.items() if s > 0}
    if not starts:
        return {}
    t0 = min(starts.values())
    tdirs = {_trial_id(d): d for d in (online / "trials").glob("trial_*") if d.is_dir()}
    tdirs.pop(-1, None)
    if not tdirs:
        return {}
    att = attribute_ledger(
        rows, optimizers=list(tdirs),
        finishes={t: _round_finishes(d) for t, d in tdirs.items()},
        campaign_start=t0, audit=read_broker_audit(tdirs))
    n = len(tdirs)
    setup_each = att["setup_core_s"] / n
    if info is not None:
        info.update(setup_core_s=att["setup_core_s"], optimizers=n)

    out: dict[int, list] = {}
    late: dict[int, list] = {}          # trial -> [core_s, latest overrun]
    for t in sorted(tdirs):
        down = stops_by_trial.get(t, [])
        start = starts.get(t, t0)
        wins = []
        for k, cs in att["charges"][t].items():
            elapsed = att["positions"][t][k] - start
            if elapsed > HOURS * 3600:
                lt = late.setdefault(t, [0.0, 0.0])
                lt[0] += cs
                lt[1] = max(lt[1], elapsed - HOURS * 3600)
                elapsed = HOURS * 3600
            wins.append((to_run_time(elapsed, down), cs))
        out[t] = sorted(wins)

    if report:
        h = 3600.0
        print(f"  CPU charge, {exp_dir.name}: {att['style']}-style ledger"
              + ("" if att["style"] == "new" else
                 f" (rounds re-derived from timestamps; {att['split_by_session']} "
                 f"untagged broker rows split over overlapping agent sessions, "
                 f"{att['split_by_activity']} over active optimizers)"))
        u = att["untagged_core_s"]
        if any(u.values()):
            print(f"    untagged broker core-h: {u['matched']/h:.2f} matched to "
                  f"one session by broker_audit.log, fallback split "
                  f"{(u['ambiguous'] + u['unmatched'])/h:.2f} "
                  f"({u['ambiguous']/h:.2f} ambiguous + {u['unmatched']/h:.2f} "
                  f"unmatched); {u['matched'] / sum(u.values()) * 100:.1f}% exact")
        if att["setup_core_s"]:
            print(f"    setup {', '.join(att['setup_stages'])}: "
                  f"{att['setup_core_s']/h:.2f} core-h before any trial started "
                  f"({setup_each/h:.2f} h per optimizer): NOT charged")
        for t in sorted(out):
            tot = sum(c for _, c in out[t])
            print(f"    trial_{t:02d}: {tot/h:6.2f} h charged (rounds)"
                  + (f"; {late[t][0]/h:.2f} h finished past {HOURS:.0f} h "
                     f"(up to +{late[t][1]/h:.2f} h), clamped to the end"
                     if t in late else ""))
        if late:
            print(f"    {sum(v[0] for v in late.values())/h:.2f} core-h of round "
                  f"charges finished past the {HOURS:.0f} h budget on "
                  f"{len(late)} trial(s): clamped to run_time at {HOURS:.0f} h")
        charged = sum(c for w in out.values() for _, c in w)
        accounted = charged + att["setup_core_s"]
        print(f"    total charged {charged/h:.3f} core-h + setup not charged "
              f"{att['setup_core_s']/h:.3f} vs ledger counted "
              f"{att['ledger_core_s']/h:.3f} core-h (diff {(accounted - att['ledger_core_s']):+.3f} "
              f"core-s); mean {charged/n/h:.2f} h/trial")
    return out


def cpu_charge_windows(exp_dir: Path, project: str, swaps):
    """Optimizer CPU, charged to the online arm as lost fuzzing time.

    The profiling, rebuilds and replays run on a separate core, so they do not
    stop the trials -- but that core could have been fuzzing. Charging
    ``core_seconds / trial_cores`` per round puts both arms on an equal CPU
    budget: the online arm's curve is shifted right by the fuzzing time its
    optimizer consumed, so a coverage advantage has to be paid for before it
    counts. Agent model-wait is NOT charged (it is GPU/API latency, not CPU).

    Returned in run_time coordinates so it composes with the swap downtime.
    """
    try:
        cost = json.loads((exp_dir / "optimized" / "online" / "cpu_cost.json").read_text())
    except (OSError, json.JSONDecodeError):
        return []
    starts = sorted(
        json.loads(m.read_text()).get("start_time", 0)
        for m in (exp_dir / "optimized").glob("trial_*/metadata.json"))
    if not starts:
        return []
    t0 = starts[0]
    out = []
    for r in cost.get("rounds", []):
        charge = float(r.get("fuzz_seconds_equivalent") or 0.0)
        end = r.get("t_end")
        if charge <= 0 or not end:
            continue
        wall = end - t0
        prior = sum(d for rt, d in swaps if rt <= wall)   # downtime already elapsed
        out.append((max(wall - prior, 0.0), charge))
    return out


def swap_windows(experiment_id: str, trial_id: int | None = None):
    """Hot-swap stops for ONE trial (or, legacy, for the whole online arm).

    Two log formats, because the design changed underneath this script:

      shared-binary (b1..b6)  "online round N: HOT-SWAP into K running online
                              trials" -- ONE stop applies to every online trial,
                              so a single global window list is correct.
      per-trial     (c1+)     "trial_07 round N: HOT-SWAP (swap generation G)"
                              -- each trial stops on its OWN schedule, so the
                              windows must be read per trial and applied only to
                              that trial's samples. Averaging them onto a common
                              timeline would place a gap where no trial actually
                              stopped and shift every trial by downtime it did
                              not experience.

    A log that parses to ZERO swaps is treated as an error, not as "no
    downtime". The old parser matched only the shared-binary string, so against
    a per-trial log it silently returned [] and the online arm was plotted
    UNCHARGED -- exactly the flattering curve the file-missing guard below was
    written to prevent.
    """
    log = Path(f".{experiment_id}.log")
    if not log.is_file():
        raise SystemExit(
            f"missing run log {log} -- it is the only record of hot-swap "
            f"downtime; without it the online arm would be plotted uncharged")
    stamp = lambda l: dt.datetime.strptime(l[:19], "%Y-%m-%d %H:%M:%S")
    text = log.read_text(errors="replace").splitlines()

    per_trial = any(re.search(r"trial_\d+ round \d+: HOT-SWAP", l) for l in text)
    start = None
    pend: dict[str, dt.datetime] = {}
    downtime: dict[str, float] = {}
    out: dict[str, list] = {}
    for line in text:
        if "Started trial" in line and start is None:
            start = stamp(line)
            continue
        if start is None:
            continue
        if per_trial:
            m = re.search(r"trial_(\d+) round \d+: HOT-SWAP", line)
            if m:
                pend[m.group(1)] = stamp(line)
                continue
            m = re.search(r"trial_(\d+) round \d+: swap complete", line)
            key = m.group(1) if m else None
        else:
            if "HOT-SWAP into" in line:
                pend["*"] = stamp(line)
                continue
            key = "*" if "swap complete" in line else None
        if key is None or key not in pend:
            continue
        began = pend.pop(key)
        dur = (stamp(line) - began).total_seconds()
        acc = downtime.get(key, 0.0)
        wall = (began - start).total_seconds()
        out.setdefault(key, []).append((wall - acc, dur))
        downtime[key] = acc + dur

    total = sum(len(v) for v in out.values())
    if total == 0:
        raise SystemExit(
            f"{log} parsed to ZERO hot swaps. Refusing to plot: the online arm "
            f"would be drawn as if it never stopped. Check the log format "
            f"(expected 'HOT-SWAP into' or 'trial_NN round N: HOT-SWAP').")

    if not per_trial:
        return out["*"]
    if trial_id is None:
        # Legacy callers want one list; hand back the union so the charged-CPU
        # bookkeeping still composes, but per-trial callers pass trial_id.
        return sorted(w for v in out.values() for w in v)
    return out.get(f"{trial_id:02d}", [])


def swap_windows_by_trial(experiment_id: str) -> dict:
    """{trial_id: [(run_time, duration), ...]} -- empty dict for legacy logs."""
    log = Path(f".{experiment_id}.log")
    if not log.is_file():
        return {}
    text = log.read_text(errors="replace")
    if not re.search(r"trial_\d+ round \d+: HOT-SWAP", text):
        return {}
    ids = sorted({int(m) for m in re.findall(r"trial_(\d+) round \d+: HOT-SWAP", text)})
    return {i: swap_windows(experiment_id, i) for i in ids}


# A swap row's state_at_swap.run_time is the trial's LAST periodic fuzzer_stats
# write (AFL writes it every 60 s, and docker stop ends in SIGKILL after its
# 10 s grace, so no final write): 0-55 s, mean ~28 s, behind where the trial
# really stopped. plot_data rows come every 5 s, and a resumed AFL writes none
# in its first 60 s, so the old process's last row below run_time + 55 is
# where it stopped.
_STATS_STALE = 55.0


def _plot_times(tdir: Path):
    """Sorted plot_data relative_times of one trial, or None."""
    try:
        text = (tdir / "afl_out" / "default" / "plot_data").read_text(errors="replace")
    except OSError:
        return None
    xs = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            try:
                xs.append(float(line.split(",", 1)[0]))
            except ValueError:
                continue
    return sorted(xs) or None


def _stop_run_time(rt: float, xs) -> float:
    """The run_time a trial stopped at, given the stale one its swap row read."""
    if not xs:
        return rt
    i = bisect.bisect_left(xs, rt - 10.0)
    j = bisect.bisect_left(xs, rt + _STATS_STALE)
    return max([rt] + xs[i:j])


def _end_offset(tdir: Path, md: dict):
    """(wall - run_time, source, run_time) of a trial's LAST segment, or None.

    The final fuzzer_stats write is exact: its mtime and its run_time are one
    instant of both clocks. end_time is taken after the container is torn
    down, 3-32 s later, so it is only the fallback, for a file rewritten or
    touched since (run_time unlike the metadata's, or mtime past end_time).
    """
    start = float(md.get("start_time") or 0.0)
    end = md.get("end_time")
    final = (md.get("final_stats") or {}).get("run_time")
    f = tdir / "afl_out" / "default" / "fuzzer_stats"
    try:
        rt = next(float(v) for k, _, v in
                  (line.partition(":") for line in f.read_text().splitlines())
                  if k.strip() == "run_time")
        mt = f.stat().st_mtime
        if (start < mt and (end is None or mt <= float(end) + 1.0)
                and (final is None or abs(rt - float(final)) < 1.0)):
            return mt - start - rt, "fuzzer_stats", rt
    except (OSError, StopIteration, ValueError):
        pass
    if end and final is not None:
        return float(end) - start - float(final), "end_time", float(final)
    return None


def _mean_offset(windows, T: float) -> float:
    """Mean of to_wall(t) - t over run_time [0, T]."""
    if T <= 0:
        return 0.0
    return sum(d * (T - rt) for rt, d in windows if rt <= T) / T


def axis_windows(exp_dir: Path, experiment_id: str, logged: dict,
                 report: bool = True) -> dict:
    """run_time -> wall-clock windows for every trial of both arms, MEASURED.

    AFL's clock (run_time) stops whenever the trial is not fuzzing, and the
    logged swap downtime (HOT-SWAP -> swap complete, ~10-20 s) is only part of
    that: the relaunched AFL re-calibrates its whole queue before its clock
    resumes (afl-fuzz.c resets start_time after the dry run). Adding only the
    logged downtime drew the online curves minutes too early (r2 bloaty: 18 min
    per trial by 24 h, ~4 min per swap) and each swap gap as ~15 s.

    So the offset O = wall elapsed - run_time is MEASURED once per segment (the
    stretch between two starts of AFL), from a reading of both clocks:
      * a segment a swap ended: the swap_timeline row's ``ts`` (taken after
        the stop) against the run_time the trial stopped at (_stop_run_time);
        exact when the row has ``stats_ts``, the wall instant of the
        fuzzer_stats write ``state_at_swap`` read;
      * the last segment: the final fuzzer_stats write (_end_offset);
      * newer rows also carry ``resumed_ts``/``resumed_run_time``, the
        relaunched AFL's first write: the next segment's offset, exact.
    run_time t in segment k maps to t + O_k, and the stop at boundary b_k is
    drawn [b_k + O_{k-1}, b_k + O_k]: as windows, a start-up lead (0, O_0) then
    (b_k, O_k - O_{k-1}), so to_wall, with_gaps and to_run_time apply as they
    are. The baseline is converted the same way (one segment: it never
    swaps), so each arm carries its own start-up lag.

    A trial whose rows, start or final run_time are missing, or whose rows do
    not match its logged swaps one-to-one, falls back to the logged downtime
    (``logged``: swap_windows_by_trial), and the printout says so; a baseline
    that was restarted keeps run_time as its wall-clock.

    Returns {"optimized": {trial: windows}, "stops": {trial: its stop windows
    alone}, "lead": {trial: O_0}, "baseline": {trial: windows}}.
    """
    out = {"optimized": {}, "stops": {}, "lead": {}, "baseline": {}}
    log = Path(f".{experiment_id}.log")
    text = log.read_text(errors="replace") if log.is_file() else ""
    launches = Counter(re.findall(
        rf"Started trial {re.escape(exp_dir.name)}-(baseline|optimized)-trial_(\d+) ",
        text))
    online = exp_dir / "optimized" / "online"
    rows: dict[tuple, dict] = {}
    # Every trial's file holds the whole shared list as of its last write;
    # keep the fullest copy of each row.
    for f in [online / "swap_timeline.json", *online.glob("trials/trial_*/swap_timeline.json")]:
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for r in data if isinstance(data, list) else ():
            if isinstance(r, dict) and r.get("trial_id") is not None and r.get("ts"):
                key = (int(r["trial_id"]), float(r["ts"]))
                if len(r) >= len(rows.get(key, {})):
                    rows[key] = r

    def _rt(r):
        try:
            return float((r.get("state_at_swap") or {}).get("run_time"))
        except (TypeError, ValueError):
            return None

    stat = {"old_end": [], "new_end": [], "old_avg": [], "new_avg": [],
            "lead": [], "stats": 0, "measured": 0, "fallback": [],
            "base": [], "base_stats": 0, "base_skip": [], "clamped": 0}
    for m in sorted((exp_dir / "optimized").glob("trial_*/metadata.json")):
        t, tdir = _trial_id(m), m.parent
        try:
            md = json.loads(m.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        start = float(md.get("start_time") or 0.0)
        logd = sorted(logged.get(t, []))
        mine = sorted((r for (tt, _), r in rows.items() if tt == t),
                      key=lambda r: float(r["ts"]))
        end = _end_offset(tdir, md) if start else None
        why = ("no start_time" if not start else
               "no final run_time" if end is None else
               f"{len(mine)} swap_timeline rows vs {len(logd)} logged swaps"
               if (text or logged) and len(mine) != len(logd) else
               "a swap row without run_time" if any(_rt(r) is None for r in mine)
               else None)
        T = end[2] if end else max([x for x, _ in logd] + [0.0])
        if why:
            out["optimized"][t] = out["stops"][t] = logd
            out["lead"][t] = 0.0
            stat["fallback"].append(f"trial_{t:02d} ({why})")
            continue
        xs = _plot_times(tdir)
        offs, exact, bounds = [], [], []
        for r in mine:
            rt = _rt(r)
            b = _stop_run_time(rt, xs)
            if r.get("stats_ts"):
                offs.append(float(r["stats_ts"]) - start - rt)
            else:
                offs.append(float(r["ts"]) - start - b)
            exact.append(bool(r.get("stats_ts")))
            bounds.append(b)
        offs.append(end[0])
        exact.append(end[1] == "fuzzer_stats")
        for k, r in enumerate(mine):
            if (not exact[k + 1] and r.get("resumed_ts") is not None
                    and r.get("resumed_run_time") is not None):
                offs[k + 1] = (float(r["resumed_ts"]) - start
                               - float(r["resumed_run_time"]))
        stops = []
        for k, b in enumerate(bounds):
            d = offs[k + 1] - offs[k]
            stat["clamped"] += d < 0
            stops.append((b, max(d, 0.0)))
        lead = max(offs[0], 0.0)
        out["optimized"][t] = [(0.0, lead)] + stops
        out["stops"][t], out["lead"][t] = stops, lead
        stat["measured"] += 1
        stat["stats"] += end[1] == "fuzzer_stats"
        stat["old_end"].append(sum(d for _, d in logd))
        stat["new_end"].append(lead + sum(d for _, d in stops))
        stat["old_avg"].append(_mean_offset(logd, T))
        stat["new_avg"].append(_mean_offset(out["optimized"][t], T))
        stat["lead"].append(lead)

    for m in sorted((exp_dir / "baseline").glob("trial_*/metadata.json")):
        t = _trial_id(m)
        if launches.get(("baseline", f"{t:02d}"), 1) > 1:
            stat["base_skip"].append(f"trial_{t:02d} (restarted)")
            continue
        try:
            md = json.loads(m.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        end = _end_offset(m.parent, md) if md.get("start_time") else None
        if end is None:
            stat["base_skip"].append(f"trial_{t:02d} (no final run_time)")
            continue
        out["baseline"][t] = [(0.0, max(end[0], 0.0))]
        stat["base"].append(max(end[0], 0.0))
        stat["base_stats"] += end[1] == "fuzzer_stats"

    if report and (out["optimized"] or out["baseline"]):
        mean = lambda v: sum(v) / len(v) if v else 0.0
        n_opt = len(out["optimized"])
        print(f"  axis, {exp_dir.name}: run_time -> wall-clock from MEASURED "
              f"per-segment offsets on {stat['measured']}/{n_opt} online and "
              f"{len(stat['base'])}/{len(stat['base']) + len(stat['base_skip'])} "
              f"baseline trials (last segment from the final fuzzer_stats write "
              f"on {stat['stats'] + stat['base_stats']}, end_time on the rest)")
        if stat["measured"]:
            print(f"    online offset, mean per trial: by the end "
                  f"{mean(stat['old_end']):.1f} s logged downtime -> "
                  f"{mean(stat['new_end']):.1f} s measured (start-up "
                  f"{mean(stat['lead']):.1f} s); run-averaged "
                  f"{mean(stat['old_avg']):.1f} -> {mean(stat['new_avg']):.1f} s")
        print(f"    baseline offset (its start-up lag), mean per trial: "
              f"0.0 -> {mean(stat['base']):.1f} s"
              + (f"; {stat['clamped']} negative stop(s) clamped to 0"
                 if stat["clamped"] else ""))
        if stat["fallback"]:
            print(f"    FALLBACK to the logged swap downtime: "
                  f"{', '.join(stat['fallback'])}")
        if stat["base_skip"]:
            print(f"    baseline left on run_time: {', '.join(stat['base_skip'])}")
    return out


def to_wall(t, windows):
    """run_time -> wall-clock elapsed, adding the downtime accrued before t."""
    t = np.asarray(t, dtype=float)
    shift = np.zeros_like(t)
    for rt, dur in windows:
        shift += np.where(t >= rt, dur, 0.0)
    return t + shift


def to_run_time(wall: float, windows) -> float:
    """wall-clock elapsed -> run_time, the exact inverse of to_wall. An instant
    inside a stopped window maps to the run_time the trial stopped at."""
    acc = 0.0
    for rt, dur in sorted(windows):
        if wall < rt + acc:
            break
        if wall < rt + acc + dur:
            return rt
        acc += dur
    return max(wall - acc, 0.0)


def with_gaps(xs, ys, windows, hold):
    """Insert the stopped intervals: value ``hold`` (0 for rate, flat for total)."""
    xs, ys = list(xs), list(ys)
    pts = sorted(zip(to_wall(xs, windows), ys))
    out_x, out_y = [], []
    walls = []
    acc = 0.0
    for rt, dur in windows:
        w = to_wall([rt], windows[:0])[0] + acc
        walls.append((w, w + dur)); acc += dur
    i = 0
    for x, y in pts:
        while i < len(walls) and walls[i][1] <= x:
            a, b = walls[i]
            last = out_y[-1] if out_y else y
            if hold == "zero":
                # Sample the stop DENSELY. Two endpoint zeros leave every bin in
                # the interior empty, and an empty bin is NaN -- a hole in the
                # aggregate line, not the zero the stop actually was. Spacing
                # must be below the bin width so no interior bin stays empty.
                step = min(GRID[1] - GRID[0], max(b - a, 1e-6)) / 2.0
                zs = list(np.arange(a, b, step)) + [b]
                out_x += zs
                out_y += [0.0] * len(zs)
            else:
                out_x += [a, b]
                out_y += [last, last]
            i += 1
        out_x.append(x); out_y.append(y)
    return np.array(out_x), np.array(out_y)


def band(series, gridded=False, hold_right=False):
    """Per-time-point mean across trials with a t-based 95% confidence interval.

    Trials are interpolated onto a common grid first; ``left/right=nan`` keeps a
    trial from contributing outside its own observed span, so the interval widens
    honestly where fewer trials are still reporting rather than extrapolating.

    ``hold_right`` carries each trial's LAST value forward to the end of the grid
    instead of going NaN. Required for the cumulative-coverage panel, where a
    series' last x is the last DISCOVERY, not the end of the trial: coverage is
    monotonic, so "found nothing after t" must plot as a flat line, not as a
    missing one. Without it a target that saturates early renders as almost
    nothing -- lcms stops discovering at t=0.015s and produced a coverage panel
    with 1 finite point out of 2881, an empty axis that reads as "no data" when
    the truth is "no NEW data". Never set it for a RATE panel, where the absence
    of samples is genuinely unknown rather than unchanged.
    """
    def _row(xs, ys):
        row = np.interp(GRID, xs, ys, left=np.nan,
                        right=(ys[-1] if hold_right and len(ys) else np.nan))
        return row

    m = (np.vstack(series) if gridded else
         np.vstack([_row(xs, ys) for xs, ys in series]))
    mean = np.nanmean(m, axis=0)
    n = np.sum(~np.isnan(m), axis=0)
    with np.errstate(invalid="ignore"):
        sd = np.nanstd(m, axis=0, ddof=1)
    half = np.zeros_like(mean); ok = n > 1
    half[ok] = sd[ok] / np.sqrt(n[ok]) * stats.t.ppf(0.975, n[ok] - 1)
    return mean, mean - half, mean + half, m.shape[0]


def bin_rate(xs, ys):
    """Mean rate within each grid interval, per trial.

    A RATE must be averaged over an interval, not sampled at a point: exec/s is
    logged every second and swings by an order of magnitude between adjacent
    samples, so interpolating at the grid spacing picks an arbitrary sample and
    produces noise that then appears to need smoothing. Rolling-smoothing that
    result is worse than useless here -- the window spans many grid points and
    blurs away the stopped intervals this figure exists to show. Binning gives
    the same legibility honestly: a bin lying inside a gap averages to zero.
    """
    idx = np.digitize(xs, GRID) - 1
    out = np.full(GRID.shape, np.nan)
    ok = (idx >= 0) & (idx < GRID.size)
    if not ok.any():
        return out
    sums = np.bincount(idx[ok], weights=np.asarray(ys)[ok], minlength=GRID.size)
    cnts = np.bincount(idx[ok], minlength=GRID.size)
    nz = cnts > 0
    out[nz] = sums[nz] / cnts[nz]
    return out


def gap_mask(walls):
    """True for grid bins lying inside a stopped/charged window."""
    m = np.zeros(GRID.shape, dtype=bool)
    for a, b in walls:
        m |= (GRID + (GRID[1] - GRID[0]) > a) & (GRID < b)
    return m


def smooth(y, mask, win):
    """Rolling mean applied SEGMENT-WISE, never across a stopped interval.

    Smoothing straight through a gap is what made the earlier figures wrong: the
    window spans the stop, drags neighbouring throughput into it, and the arm
    never appears to halt. Each run of fuzzing bins between two stops is instead
    smoothed on its own, and gap bins are pinned to exactly zero.
    """
    if win < 2:
        return y
    out = np.array(y, dtype=float)
    out[mask] = 0.0
    edges = np.flatnonzero(np.diff(np.r_[True, mask, True].astype(np.int8)))
    for lo, hi in zip(edges[::2], edges[1::2]):
        seg = out[lo:hi]
        good = ~np.isnan(seg)
        if good.sum() < 2:
            continue
        w = min(win, max(good.sum() // 2, 2))
        filled = np.where(good, seg, np.nanmean(seg[good]))
        pad = w // 2
        padded = np.r_[np.full(pad, filled[0]), filled, np.full(pad, filled[-1])]
        sm = np.convolve(padded, np.ones(w) / w, mode="same")[pad:pad + seg.size]
        sm[~good] = np.nan
        out[lo:hi] = sm
    return out


def _windows_for(windows, arm, trial_id, baseline=None):
    """Windows that apply to ONE trial's samples.

    The baseline arm never stops: it gets only its own start-up lag
    (``baseline``, axis_windows), or [] -- run_time as wall-clock -- without
    one. For the online arm, a dict means per-trial optimizers (look up this
    trial); a list is the legacy shared-binary case where one stop applied to
    every trial.
    """
    if arm != "optimized":
        return (baseline or {}).get(trial_id, [])
    if isinstance(windows, dict):
        return windows.get(trial_id, [])
    return windows


def _trial_id(path) -> int:
    m = re.search(r"trial_(\d+)", str(path))
    return int(m.group(1)) if m else -1


def load_coverage(d: Path, windows, baseline=None):
    out = {}
    for arm in ARMS:
        series = []
        for f in sorted(d.glob(f"{arm}_trial_*.csv")):
            xs, ys = [], []
            with open(f) as fh:
                for row in csv.DictReader(fh):
                    xs.append(float(row["time_s"])); ys.append(int(row["cumulative_edges"]))
            if xs:
                w = _windows_for(windows, arm, _trial_id(f), baseline)
                series.append(with_gaps(xs, ys, w, hold="flat"))
        if series:
            out[arm] = series
    return out


def load_execs(exp_dir: Path, windows, baseline=None):
    out = {}
    for arm in ARMS:
        series = []
        for pd in sorted(exp_dir.glob(f"{arm}/trial_*/afl_out/default/plot_data")):
            xs, ys = [], []
            for line in Path(pd).read_text(errors="replace").splitlines():
                if line.startswith("#"):
                    continue
                p = [c.strip() for c in line.split(",")]
                if len(p) < 11:
                    continue
                try:
                    xs.append(float(p[0])); ys.append(float(p[10]))
                except ValueError:
                    continue
            if xs:
                w = _windows_for(windows, arm, _trial_id(pd), baseline)
                series.append(with_gaps(xs, ys, w, hold="zero"))
        if series:
            out[arm] = series
    return out


def _charge_caption(exp_dir: Path, per_trial: bool = False,
                    setup_core_s: float = 0.0,
                    optimizers: int | None = None) -> str:
    """How the plotted optimizer cost was converted to fuzzing time.

    per-replicate charges each trial the FULL optimizer cost (each online trial
    is a replicate of a campaign that would run its own optimizer); as-run
    divides by the arm, which is what this machine actually spent.

    ``per_trial`` wins over the stored charge_model, because under the per-trial
    design per_trial_charge_windows charges each trial its own optimizer's share
    no matter what the ledger recorded. libxml2's ledger says per-replicate while
    the figure charges core_s / 10, so quoting the stored model described a
    quantity 10x the one actually plotted -- the exact failure this caption was
    written to prevent, pointed the other way.

    Setup (``setup_core_s``, per_trial_charge_windows' info) is not charged;
    the caption says so only when there was setup, so a campaign without ccache
    template builds does not mention it at all.
    """
    for f in [exp_dir / "optimized" / "online" / "cpu_cost.json"]:
        if not f.exists():
            continue
        try:
            d = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if per_trial:
            n = optimizers or d.get("optimizers") or 10
            # Kept short: the suptitle is one line, and bbox_inches="tight"
            # widens the whole figure to fit it (13in -> 16in on the first try).
            # Each trial is charged its OWN optimizer's ledger rows, at the
            # finish of the round they belong to (per_trial_charge_windows);
            # the n trials plus the uncharged setup sum to the ledger total.
            return ("as each trial's own optimizer CPU (ledger, per round)"
                    + (f"; setup ({setup_core_s / 3600:.1f} core-h, before trials "
                       f"started) not charged" if setup_core_s > 0 else ""))
        model = d.get("charge_model")
        tc = d.get("trial_cores") or 9
        if model == "per-trial-optimizer":
            # Measured, not divided: this trial's own session wall time scaled
            # by the ledger's CPU/wall ratio. Saying "total / N" would describe
            # an average the windows do not use -- the trials differ by ~12%.
            return "as THIS trial's own optimizer CPU (measured), per-trial-optimizer"
        if model == "per-replicate":
            return "in full to every replicate (per-replicate)"
        if model == "as-run":
            return f"as core-seconds / {tc} trials (as-run)"
        return f"as core-seconds / {tc} trials (legacy file, model unrecorded)"
    return "(charge model unknown)"


def cpu_cost(walls, wall_charge):
    """Running total of the charge THIS FIGURE APPLIES, on THIS FIGURE's axis.

    Built from the same windows the grey bands are drawn from rather than
    re-read from the ledger, so the overlay is by construction the cumulative
    area of the grey. Reading cpu_cost.json straight got all three of these
    wrong, in one panel:

      * Charge model. The ledger records charge_model=per-replicate, i.e.
        core_s undivided -- the whole arm's ten optimizers. The x-shift and the
        bands charge ONE optimizer's share (core_s / optimizers), so the overlay
        ran 10x the cost the rest of the panel was drawn from: a 3336-minute
        curve beside a 323-minute charge.
      * Clock. xs came from the first ROUND's t_start, while the arms start from
        the first TRIAL's start_time (301 s later on libxml2), and were never
        shifted although the arm curves are stretched right by the charge.
      * Ordering. summarize() buckets by iter and takes t_end = max over the
        round's rows. The orchestrator-side stages (profile_prebuild, rebuild,
        replay_gate) all carry iter 0, so iter 0's bucket spans the WHOLE
        campaign and its t_end IS the campaign end. Plotted in iter order with
        where="post", the first segment therefore ran BACKWARDS from 24.1h to
        5.2h; the long flat dash at 440 min in the old figure was that artifact,
        not a plateau.

    Each window's cost accrues LINEARLY across its own span instead of stepping
    at a single instant: the CPU was burned over that interval, and a ramp is
    monotone by construction, so nothing needs sorting and no segment can run
    backwards. Cost falling past the 24 h edge is clipped exactly as the arm
    tails are.
    """
    ys = np.zeros_like(GRID)
    for (a, b), c in zip(walls, wall_charge):
        if c <= 0:
            continue
        ys += np.clip((GRID - a) / max(b - a, 1e-9), 0.0, 1.0) * c
    return (GRID, ys) if ys.any() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--covdir", default="coverage_growth")
    ap.add_argument("--outdir", default="plots")
    ap.add_argument("--no-charge-cpu", dest="charge_cpu", action="store_false",
                    help="show only the stopped-for-swap gaps, without charging "
                         "the optimizer's CPU as lost fuzzing time")
    ap.add_argument("--bands", action="store_true",
                    help="shade the median trial's charge windows and pin the "
                         "optimized throughput to zero inside them. Off by "
                         "default: the ten trials pay at different instants, so "
                         "one trial's windows zero an aggregate that was still "
                         "fuzzing. The green overlay marks the same windows "
                         "without overwriting the data.")
    ap.add_argument("--smooth", type=int, default=9,
                    help="throughput smoothing window in 30 s bins (default 9 = "
                         "4.5 min); applied within fuzzing segments only, never "
                         "across a stopped interval. 0 disables.")
    args = ap.parse_args()

    root = Path(config.RESULTS_DIR) / args.experiment_id
    project = args.experiment_id.rsplit("-", 1)[-1]
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    by_trial = swap_windows_by_trial(args.experiment_id)
    swaps = swap_windows(args.experiment_id)          # union, for CPU bookkeeping

    for exp_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        # Optimizer CPU, charged to the online arm. Unlike a swap stop this is
        # campaign-wide (the optimizer's core could have been fuzzing at that
        # instant for ANY trial), so it stays on one shared timeline.
        charge = (cpu_charge_windows(exp_dir, project, swaps)
                  if args.charge_cpu else [])
        per_trial_charged = False
        pt_info: dict = {}
        stops, lead, base_axis = {}, {}, {}

        # Per-trial design: each trial's own stops shift only its own samples.
        # The shared CPU charge is added to every online trial on top of that.
        if by_trial:
            # Each trial's run_time -> wall conversion, MEASURED per segment
            # rather than summed from the logged swap downtime (axis_windows):
            # samples, stops and charges all go through it.
            axis = axis_windows(exp_dir, args.experiment_id, by_trial)
            stops, lead, base_axis = axis["stops"], axis["lead"], axis["baseline"]
            own = {t: axis["optimized"].get(t, by_trial.get(t, []))
                   for t in set(by_trial) | set(axis["optimized"])}
            # Each trial charged ITS OWN optimizer, not a share of the campaign.
            pt = (per_trial_charge_windows(exp_dir, own, info=pt_info)
                  if args.charge_cpu else {})
            per_trial_charged = bool(pt)
            if pt:
                # Union of both key sets: by_trial lists only trials with at
                # least one HOT-SWAP line in the log, so a trial whose every
                # round was rejected still ran (and paid for) its optimizer --
                # keyed on by_trial alone it was plotted uncharged.
                windows = {t: sorted(own.get(t, []) + pt.get(t, []))
                           for t in set(own) | set(pt)}
                # Bands: the per-trial charges land at different instants, so
                # shade the MEDIAN trial's windows as the representative case
                # and say so in the caption. Shading all ten would overlap into
                # a solid block that implies every trial paid at every moment.
                med = sorted(pt, key=lambda t: sum(d for _, d in pt[t]))[len(pt)//2]
                charge = pt[med]
            else:
                windows = {t: sorted(w + charge) for t, w in own.items()}
            # Bands: draw the CHARGE only. A per-trial stop is ~16s against a
            # 24h axis -- under half a pixel -- and ten trials stop at ten
            # different instants, so there is no common interval to shade. The
            # old single-timeline bands would have implied a synchronised stop
            # that never happened.
            band_windows = sorted(charge)
        else:
            windows = sorted(swaps + charge)
            band_windows = windows
        # Two kinds of band share one list: a hot-swap stop is real downtime and
        # costs no CPU, a charge band IS the CPU. Only the latter may feed the
        # cumulative-cost overlay, so carry the split alongside the geometry.
        # Placed on the axis of the trial they belong to: every earlier window
        # of THAT trial -- start-up, stops, charges -- delays them, not only
        # the earlier charges (which left them up to ~20 min early on r2 bloaty).
        charged = {(rt, dur) for rt, dur in charge}
        shown = set(band_windows)
        walls, wall_charge, acc = [], [], 0.0
        for rt, dur in (windows[med] if per_trial_charged else band_windows):
            if (rt, dur) in shown:
                walls.append((rt + acc, rt + acc + dur))
                wall_charge.append(dur if (rt, dur) in charged else 0.0)
            acc += dur

        # Match coverage_growth.py's experiment-namespaced layout, falling back
        # to the flat CVE-only path so campaigns replayed before the rename
        # still plot.
        covdir = Path(args.covdir) / args.experiment_id / exp_dir.name
        if not covdir.is_dir():
            covdir = Path(args.covdir) / exp_dir.name
        cov = load_coverage(covdir, windows, base_axis)
        exe = load_execs(exp_dir, windows, base_axis)
        if not cov and not exe:
            continue

        # The mask and the shading are the SAME statement about one trial, so
        # they travel together: without the bands drawn, zeroing the aggregate
        # would assert a stop the figure no longer shows.
        gmask = (gap_mask(walls) if args.bands
                 else np.zeros(GRID.shape, dtype=bool))
        # Stacked, sharing the wall-clock axis: coverage and throughput are read
        # against the same instants (a swap gap, a round landing), and that
        # correspondence is what a side-by-side layout makes the reader do in
        # their head.
        fig, axes = plt.subplots(2, 1, figsize=(13, 9.2), sharex=True)
        for ax, data, ylab, title in (
            (axes[0], cov, "Cumulative edges (replayed on baseline binary)",
             "Coverage growth — common instrument\nmean ± 95% CI across trials"),
            (axes[1], exe, "Executions / second",
             "Throughput as actually run\nmean ± 95% CI across trials"),
        ):
            for a, b in (walls if args.bands else ()):
                ax.axvspan(a / 3600, b / 3600, color="#999999", alpha=0.35, lw=0)
            for arm, (colour, label) in ARMS.items():
                if arm not in data:
                    continue
                if data is exe:
                    mean, lo, hi, n = band([bin_rate(xs, ys) for xs, ys in data[arm]],
                                           gridded=True)
                    # Mask per ARM. gmask marks the ONLINE arm's stopped/charged
                    # windows, and smooth() pins masked bins to exactly zero --
                    # so sharing one mask blanked the BASELINE's throughput for
                    # the duration of a cost it never paid (893 min of assimp's
                    # 1440, i.e. most of the run read as "baseline not fuzzing").
                    # load_execs already withholds the windows from the
                    # baseline's data; this withholds them from its rendering.
                    amask = (gmask if arm == "optimized"
                             else np.zeros_like(gmask, dtype=bool))
                    mean, lo, hi = (smooth(mean, amask, args.smooth),
                                    smooth(lo, amask, args.smooth),
                                    smooth(hi, amask, args.smooth))
                else:
                    # Cumulative coverage: hold the last value to the grid end.
                    mean, lo, hi, n = band(data[arm], hold_right=True)
                ax.plot(GRID / 3600, mean, color=colour, label=f"{label} (n={n})")
                ax.fill_between(GRID / 3600, lo, hi, color=colour, alpha=0.25)
            # Only the lower panel is labelled: the axis is shared, so repeating
            # it above just crowds the gap between the two plots.
            if ax is axes[-1]:
                ax.set_xlabel("Wall-clock time (hours)")
            ax.set_ylabel(ylab)
            ax.set_title(title, fontsize=10); ax.grid(alpha=0.3); ax.set_xlim(0, HOURS)
            # exec/s cannot be negative; the CI's normal approximation can dip
            # below zero at high variance, so crop the view rather than the data.
            if data is exe:
                ax.set_ylim(bottom=0)
        axes[0].legend(loc="lower right"); axes[1].legend(loc="upper right")

        cc = cpu_cost(walls, wall_charge)
        if cc is not None:
            ax2 = axes[1].twinx()
            # plot, not step: the cost accrues ACROSS each band rather than
            # landing at one instant, and a ramp cannot be drawn out of order.
            ax2.plot(cc[0] / 3600, cc[1] / 60, color="#55A868",
                     linestyle="--", linewidth=1.6,
                     label="optimizer CPU charged (median trial, cumulative)")
            ax2.set_ylabel("Cumulative optimizer cost (minutes of fuzzing)", color="#55A868")
            ax2.tick_params(axis="y", labelcolor="#55A868")
            ax2.set_ylim(bottom=0)
            ax2.legend(loc="lower right", fontsize=8)

        # Per-trial mode: report the MEDIAN trial, because there is no single
        # campaign-wide figure any more -- each trial stopped on its own
        # schedule and paid its own optimizer. A total would describe a run
        # nobody performed.
        if isinstance(windows, dict):
            # Stops as measured (axis_windows), the start-up lead left out: the
            # baseline waits through its own.
            per_swap = {t: sum(d for _, d in stops.get(t, by_trial.get(t, [])))
                        for t in windows}
            per_all = {t: sum(d for _, d in w) - lead.get(t, 0.0)
                       for t, w in windows.items()}
            mt = sorted(per_all, key=lambda t: per_all[t])[len(per_all)//2]
            swap_s, cpu_s = per_swap[mt], per_all[mt] - per_swap[mt]
            n_swaps = len(stops.get(mt, by_trial.get(mt, [])))
            who = f" (median trial_{mt:02d} of {len(windows)})"
        else:
            swap_s = sum(d for _, d in swaps)
            cpu_s = sum(d for _, d in windows) - swap_s
            n_swaps = len(swaps)
            who = ""
        fig.suptitle(
            f"{exp_dir.name}{who} — online arm charged for its own cost: "
            f"{swap_s/60:.1f} min stopped for {n_swaps} hot swaps"
            # Read the charge model from the ledger rather than hardcoding a
            # divisor: cpu_cost.json records which model produced
            # fuzz_seconds_equivalent, and a stale "÷ 9 trials" caption on a
            # per-replicate number is a lie about the very quantity plotted.
            + (f" + {cpu_s/60:.1f} min optimizer CPU (profile / rebuild / replay), "
               f"charged {_charge_caption(exp_dir, per_trial_charged, **pt_info)}"
               if args.charge_cpu else "")
            # Both tails stay short: the suptitle is one line and
            # bbox_inches="tight" widens the whole figure to fit it.
            + (".  Grey bands = median trial not fuzzing."
               if args.bands else ".  Green = where that cost is paid."),
            fontsize=9)
        fig.tight_layout()
        # Same reason as the CSV path: name by experiment so a second campaign
        # on one target cannot overwrite the first's figure.
        path = outdir / f"{args.experiment_id}_{exp_dir.name}_coverage_execs.png"
        fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
        print(f"  wrote {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
