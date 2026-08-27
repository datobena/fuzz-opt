# Sandbox credentials: how they flow, and why they keep breaking

Written 2026-08-21, after three campaigns lost optimizer rounds to authentication
failures (b3, b3r, b3r2).

---

## 1. The problem in one sentence

The optimizer agent runs inside a sandbox container and needs to log in as you —
so we make **copies** of your login. OAuth logins cannot be safely copied, and
every failure so far is a consequence of that.

---

## 2. Two kinds of token

Your credential file (`~/.claude/.credentials.json`) holds two different things.
Confusing them is what makes this topic hard:

| | lifetime | what it does |
|---|---|---|
| **access token** | ~8 hours | Sent with every API call. The server checks it. |
| **refresh token** | 28 days | Used **only** to obtain a new access token. |

Real values from your file:

```
accessToken            expiresAt              +7.0 h
refreshToken           refreshTokenExpiresAt  +672.9 h  (28 days)
```

### Rotation — the critical rule

When a refresh token is used, the server **issues a new one and destroys the old
one**. This is called *rotation*.

```
holder presents RT1  ->  server returns AT2 + RT2, and RT1 is now dead forever
```

This is a security feature: a stolen refresh token can only be used once before
the theft becomes obvious. But it has a consequence that matters enormously here:

> **Only one holder can ever use a given refresh token. The moment anyone
> refreshes, every other copy of THAT REFRESH TOKEN is dead.**

Rotation applies to the refresh token **only**. It does *not* touch access tokens
that were already issued — those keep working until their own expiry. This
distinction is the single most confusing thing here, so, concretely:

Everyone starts holding the same file `{AT1, RT1}`. lcms refreshes, presenting
`RT1`, and receives `{AT2, RT2}`.

| holder | access token | refresh token | can it work? |
|---|---|---|---|
| lcms (refreshed) | AT2 valid | RT2 valid | fully working |
| yara / store / host | AT1 **still valid** | RT1 **dead** | works until AT1 expires, then stuck |

A copy left behind is therefore **alive but terminal**: it keeps making API calls
normally until its access token runs out, and only then discovers it cannot renew.

That is why the failures look the way they do in the logs:

- sessions ran 45-60 min to completion across host refreshes — they were using an
  access token, which a refresh elsewhere never touches
- every auth failure landed at **0.0 min, at startup** — the CLI found its access
  token expired and reached for a refresh token another holder had already burned

If refreshing killed outstanding access tokens, sessions would have died
mid-flight. In six campaigns, not one did.

---

## 3. The three copies

There is not one credential on this machine. There are three, in a chain:

```
  1. HOST      ~/.claude/.credentials.json
               your real login. Your own Claude CLI refreshes this on its own schedule.
                     |
                     |  seed_store()          copies down only if host is strictly newer
                     v
  2. STORE     fuzz-opt/.sandbox-creds/claude.json
               the sandbox's persistent copy. Exists because sessions are ephemeral.
                     |
                     |  stage_credentials()   fresh copy per session
                     v
  3. SESSION   <session_dir>/creds/claude.json
               mounted WRITABLE into the agent container, so the CLI can refresh.
                     |
                     |  harvest_credentials() folds back up, at session END only
                     +--------> back into the STORE
```

**Why the store exists:** agent containers are `docker run --rm` — created for one
optimizer round (~45 min), destroyed after. If the CLI inside refreshes its token,
that new token would die with the container. The store is where a sandbox-side
refresh gets remembered for the next round.

**Why the session copy is writable:** the CLI must be able to rewrite the file when
it refreshes. A read-only mount works until the first expiry, then fails.

Code: `sandbox/egress.py` — `CREDENTIAL_STORE` (line 58), `seed_store`,
`stage_credentials` (line 244), `harvest_credentials`.

---

## 4. Why copying breaks

Put sections 2 and 3 together:

- The rule says **only one holder can use a refresh token.**
- The design creates **three or more holders**: your host CLI, the store, and one
  writable copy per concurrent session.

Two projects run concurrently (lcms and yara), so two containers each hold a copy
of the same refresh token, for the full length of their sessions:

```
lcms r1 [04:07-04:33]  vs  yara r1 [04:07-04:52]   overlap 26 min
lcms r2 [06:38-07:14]  vs  yara r2 [06:57-07:47]   overlap 17 min
lcms r6 [16:21-16:34]  vs  yara r5 [15:41-16:40]   overlap 13 min
```

For 13–26 minutes every round, two containers hold the same RT1. Whichever CLI
refreshes first turns RT1 into RT2 server-side — and at that instant the other
container's copy, the store's copy, and your host's copy are all dead paper.

There is **no locking** anywhere in the credential path.

---

## 5. What actually happened: three distinct failures

Three separate bugs, all growing from the same root. Fixing one revealed the next.

### Failure 1 — the refresh endpoint was blocked (campaigns b3, b3r)

The sandbox reaches the internet only through an allowlisting proxy. The CLI
refreshes its token against `platform.claude.com`, which was **not on the
allowlist** — the list named `console.anthropic.com`, which predates it.

```
21x  DENY platform.claude.com:443 (not allowlisted)

12:40:49  first DENY
12:50:54  first "401 OAuth access token has expired"
```

The access token expired ~12 h in, the CLI tried to renew, the proxy refused, and
every round after that died instantly.

**Fixed:** added `platform.claude.com` to `DEFAULT_ALLOWLIST` in
`sandbox/egress_proxy.py`. Confirmed working in b3r2 — 4 ALLOWs, 0 DENYs.

*This fix was necessary but not sufficient. It removed a network block; it did
not address why a refresh was being rejected.*

### Failure 2 — the store got poisoned (campaign b3r2)

With the endpoint reachable, the refresh request now arrived at the server and was
**rejected** — because the token had been rotated away by another holder. The error
text changed accordingly:

```
before:  API Error: 401 OAuth access token has expired      (never asked)
after:   OAuth session expired and could not be refreshed   (asked, refused)
```

Then the damage compounded:

1. On a failed refresh, the CLI **rewrites the credential file with `expiresAt: 0`**
   — a wreck, not a token.
2. `harvest_credentials()` folded that wreck **up into the store**, overwriting a
   working credential.
3. Recovery had to come from the host. `seed_store()` picks the fresher of the two
   by comparing `expiresAt` — but when `expiresAt` was `0`, the old code fell
   through to **file mtime**. The wreck had just been written, so its mtime was the
   newest on disk.
4. The broken copy therefore **ranked as the freshest credential in the system.**
   Every later round refused to re-seed from the good host copy.

```
18:46  store poisoned
18:46 -> 03:03  every round: "no fresher credential is available", session dies in 0.0 min
       meanwhile the refresh token underneath was valid for another 12 days
```

**Fixed** (in `sandbox/egress.py`, not by me):
- `harvest_credentials` refuses to fold back a credential with `expiresAt <= 0`.
- `_credential_expiry` returns `0` for an OAuth-shaped file with no valid expiry,
  so a wreck sorts as *oldest* and the host copy wins.

### Failure 3 — cross-session rotation (structural, still open)

This is the root cause, and nothing above fixes it. Two concurrent sessions hold
copies of the same refresh token (section 4). The observed pattern:

```
18:37  lcms session starts, staged with RT1 from the store
~18:4x lcms's CLI refreshes: RT1 -> RT2.  RT1 is now dead server-side.
       lcms holds RT2 in its own session dir. The STORE still holds RT1.
18:46  yara's round starts, stages from the store -> receives dead RT1
       -> "could not be refreshed", session dies at startup
18:54  lcms finishes and harvests RT2 into the store, 8 minutes too late
```

**Caveat:** the refresh happens inside the container, so the orchestrator never
logs it. The structure (shared rotating token, no lock, 13–26 min overlaps) is
established; this exact ordering is inference from timing, not proof.

Note that `harvest_credentials` cannot close this, because it writes back only at
session **end** — any session starting during another's run may read a store that
went stale minutes ago.

---

## 6. Two ideas that don't work, and why

### "Symlink the sandbox credential to the real one"

The appeal is real: a new session would resolve the link at container start and
always get the current token. (My first objection — that bind-mounted files don't
see host updates — was wrong for *ephemeral* containers, which is the case here.)

It still fails:

- The mount must be **writable**, so you hand an untrusted agent write access to
  your real credential.
- You'd have **three unsynchronized writers** on one file: two sandboxes and your
  host CLI. The per-session copy exists specifically "so the CLI can refresh
  without racing other sessions on one shared file."
- Docker resolves a symlink at mount time, so the container gets your real file
  directly — there's no indirection left inside.
- It doesn't address rotation at all. Sharing the token *harder* is not a fix.

### "Edit `expiresAt` so it never expires"

`expiresAt` is a **local note about** the token, not the thing granting access. The
server validates the token itself and never reads your file. Editing it is like
changing the date written on a photocopy of a passport.

It makes things strictly worse:

- The CLI would believe the token is fine and **skip refreshing**, then send a dead
  token and get a 401.
- A forged far-future expiry outranks every real credential in
  `_credential_expiry()` **forever**, so `seed_store` would never re-seed from the
  host again. That's Failure 2, made permanent and unrecoverable.

---

## 7. The fix

**Give the sandbox an access token and no refresh token.**

```python
# in stage_credentials(), after copying:
blob["claudeAiOauth"].pop("refreshToken", None)
```

Nothing inside a container can then rotate anything. Every failure above stops
being possible:

| failure | why it can't happen |
|---|---|
| blocked refresh endpoint | the sandbox never refreshes |
| poisoned store | a failed refresh is what writes `expiresAt: 0` |
| cross-session rotation | no session holds a rotatable token |

Three supporting pieces:

1. **Freshness gate.** Only hand out a token with **> 5 h** remaining
   (4 h optimizer backstop + 1 h margin). Sessions observed at 13–60 min, so a
   token that outlives the backstop cannot expire mid-session.
2. **Host is the sole refresher**, serialized behind an `flock` — acquire, *re-check
   remaining life*, refresh only if still needed, release. The re-check is what
   makes N orchestrators safe: losers wake, see a fresh token, and skip refreshing.
3. **The store can be simplified.** It exists only to carry sandbox-side refreshes
   between rounds. With no sandbox-side refresh, per-round copies from the host are
   sufficient, and `harvest_credentials` becomes unnecessary.

### The one unknown

**Does the CLI start with a credential file that has no `refreshToken` field?**
Unverified. It might validate the shape at startup. This is cheap to test — build a
stripped credential, run the CLI in the agent image, see whether it authenticates.
Everything above depends on it.

Fallback if it refuses: keep the field but blank it; failing that, host-side
refresh on a timer with the sandbox still holding a real refresh token — which only
narrows the race window rather than closing it.

### Alternative that sidesteps all of it

Give the sandbox **its own credential** — a separate account, or an API key
(`ANTHROPIC_API_KEY`, which never expires or rotates). No shared lineage, no race,
nothing to strip. Requires wiring: the key appears nowhere in `sandbox/` today, and
`ENV_ALLOWLIST` (`sandbox/launch.py:48`) forwards only `FUZZ_SOURCE_FOLDS_*`.

---

## 8. Cost so far

| campaign | rounds lost to auth | notes |
|---|---|---|
| b3 (lcms) | 1 of 6 | |
| b3r (yara) | 2 of 7 | |
| b3r2 (lcms) | 3 of 10 | last 8 h of a 24 h run |
| b3r2 (yara) | 4 of 9 | after 5 consecutive accepted rounds |

Each lost round reads in the results as "the optimizer found nothing," which is
indistinguishable from a genuinely unproductive round unless you read the logs.
That is the real cost: not machine time — the sessions died in 0.0 minutes — but
**silently degraded experimental results.**
