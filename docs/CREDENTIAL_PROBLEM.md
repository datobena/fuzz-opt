# The Credential Problem

*Written 2026-08-21, after the b3r4 run logged you out.*

## TL;DR

Your Claude login and the benchmark's two sandboxes all authenticate as **one identity**.
That identity's refresh token **rotates**: every refresh mints a new one and *revokes the
old one server-side*. Three independent clients on one rotating token means whoever
refreshes last silently kills the others.

There are **two different symptoms** of this one cause:

| # | Symptom | Who suffers | Status |
|---|---------|-------------|--------|
| A | The sandbox store goes dead, every later optimizer round fails | the campaign | **fixed** |
| B | Your own `claude` login stops working | you | **not fixed — and not fixable locally** |

I fixed A and told you the credential problem was handled. That was wrong: A and B are
different problems, and B is the one you actually complained about.

---

## 1. What is actually in the credential file

`~/.claude/.credentials.json`, measured from your real file:

```
file written     2026-08-21 22:17:05
accessToken      expires 2026-08-22 06:17:05    lifetime  8.00 hours
refreshToken     expires 2026-09-19 00:08:32    lifetime 28.1 days
```

Two tokens with very different jobs:

- **accessToken** — sent on every API call. Short-lived by design (8 h).
- **refreshToken** — never sent to the API. Used *once*, to mint a fresh pair.

### The refresh, and the part that causes all the trouble

```
        refreshToken_N
              │
              ▼
     ┌──────────────────┐
     │  POST /oauth/... │
     └──────────────────┘
              │
              ├──► accessToken_N+1     (new, 8 h)
              ├──► refreshToken_N+1    (new, 28 days)
              │
              └──► server REVOKES refreshToken_N     ◄── "rotation"
```

That last line is the whole story. This is called **refresh-token rotation**, and it is a
deliberate security feature: if someone steals your refresh token, it becomes useless the
moment the real client refreshes. It assumes **exactly one client holds the token**.

---

## 2. Why this never bothers you on your own machine

One client, one chain:

```
  t=0h        t=8h        t=16h       t=24h              t=28 days
   R0 ───────► R1 ───────► R2 ───────► R3 ─── … ───────► re-login
        ▲            ▲           ▲
        └────────────┴───────────┴── each refresh: client keeps the NEW token
```

Nothing else holds a copy, so nothing else is ever revoked out from under you.
You log in about once a month, when the refresh token itself ages out.

---

## 3. What the benchmark does instead

```
                 ~/.claude/.credentials.json          ← YOUR login
                              │
                              │  egress.seed_store()
                              │  (copies host → store when host is newer)
                              ▼
                 .sandbox-creds/claude.json           ← the "store"
                        │                │
    stage_credentials() │                │ stage_credentials()
       (writable copy)  │                │  (writable copy)
                        ▼                ▼
              ┌──────────────────┐  ┌──────────────────┐
              │  lcms sandbox    │  │  yara sandbox    │
              │  own copy of     │  │  own copy of     │
              │  the credential  │  │  the credential  │
              └──────────────────┘  └──────────────────┘
```

Each sandbox gets its **own file**, so they never fight over the file on disk. That was the
original design intent, and it is documented in `sandbox/egress.py`:

> *"A copy, mounted writable, so the CLI can refresh without racing other sessions on one
> shared file."*

**But separate files do not create separate identities.** All three copies carry the *same*
refresh token. The server sees one chain, not three files. So the copies solve *file
contention* and do nothing about *lineage contention* — which is the real problem.

And crucially, the two sandboxes **run at the same time**. Measured from b3r4:

```
  lcms r1: 21:48:56 ──────────► 22:24:04
  yara r1:   21:49:50 ──────────────► 22:43:57      overlap: 34.2 min
                    ^^^^^^^^^^^^^^^^^
                    both sandboxes live, both able to refresh
```

7 of b3r4's 8 yara rounds overlapped an lcms round.

---

## 4. What actually happened in b3r4 (the run that logged you out)

The failure took **2.6 seconds**. That is far too fast to be a refresh timing out — the
credential was *dead on arrival*. Here is the sequence, from the logs:

```
 15:58:56   lcms stages a copy of the store            store holds token N
 15:58:58   store rewritten by seed_store()            (host copy was newer)
    ...     lcms's CLI refreshes inside its sandbox    mints N+1, server REVOKES N
 16:09:20   yara stages a copy of the store            store STILL holds N  ← stale!
 16:09:23   yara dies instantly                        N was revoked 10 min ago
 16:17:31   lcms finally harvests N+1 into the store   too late for yara
```

The trap is the gap between **16:09:20** and **16:17:31**: lcms had already rotated the
token, but had not yet written the new one back. For those ~19 minutes the store was a
loaded gun — it *looked* perfectly valid and was in fact revoked.

Proof it was revoked rather than expired — the store's own timestamps at the moment yara died:

```
  store file written    15:58:58
  store says expiresAt  23:58:58
  yara failed at        16:09:23   →  the file claimed +7.83 h of remaining validity
```

The local file said "valid for another 8 hours". The server said no. **`expiresAt` is just a
claim written in a JSON file; only the server knows if a token is still alive.**

---

## 5. Why *you* got logged out — the asymmetry

This is the part I never addressed. Look at where a refreshed token goes:

```
   sandbox refreshes
          │
          ├──► new token N+1 written into  .sandbox-creds/claude.json   ✔ store updated
          │
          └──► ~/.claude/.credentials.json                              ✘ NEVER written
                        │
                        └── still holds token N ── which the server just revoked
```

`harvest_credentials` is explicit about this:

> *"The HOST credential is never written. The sandbox reads it once and then keeps its own
> lineage."*

That rule exists for a good reason — so a misbehaving sandbox cannot corrupt your real
login. But it has an unavoidable consequence:

**Your host file can never learn that a rotation happened.** It keeps a token that looks
fine and is silently dead. You don't find out until the next time you run `claude`, which
is exactly what you saw:

```
  Login expired · Please run /login
```

So the protection ("never touch the user's credential") is precisely what *guarantees* you
get logged out. The sandbox refreshing is enough to kill your session; nothing on this
machine can prevent that, because the revocation happens on Anthropic's servers the
instant the refresh succeeds.

---

## 6. What I fixed, and what it was actually for

### The bug I found (real, and worth fixing)

When a refresh *failed*, the CLI rewrote its credential with `expiresAt: 0`. Two functions
then conspired to make that permanent:

```
  1. harvest_credentials()  compared only FILE MTIME
     → the dead copy was newer → it overwrote a WORKING store credential

  2. _credential_expiry()   saw expiresAt: 0, treated it as "absent",
                            and FELL BACK TO MTIME
     → a just-written dead file ranked as the FRESHEST thing on disk
     → seed_store() concluded the store was newer than the host
     → refused to heal, forever
```

One unlucky refresh permanently bricked the campaign. In b3r2 the store sat at
`expiresAt: 0` from 18:46 onward and **every** later round failed with *"no fresher
credential is available"* — while the refresh token underneath was still valid for
another 12 days.

### The fix

- `harvest_credentials` now validates *content*: a credential with no valid expiry is
  never written back.
- `_credential_expiry` now sorts a dead OAuth credential as **oldest**, so `seed_store`
  heals from the host instead of protecting the corpse.

### Did it work?

Yes — for what it covers. In b3r4 you can watch it fire correctly:

```
  16:09:23  not harvesting claude: the session's credential has no valid expiry
            (a failed refresh, not a new token)
```

The dead copy was refused, the store stayed healthy, and the campaign lost **one round out
of eight** instead of its entire back half.

### Why it did nothing for you

The guard is about **store integrity** — keeping the *campaign's* credential usable. Your
logout is caused by **server-side revocation**, which happens the moment any sandbox
refreshes. No local guard can undo a revocation that already happened remotely.

I fixed the blast radius inside the pipeline and then described the credential problem as
solved. The campaign surviving is not the same as you staying logged in.

---

## 7. Evidence across the three runs

| Run | Fix present | Auth errors | Rounds lost | You logged out? |
|-----|-------------|------------:|------------:|-----------------|
| **b3r2** | none | 7 | **7 of 19** | yes |
| **b3r3** | poisoning guard | 0 | 0 | (not observed) |
| **b3r4** | poisoning guard | 1 | **1 of 17** | **yes** |

The guard clearly reduced campaign damage (7 rounds → 1 round). It had **no effect on the
logout**, because it was never aimed at it.

---

## 8. Why "just retry" isn't enough

The pipeline already retries once per round (`_reseed_credentials_after_auth_failure`).
It works when the *store* has a good token. It cannot work when the token generation the
sandbox needs has already been rotated away — there is nothing fresher to re-seed *from*,
because the only fresher copy is inside the other sandbox's still-running session.

---

## 9. The options, stated honestly

The root cause is **one identity, three refreshers**. Everything else is damage control.

### Option 1 — a second Claude account for the sandbox *(recommended)*

```
  ~/.claude/.credentials.json      ← account A (you)          chain A
  .sandbox-creds/claude.json       ← account B (benchmark)    chain B
```

Two chains that never touch. You are never logged out; the sandboxes cannot revoke you.
Keeps subscription billing. Cost: one more account to hold.

### Option 2 — API key for the sandbox *(you ruled this out)*

No expiry, no refresh, no rotation. The failure class disappears entirely. Requires
metered API billing instead of your subscription. Code support is already written and
tested, and is inert unless `ANTHROPIC_API_KEY` is set.

### Option 3 — serialize the two projects

Run lcms and yara in sequence rather than concurrently. Removes sandbox-vs-sandbox
collisions but **not** host-vs-sandbox: your own `claude` use still rotates the token and
still gets revoked. Costs 48 h per batch instead of 24 h. **Does not solve your logout.**

### Option 4 — accept it

Roughly one logout per 24 h run, plus the occasional lost round. This is where we are now.

---

## 10. What I should have said earlier

When you asked *"why can't sandboxed runs last a month like local?"*, the correct answer
was:

> They can — but only if the sandbox has its **own identity**. Sharing yours means every
> sandbox refresh revokes your login, and no amount of local code can prevent that,
> because the revocation happens on the server.

Instead I fixed the store-poisoning bug, watched the campaign survive, and reported the
problem as solved. The two symptoms have one cause but different cures, and I conflated
them.
