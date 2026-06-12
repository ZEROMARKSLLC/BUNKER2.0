# BUNKER 2.0 — Code Review Council Report, Round 2

**Date:** 2026-06-12
**Subject:** Review of branch `claude/mobile-version-check-3p4gat` (8 commits, ~+1,766/−309 vs `main`) — the parallel team's security rework — including a head-to-head comparison with this branch's P0 fixes (`claude/code-review-council-7s0d1i`).
**Method:** Three independent review seats run in parallel — Cryptography & Migration Safety, Correctness & Regression, Tests/CI/Packaging — all read-only against a detached worktree; findings verified empirically (their test suites executed on Python 3.10/3.12/3.13; migration paths replayed against copies of the committed demo vault).

---

## Council verdict

**Adopt `mobile-version-check-3p4gat` as the base for the data-loss/security work — it is the better-engineered branch — but it is NOT mergeable as-is.** Three blockers must land first, and five of the six user-facing feature bugs it implicitly claims to cover are in fact still broken. This branch supersedes the P0 fixes on `code-review-council-7s0d1i`; two specific deltas from our branch should be ported on top.

What the branch verifiably gets right:

- Every legacy vault class still opens — verified empirically, not from the diff: vaults created by `main`'s code open via the legacy pepper fallback (2 KDF runs), the committed demo vault opens with `rootroot`, and old static-key `config.cfg` files migrate cleanly to the new device-key scheme on first run.
- Destruction is now gated at the primitive (`self_destruct(force=False)` is a loud no-op; exactly one `force=True` call site — max failed logins — pinned by a sentinel test), not just at call sites.
- `_atomic_write` is the strongest writer either team produced: same-dir mkstemp → fsync → rolling `.bak` → `os.replace` → directory fsync, with a pre-publish round-trip decrypt in `saveDatabase`, and all ~10 inline save sites deduplicated through a return-checked call.
- Real tests (12 sentinels + 30 behavioral checks, including a SIGKILL-mid-save crash test), a working GitHub Actions workflow with a clever guard against test pollution of the tracked demo vault, a complete `requirements.txt`, and genuine Python 3.10–3.13 compatibility (the 3.12-only f-string is fixed and proven in CI).

---

## Blockers (must fix before merge)

### BLOCKER 1 — Max-attempts wipe destroys the `.bak` recovery files (Critical, data loss)
The branch's own crash-recovery story defeats itself. Rotation order is DB → salt → config; after a crash between the salt and config writes, the **old** password recovers via the `bunker.salt.bak` fallback without burning attempts — but the **new** password (the one the user just chose and will naturally type) fails to open `bunker.cfg`, burns an attempt per try, and at three attempts fires `self_destruct(force=True)` whose wipe list **includes `Bunker.mmf.bak*`, `bunker.cfg.bak*`, `bunker.salt.bak*`** (`main/SHARED_RESOURCES.py:487-490`). Three typings of a legitimately set password after a crash = total, unrecoverable loss.
**Fix:** exclude `*.bak` from the max-attempts wipe, and/or suppress attempt-increment when an interrupted-rotation state is detectable (`bunker.salt.bak` differs from `bunker.salt`).

### BLOCKER 2 — `.bak`-salt recovery never repairs on-disk state; a second crashed rotation bricks the vault permanently (High)
After a `.bak`-based login, `bunker.salt` stays orphaned forever and every login depends on the `.bak`. If the user then runs another rotation that also crashes in the same window, `save_salt` rolls the `.bak` over with the orphaned salt — the salt matching `bunker.cfg` then exists nowhere, and no password can ever open the vault again. This is the only true bricking path found, and the fix is cheap: on successful `.bak`-based login, write the recovered salt back to `bunker.salt` (or refuse rotation while state is inconsistent).

### BLOCKER 3 — The shipped docs still contain every previously flagged error (High, first-customer-contact)
The README redesign exists only as `docs/README.draft.md`; nothing ships it. The live root `README.md` (and its `main/` byte-duplicate) still says to delete `BUNKER.mmf` (wrong case — file is `Bunker.mmf`), still tells users to `pip install … keyboard …` (a package this very branch removed, which needs root on Linux) — now actively contradicting the branch's own `requirements.txt` — `gumroad.md` still omits `inputimeout` and `argon2-cffi` from its install line (ImportError on first run for paying customers) and still claims "open source" against the personal-use-only license. All are sub-hour fixes: promote the draft (it fixes all four correctly) or patch the live files.

---

## Port from `code-review-council-7s0d1i` (our branch) on top

1. **Remove the stale-snapshot fallback** (`BUNKER.py:370-385` on their branch). Their fix for the unbound-`contents` NameError binds the variable but *entrenches* the fallback: if re-reading `Bunker.mmf` fails, the manager runs on the login-time snapshot, and any save inside it atomically overwrites the newer on-disk vault — a silent rollback of recent changes. Our branch returns to the menu instead; that behavior should win.
2. **Rotation rollback on exception.** Their rotation is stronger on *crash* (the `.bak` scheme), ours on *exception* (in-memory rollback restores all three files immediately; theirs leaves new-salt/old-config on disk needing the login recovery path). Combine: keep their `.bak` scheme, add our immediate rollback in the `except` path.
3. Minor: move `INITIALIZE.py`'s mid-file `__main__` guard to end of file (still mid-file on their branch; fixed on ours), and after a successful rotation, refresh or shred the `.bak` files — they otherwise persist encrypted under the **old** password, which matters if the rotation was prompted by compromise (and a stale `bunker.salt.bak` doubles the KDF cost of every failed login).

**Honest accounting of our own branch:** the correctness seat confirmed `code-review-council-7s0d1i` retains the 3.12-only f-string at `BUNKER.py:1955` — our branch does not even import on Python 3.10/3.11. Theirs fixed it and proves it in CI. With the two deltas above ported, our P0 commits are fully superseded; this branch's lasting contribution is the council reports and the two portable deltas.

---

## Claimed-fixed vs. actually-fixed (correctness seat verification)

| Known issue from Round 1 | Status on their branch |
|---|---|
| Generic handlers destroying vault (P0-1) | **FIXED** (and hardened with `force=` gating + sentinel test) |
| Non-atomic vault writes (P0-2) | **FIXED** (superior writer; zero truncate-writes remain) |
| Master-password rotation ordering/ignored failure/settings reset (P0-3) | **FIXED** (modulo Blockers 1–2 and the exception-rollback delta) |
| Unbound `contents` NameError (P0-4) | **FIXED**, but entrenches the stale-snapshot fallback (port our removal) |
| `timeoutInput` hardcoded 60s / instant logout at 0 | **FIXED**; but `os._exit` still fires before the sentinel can return, so the `*TIMEOUT*` protocol and its ~200 comparison branches remain dead code |
| addProfile/editProfileData `KeyError: timeout_value` | **FIXED** |
| tagNotes decrypts/copies the wrong note | **NOT FIXED** (`BUNKER.py:4838, 4858`) |
| exportNotes returns True → silent logout on success | **NOT FIXED** (`BUNKER.py:3806`) |
| editNoteData private-toggle infinite loop | **NOT FIXED** (`BUNKER.py:~3206`) |
| displayAllNotes IndexError on undecryptable notes | **NOT FIXED** (`BUNKER.py:5070/5146`) |
| Favorite notes leaking into profile favorites | **NOT FIXED** (`BUNKER.py:1384`) |

## Other findings to file (non-blocking)

- **Downgrade hazard (High, docs-only mitigation possible):** after migration, `config.cfg` is device-key-encrypted; running the *old* binary once against the migrated directory triggers main's unconditional self-destruct. Release notes must warn: never launch the pre-upgrade version against a migrated vault; back up first.
- **Device key overpromise (Medium):** deleting `config.cfg` still resets `attempts: 0` regardless of the devkey — the forgery gate only blocks silent tampering via the published static key. The code comment is honest; the commit message oversells. No bricking: all devkey-loss paths exit with correct recovery instructions (verified).
- **`BUNKER_PEPPER` foot-gun (Medium):** vaults created on this branch become unopenable if the env var is later set/lost (legacy vaults are immune). Add `""` as a third candidate when a pepper is set, or warn loudly.
- **Clipboard auto-clear is blind (Low):** the 30s timer wipes whatever is in the clipboard (including unrelated user content), and overlapping copies truncate each other's window. Compare-before-clear.
- **ip-thread stop/start race (Low):** quick toggle can leave the old loop running alongside the new thread.
- **Corrupt `bunker.salt` burns attempts toward the forced wipe (Low, pre-existing):** contradicts the branch's "corruption never destroys" thesis; detect and fail loudly instead.
- **Test-coverage gaps (Medium):** no behavioral test for the full login/lockout/wipe path, master-password rotation (the one place the council found a Critical), import/export round-trip, or "demo vault opens with rootroot" (verified manually only — works solely via the legacy fallback, and nothing in CI would catch a regression).
- Housekeeping: `main/README.md` + `main/LICENSE.txt` duplicates still present; `loadDatabase` silently returns `{}` when DB and `.bak` are both missing (could mask loss); `except BaseException` in `timeoutInput`; unused `ui`/`slow` pytest markers; vhs tape output-path nit in `docs/img/README.md`.

---

## Recommended merge sequence

1. On `mobile-version-check-3p4gat`: fix Blockers 1–3 (exclude `*.bak` from the wipe + interrupted-rotation detection; salt repair after `.bak` login; promote/patch the shipped docs).
2. Port the two deltas from `code-review-council-7s0d1i` (stale-fallback removal, rotation exception rollback) + the `__main__`-guard move + post-rotation `.bak` refresh.
3. Add two cheap high-value tests: "demo vault opens with rootroot" and a crash-mid-rotation recovery test for both old and new passwords (the latter would have caught Blocker 1).
4. Merge to `main`. Do **not** merge our P0 commits on top (guaranteed conflicts, fully superseded); cherry-pick only this branch's review reports if a record in `main` is wanted.
5. File the five unfixed feature bugs (tagNotes, exportNotes, private-toggle, displayAllNotes, favorites leak) plus the dead `*TIMEOUT*` sentinel protocol as the next work package — they are all small, located, and specified in Round 1.
