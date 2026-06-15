# Code Review Council — Archived Reports

These are the review reports from the three parallel review/fix sessions that
hardened BUNKER 2.0. They are preserved here as the audit trail for *why* the
security and correctness changes on this branch exist. The branches themselves
(`claude/code-review-council-7s0d1i`, `claude/code-review-council-yma5h3`) are
frozen/read-only; everything portable from them has been integrated here.

| File | Source branch | What it is |
|---|---|---|
| `ROUND1_yma5h3_four_seat.md` | yma5h3 | Round-1 four-seat review of `main` — ~60 findings with file:line evidence and a P0–P3 priority matrix. |
| `ROUND1_7s0d1i.md` | 7s0d1i | Round-1 review (independent seats) of `main`. |
| `ROUND2_blocker_analysis.md` | 7s0d1i | Round-2 review of the integration branch: the three merge blockers (all fixed here), the two ported deltas, and the five-bug work package. |

The session's own consolidated report lives at the repo root as
`COUNCIL_REVIEW.md`.

## Status of the work these reports specified

- **Three round-2 blockers** (`.bak`-preserving wipe, interrupted-rotation
  detection, salt repair): **fixed** on this branch.
- **Two ported deltas** (stale-snapshot removal, rotation exception rollback)
  + `__main__`-guard move + post-rotation `.bak` shred: **done.**
- **Five Round-1 feature bugs** (tagNotes wrong-note, exportNotes silent
  logout, editNoteData private-toggle infinite loop, displayAllNotes
  IndexError, favorite-notes leaking into profile favorites): **fixed.**
- **Docs truth pass** (README promoted; gumroad.md "open source"/"military-
  grade"/"fresh 3 tries" corrected; install line fixed): **done.**
- **Unit suite** `tests/test_bunker.py` (from yma5h3): **integrated** with
  function-scoped fixtures so the fast-KDF harness applies.

### Still open (filed, not yet addressed)
- Dead `*TIMEOUT*` sentinel protocol (`os._exit` fires before the sentinel
  can return — the ~200 comparison branches are unreachable).
- `BUNKER_PEPPER` foot-gun: vaults created with a pepper set become
  unopenable if it is later lost; add `""` as a third candidate or warn.
- Clipboard auto-clear is blind (wipes whatever is on the clipboard at 30s).
- Downgrade hazard: running the pre-upgrade binary against a migrated vault
  triggers self-destruct — needs a release-notes warning.
