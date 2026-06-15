# Handoff — Council Teams → Mobile Integration Branch

**Purpose:** coordinate three parallel Claude sessions so nothing is lost and
the eventual merge is clean. Copy the prompt block below into each council
session.

## The situation (why this matters)

Three branches have been editing the same three core files (`BUNKER.py`,
`main/INITIALIZE.py`, `main/SHARED_RESOURCES.py`):

| Branch | Role | State |
|---|---|---|
| `claude/mobile-version-check-3p4gat` | **Integration branch (canonical).** Superset: all P0 data-loss fixes, devkey, pepper, atomic saves, rotation recovery, 3.10 compat, CI, sentinel + rotation tests, README redesign + real screenshots, threat model, positioning, mobile UI spec, release plan. | Active — mobile port starts here |
| `claude/code-review-council-7s0d1i` | Council round-2 review | **Fully absorbed.** It merged the integration branch and its one unique commit (rotation safety + recovery tests) was ported back. Nothing left to salvage. |
| `claude/code-review-council-yma5h3` | Independent council review | **Parallel solution to the same P0 problems** — less complete than the integration branch. One unique asset worth keeping: `tests/test_bunker.py` (unit suite for KDF / encryption / save-load / export / strength / generator). |

**The risk:** every additional edit a council team makes to the three core
files widens a three-way divergence that someone has to reconcile by hand.
The integration branch already contains a more complete version of what both
council teams were building — so the cheapest path is for them to **freeze
core-file edits now, commit everything, push, and hand off.**

## What each council team should commit RIGHT NOW

1. Commit and push **any uncommitted work** in the session — don't leave
   anything stranded in a working tree (this whole exercise started because
   the mobile code sat uncommitted on a local machine for months).
2. **Stop editing** `BUNKER.py`, `main/INITIALIZE.py`,
   `main/SHARED_RESOURCES.py`. Those are owned by the integration branch now.
3. Confirm **no real vault artifacts** are tracked: `Bunker.mmf`,
   `bunker.cfg`, `bunker.salt`, `config.cfg`, `bunker.devkey`, any `*.bak`.
   If any are tracked, `git rm --cached` them and add to `.gitignore`.
4. Post the final commit SHA + branch name back so the integration branch
   knows the handoff point.

**yma5h3 specifically:** make sure `tests/test_bunker.py` is committed and
pushed — it is the one asset the integration branch will pull in (after
reconciling its `vault` / `derived_key` fixtures with the integration
branch's `conftest.py`, which uses `key` / `vault_dir` / `populated_vault`).

---

## COPY-PASTE PROMPT FOR EACH COUNCIL SESSION

> We are consolidating three parallel branches of BUNKER 2.0. Your branch and
> the integration branch `claude/mobile-version-check-3p4gat` have both been
> editing the same core files (`BUNKER.py`, `main/INITIALIZE.py`,
> `main/SHARED_RESOURCES.py`). The integration branch is now the canonical
> superset — it already contains a more complete version of the P0 data-loss
> fixes, atomic saves, key-derivation hardening, and test coverage you have
> been working on, plus the mobile port that is about to begin there.
>
> Please **wrap up and freeze** your branch so nothing is lost and the merge
> stays clean. Do exactly this, then stop:
>
> 1. Commit and push every uncommitted change in your working tree to your
>    branch. Do NOT use `git add -A` — stage source files explicitly so you
>    never commit real vault artifacts (`Bunker.mmf`, `bunker.cfg`,
>    `bunker.salt`, `config.cfg`, `bunker.devkey`, `*.bak`).
> 2. If any of those vault artifacts are already tracked on your branch,
>    `git rm --cached` them, add them to `.gitignore`, and commit that.
> 3. Do NOT make any further edits to `BUNKER.py`, `main/INITIALIZE.py`, or
>    `main/SHARED_RESOURCES.py` — those are owned by the integration branch
>    from here on.
> 4. Reply with: your branch name, the final commit SHA after pushing, and a
>    one-paragraph summary of anything unique on your branch that the
>    integration branch should pull in (tests, docs, a specific fix). Be
>    concrete — name files.
>
> Confirm when pushed.

---

## After both teams confirm

The integration branch will:
1. Record both handoff SHAs.
2. Cherry-pick / adapt `yma5h3:tests/test_bunker.py` (fixture reconciliation
   against `conftest.py`).
3. Archive the two council reports if not already captured, then treat both
   council branches as read-only history.
4. Proceed with the mobile port per `docs/MOBILE_UI_SPEC.md`.
