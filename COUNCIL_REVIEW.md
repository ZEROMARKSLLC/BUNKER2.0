# BUNKER 2.0 — Council Code Review

A multi-angle review of the codebase (`BUNKER.py` + `main/INITIALIZE.py` + `main/SHARED_RESOURCES.py`), conducted by five specialist passes (Security, Architecture, Correctness, Product/UX, Code Quality), each followed by a verification/fix-spec round. Every runtime bug below was confirmed by direct code trace, not inferred.

> **Repo state note:** The mobile version is **not** in this repo or in git history — there are no mobile/device-detection files anywhere, no releases, and `main` is the only remote branch. The desktop app is fully present. The README/Gumroad already *advertise* a device-detecting mobile UI that does not exist yet.

---

## Verdict

**The cryptographic core is genuinely strong.** AES-256-GCM authenticated encryption, Argon2id → PBKDF2-HMAC-SHA3-256 key derivation, `secrets`-based password generation, random nonces, `chmod 600`. The math is not the problem.

**Everything around the crypto is dangerous.** Ordinary failures (a crash, a corrupt settings file, a missing vault file) trigger irreversible vault destruction; saves are non-atomic so a kill mid-write corrupts the vault; the app won't even start on Python ≤ 3.11; and the headline brute-force lockout can be reset offline because it's encrypted with a hardcoded key. Two core flows (add/edit profile) are currently broken on every freshly-created vault.

Priority order for any release: **stop destroying data → make it start & run → make security claims real → clean up.**

---

## P0 — Ship-blockers (it doesn't run, or it eats vaults)

### 1. Five code paths wipe the entire vault on ordinary failures
`self_destruct()` / `secure_delete_on_failure()` fire from generic error handlers, not just the intended 3-failed-logins path. Any of these erases `Bunker.mmf` + `bunker.cfg` + `bunker.salt` + `config.cfg`:

| Trigger | Location |
|---|---|
| **Intended:** 3 failed logins | `BUNKER.py:227` (KEEP) |
| Any unhandled exception in `main()` | `BUNKER.py:277` (REMOVE) |
| Any exception in the menu loop | `BUNKER.py:394` (REMOVE) |
| `config.cfg` missing or corrupt | `INITIALIZE.py:621` (REMOVE) |
| Any error loading salt/verifier/db | `INITIALIZE.py:892` (REMOVE) |
| `Bunker.mmf` missing (prints "Creating new empty database" then wipes instead) | `INITIALIZE.py:933` (REMOVE) |

**Fix:** gate `self_destruct()` so it only runs from the explicit lockout path (token/policy or a `force=` flag), and **never delete `bunker.salt` on a decrypt error**. With salt + a rolling `.bak` intact, every "won't open" failure becomes recoverable. One-line version: add a guard at the top of `self_destruct()` in `SHARED_RESOURCES.py:463`; full version: `SelfDestructPolicy` with a grace countdown.

### 2. All vault writes are non-atomic truncate-writes (corruption on crash)
Every save is `open("Bunker.mmf","wb")` — truncates first, so a kill/power-loss between truncate and write leaves an empty or partial vault, and the *next* launch (missing/short file) then self-destructs the rest. The one function with backup logic (`overwrite_db`, `INITIALIZE.py:438`) is **dead code, never called**.

~18 write sites need routing through one helper: `BUNKER.py:1314, 1746, 1945, 2573, 2590, 2613, 2755, 3210, 4585, 5007` plus `INITIALIZE.py:899, 1122, 1720, 1980, 391, 629, 633, 218`.

**Fix:** one `_atomic_write()` — temp file in same dir → `flush` + `os.fsync` → `os.replace()` → directory fsync, keeping one rolling `.bak`. Route every writer through it; delete `overwrite_db` and its import (`BUNKER.py:11`).

### 3. Won't start on Python 3.11 or older
`BUNKER.py:1940` uses a backslash inside an f-string expression (PEP 701), a `SyntaxError` before Python 3.12. Verified: fails on 3.11, compiles on 3.12. This is the **only** 3.12-ism in the codebase — Debian 12 / Ubuntu 22.04 / many Termux installs ship ≤ 3.11.

**Fix (2 lines, makes it 3.9+ compatible):**
```python
sep = f"{GOLD},\n{LPURPLE}"
print(sep.join(decrypted_deleted_domains))
```

### 4. `addProfile` and `editProfileData` are broken on every fresh vault
Both read `vault.manage_config(hashed_pass)["timeout_value"]` (`BUNKER.py:1180`, `:1512`), but setup stopped writing that key — the real value lives in `config.cfg["current_timeout"]`. Result: `KeyError` → swallowed by the generic handler → "Failed to add profile" every time. (Four more sites — `BUNKER.py:3636, 3858, 4171, 4461` — use `.get(..., 60)`, so they don't crash but silently ignore the user's timeout setting.)

**Fix:** `current_timeout = load_ui_config().get("current_timeout", 60)` at all six sites.

### 5. `import keyboard as kb` crashes on Linux/Termux and is never used
`BUNKER.py:3`. The `keyboard` library raises on import for non-root Linux and is unavailable on Android/Termux — and `kb` is referenced nowhere. A hard blocker for the mobile target, for a dependency that does nothing.

**Fix:** delete the import (and the dead `Scrypt`/`Fernet` imports on `BUNKER.py:4-5`).

### 6. Two latent `NameError` crashes that route into self-destruct
- `BUNKER.py:337, 347` — fallback paths reference `contents`, which isn't defined until line 384.
- `BUNKER.py:4482-4495` — import-profiles failure path falls through to an unbound `profiles_to_import`.

Because these crash into the `main()` catch-all (#1), the user's vault gets wiped by a typo-level bug.

### 7. No `requirements.txt`, and both documented install commands are wrong
Gumroad's command omits `inputimeout` and `argon2-cffi` (app won't start); README's includes the unused `keyboard`. Actual dependencies:
```
cryptography>=42.0.0
argon2-cffi>=23.1.0
inputimeout>=1.0.4
pyperclip>=1.8.2
psutil>=5.9.0
requests>=2.32.0
```
(Termux also needs `pkg install termux-api` for clipboard.)

---

## P1 — Security & trust

### 8. Brute-force lockout is trivially bypassable (hardcoded key)
The attempt counter lives in `config.cfg`, encrypted with a **hardcoded static key `b"0"*32`** (`INITIALIZE.py:613, 626`; every caller passes no key). Anyone can decrypt/forge it with a 3-line script using the key from the public source, reset `attempts` to 0 before each guess, and brute-force offline forever — the headline self-destruct never fires.
**Fix:** bind the UI-config key to a local random device secret (`bunker.devkey`, gitignored, `0600`) so it can't be forged from source knowledge, and treat the counter as advisory rather than as the security boundary. Migration path provided for existing `config.cfg`.

### 9. Live vault + salt + config are committed to git
`Bunker.mmf`, `bunker.salt`, `bunker.cfg`, `config.cfg`, and `sample_notes_encrypted.json` are all tracked (added in commit `a041155`). Combined with #8, that's a complete offline attack kit for anyone who clones the repo. **Treat the demo master password as compromised — rotate, don't just delete.**
**Fix:** `git rm --cached` all of them, extend `.gitignore`, scrub history with `git filter-repo`/BFG, force-push, and regenerate the vault with a new password/salt. (Full runbook in the security appendix.)

### 10. The "pepper" is the password itself
`derive_key_hybrid(pass, salt, pass)` concatenates `password + password` (`INITIALIZE.py:198, 1091, 1697`; `BUNKER.py:152`). A real `PEPPER` env value exists but is never used. Adds zero entropy — the pepper is illusory.
**Fix:** use a real env-sourced pepper (or drop the concept honestly), with a legacy-fallback migration so existing vaults aren't locked out.

### 11. `changeMasterPassword` can permanently destroy the vault
It writes the new salt and config **before** re-encrypting the DB and **ignores `saveDatabase`'s return value** (`INITIALIZE.py:1720, 1733`). If the DB save fails or the process dies between steps, the data on disk is encrypted with the old key whose salt is gone → permanently undecryptable, while "SUCCESS" is printed.
**Fix:** prepare → verify-roundtrip → journaled atomic swap of all three files, with rollback from `.bak` on any failure and startup recovery for an interrupted rotation.

### 12. Marketing claims that don't match the code
| Claim | Reality |
|---|---|
| "File tampering detection" | No scanner exists; the "Checking Files for tampering..." spinner is cosmetic |
| "Progressive delays between failed attempts" | No delay logic anywhere |
| "Fresh 3 tries every session" (Gumroad) | Counter persists across restarts; resets only on *successful* login |
| "AES-256" (blanket) | True for the vault; export passphrase *verifiers* use Fernet (AES-128-CBC) |
| "Open source / tweak it yourself" (Gumroad) | LICENSE forbids modification & redistribution — direct contradiction |
| "100% local, no tracking" | True except the optional IP feature calls ipify.org (off by default) |

**Fix:** corrected README "Features"/"Installation"/"Files" sections and a claims matrix are in the product appendix; pick one coherent license story (recommended: "source-available, personal modification, no redistribution").

### 13. Self-destruct UX is unsafe for a consumer product
No confirmation, no grace period, no export offer before wiping. "Delete all profiles" executes on a single keypress. Persistent counter means 2 typos this week + 1 next week = wiped vault.
**Fix:** typed confirmation ("type DESTROY") + grace countdown on the lockout path; restrict wiping to that path only; warn at launch when a persisted attempt count > 0.

---

## P2 — Code quality & the path to the mobile split

### 14. ~20–25% of the code is dead weight or duplication
BUNKER.py is 5,379 lines; an estimated **1,700–2,100** are removable:
- ~700 lines provably dead: a never-wired signal-handler chain (`INITIALIZE.py:749-828`), 9 unused vault methods, a 141-line orphan (`display_network_information`, `BUNKER.py:5234-5374`), `cleanupDatabase`, ~15 unused imports, ~120 lines of commented-out code.
- Heavy copy-paste: the "list → pick → view/copy/cancel" block pasted 8×; the timeout sentinel (`timeoutGlobalCode`) repeated 212×; the encrypt-and-save sequence 11×; two `generate_password` implementations (the weaker one shadows the stronger).

### 15. Architecture is "half-split", and the split introduced bugs
`BUNKER.py` already imports from `main/` — there is no standalone monolith. But the extraction left: duplicate diverging logic, two class methods missing `self` (`INITIALIZE.py:160, 308`), a cleanup routine mutating globals in the wrong module (`INITIALIZE.py:651-662`), and a dead/broken `__main__` block (`INITIALIZE.py:1164` — and `python -m main.INITIALIZE` would re-run setup over an existing vault, orphaning it).

### 16. More confirmed logic bugs
- Infinite loop on the note "Mark as private?" prompt (`BUNKER.py:3174-3178`, unreachable `break`).
- `tagNotes` decrypts the wrong note's content (leftover loop variable, `BUNKER.py:4812/4830`).
- Encrypted vault opened in **text mode** in `main_note_manager` (`BUNKER.py:2557`) → operates on a stale copy and can revert changes.
- Auto-logout "off" (timeout=0) instantly logs out the show-password login path (`BUNKER.py:137-140`).
- The configured auto-logout value is ignored on nearly every screen (default 60s everywhere; `timeoutInput` callers don't pass it).

### Recommended target architecture (for the desktop/mobile split)
```
bunker/
├── __main__.py          # detect device → launch UI
├── core/                # ZERO print/input — runs headless under pytest
│   ├── crypto.py        # KDF, AES-GCM, verifier, export keys
│   ├── storage.py       # atomic writes, salt, config, backups (one save path)
│   ├── models.py        # Profile / Note + field crypto (single copies)
│   ├── services.py      # add/edit/delete/find/tag/import/export (data in/out)
│   ├── passwords.py     # one generator + strength checker
│   └── session.py       # attempts, lockout, timer, SelfDestructPolicy
├── platform/detect.py   # TERMUX_VERSION / getandroidapilevel / terminal-width
│   └── clipboard.py     # pyperclip | termux-clipboard-set | no-op
└── ui/
    ├── desktop/         # current 120-col art + menus
    └── mobile/          # ≤60-col layouts, no terminal resize, compact art
```
**Device detection** (decide once at startup, in priority order): explicit `BUNKER_UI` env override → `TERMUX_VERSION` → `sys.getandroidapilevel()` → terminal-width fallback (`shutil.get_terminal_size().columns < 100`). Never force-resize the terminal (the current `check_terminal_size` 27×120 resize is ignored by phones and Windows Terminal and just wraps into garbage).

### Migration path (each step keeps the app runnable)
1. **Defuse the landmines** (P0 #1, #2, #3) + remove vault files from git (#9) + add `requirements.txt`.
2. **Make `main/` a real package** (add `__init__.py`, delete the broken `__main__`).
3. **Fix the split's correctness debt** (#4 KeyErrors, missing-`self` methods, wrong-namespace globals, duplicate generator).
4. **Carve out `core/`** (pure crypto/storage/passwords/session) behind re-export shims; add round-trip tests.
5. **Extract services** one vertical slice at a time; unify the 3 DB-write patterns into one atomic `storage.save()`.
6. **Add `platform/detect.py` + `ui/desktop/`** reproducing current visuals exactly; `BUNKER.py` becomes a thin shim.
7. **Build `ui/mobile/`** against the same services; merge in the mobile code stranded on the desktop machine — as a UI layer, not a fork.

---

## The top 7, if you do nothing else
1. Remove `self_destruct()` from every generic failure path; never delete the salt on a decrypt error.
2. Make all vault writes atomic (temp → fsync → `os.replace`, rolling `.bak`).
3. Fix `BUNKER.py:1940` so it runs on Python ≤ 3.11.
4. Fix the `timeout_value` KeyError so add/edit profile work on fresh vaults.
5. Delete the unused `keyboard` import.
6. Replace the hardcoded-`b"0"*32` lockout key and remove the committed vault/salt from git (rotate the password).
7. Add `requirements.txt` and make the README/Gumroad claims match the code.
