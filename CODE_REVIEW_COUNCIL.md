# BUNKER 2.0 — Code Review Council Report

**Date:** 2026-06-12
**Scope:** Full end-to-end review of the repository (`BUNKER.py`, `main/INITIALIZE.py`, `main/SHARED_RESOURCES.py`, config/sample/data files, docs, packaging).
**Method:** Four independent review seats run in parallel — Security & Cryptography, Correctness (main application), Correctness (support modules), Architecture & Maintainability — followed by cross-seat synthesis. All seats were read-only; no code was modified.

---

## Executive summary

The cryptographic core is genuinely solid: the vault uses AES-256-GCM with fresh random nonces, keyed by an Argon2id → PBKDF2-HMAC-SHA3-256 hybrid KDF (~100 MB memory cost, 110k iterations), with `secrets`-based password generation and `0o600` file permissions. There is no telemetry of vault data, no `eval`/`pickle`, no unsafe deserialization.

Everything around that core, however, is in a dangerous state. The council's single most important conclusion, corroborated independently by three of the four seats:

> **The app's "self-destruct on any anomaly" philosophy, combined with non-atomic file writes and blanket `except Exception` handlers, converts ordinary, recoverable I/O failures into permanent, unrecoverable destruction of the user's vault.**

A power loss during a routine save, a single flipped byte in a config file, a transient file lock, or even an internal `NameError` bug will shred `Bunker.mmf`, `bunker.cfg`, **and `bunker.salt`** — and because the salt is destroyed, even an off-site backup of the vault becomes undecryptable. For a product whose pitch is "your data survives," this is the inverse of the guarantee.

Secondary themes:

1. **A half-finished migration** (Fernet → AES-GCM exports, `bunker.cfg` → `config.cfg` split, `overwrite_db` → `saveDatabase`) left drifted duplicates and partial states. The safe, backup-and-verify database writer exists in the code and is imported — but is never called. The unsafe truncate-in-place twin is used everywhere.
2. **The advertised lockout/self-destruct protection is forgeable.** `config.cfg` (which stores the attempt counter) is encrypted with a hardcoded key of `b"0"*32`, shipped in the source with the comment "Replace with a real key if possible."
3. **Several headline features are simply broken** on vaults created by the current setup flow: adding/editing profiles crashes, the tag-folder note viewer shows (and copies to clipboard) the wrong note, exporting notes silently terminates the program, the "mark as private" editor loops forever, and the configurable auto-logout timer is decorative — nearly every prompt hardcodes 60 seconds.
4. **Commercial/packaging problems customers hit in minute one:** the Gumroad install one-liner omits two required packages (`inputimeout`, `argon2-cffi`) and crashes on first run; gumroad.md calls the product "open source" while the license is restrictive personal-use-only; the README tells users to delete `BUNKER.mmf` when the file is `Bunker.mmf` (breaks on Linux).

**Recommended fix order:** P0 items below (stop destroying user data) → P1 (broken features, forgeable lockout) → P2 (packaging/docs/hygiene) → P3 (structural refactor).

---

## P0 — Data-loss class (fix before anything else)

### P0-1. Generic exception handlers shred the vault, salt, and config
- `BUNKER.py:275-277` and `BUNKER.py:392-394`: the catch-alls for the entire main loop call `self_destruct()` / `vault.secure_delete_on_failure()`, which 3-pass-shred `Bunker.mmf`, `bunker.cfg`, `bunker.salt` (and `config.cfg`). Any unexpected exception — corrupt DB byte, missing config key (`ui_config["attempts"]`, `BUNKER.py:73-76`), missing `bunker.cfg`, or the internal bugs listed below — lands here.
- `main/INITIALIZE.py:611-630` (`load_ui_config`): any read/parse error on `config.cfg` — a UI-preferences file — triggers full self-destruct. `save_ui_config` rewrites that file non-atomically **on every login attempt** (`BUNKER.py:191, 206`), so an interrupted write bricks-then-shreds the real vault on next launch.
- `main/INITIALIZE.py:930-934` (`loadDatabase`): if only `Bunker.mmf` is missing, it prints "Creating new empty database," then calls `self_destruct()` — destroying the salt/config that were still intact; the `return {}` is unreachable.
- `main/INITIALIZE.py:1153-1156` (`vaultSetup`): the catch-all wraps the entire function including pre-write prompts, so a transient exception before anything is written still wipes whatever vault files already exist on disk.

**Fix:** Self-destruct only on the explicit max-attempts path. On unexpected exceptions: log, keep files intact, exit. Never include `bunker.salt`/`bunker.cfg` in failure-path deletion. Treat a corrupt `config.cfg` as recoverable (regenerate defaults).

### P0-2. No atomic writes; the safe writer is dead code
- `Bunker.mmf` is truncated and rewritten in place at ~10 call sites in `BUNKER.py` (1314, 1746, 1945, 2573, 2590, 2613, 2755, 3210, 4585, 5007) and in `saveDatabase` (`INITIALIZE.py:894-917`) — no temp file, no `os.replace`, no fsync, no backup. A crash mid-save destroys the only copy, and P0-1 then destroys the key material too.
- `overwrite_db` (`INITIALIZE.py:438-499`) implements backup → write → verify → restore-on-failure, is imported by `BUNKER.py:11` — and is never called anywhere.

**Fix:** Write to a temp file in the same directory, fsync, `os.replace()`. Route all saves through one (fixed, atomic) writer; delete the other.

### P0-3. Master-password change can brick the vault and reports success anyway
`main/INITIALIZE.py:1716-1738`: the new salt and config are written first; `saveDatabase`'s return value (False on failure) is discarded and "SUCCESS" prints regardless. A failure or crash between the config write and the DB re-encryption leaves salt/config keyed to the new password while the DB is still under the old key → next login fails → P0-1 destroys everything. Side effect even on success: `timeout_value`/`settings` are read from keys that no longer exist in `bunker.cfg`, silently resetting the user's timeout and IPv4 settings (`INITIALIZE.py:1724-1730`).

**Fix:** Re-encrypt the DB to a temp file, verify it decrypts under the new key, then atomically swap DB+config+salt together with rollback. Check `saveDatabase`'s return value. Carry over the previously loaded UI settings.

### P0-4. Latent `NameError`s that route into P0-1
- `BUNKER.py:329-347`: if re-reading `Bunker.mmf` fails on the first menu selection, the fallback references `contents`, which is unbound until line 384 → `NameError` → vault shredded. When bound, `contents` is a stale snapshot whose later save would silently roll back recent changes.
- `INITIALIZE.py:1174-1178`: `if __name__ == "__main__": main()` sits mid-file, 800+ lines before `display_setup_guide` is defined. Running the module directly and typing `.g` at the first prompt raises `NameError`, which the `vaultSetup` catch-all converts into deletion of existing vault files.

---

## P1 — Broken features and forgeable protections

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| P1-1 | Critical (security) | `INITIALIZE.py:611-630` | `config.cfg` encrypted with hardcoded `b"0"*32` (effectively a fixed AES-192-GCM key shared by every install; comment admits it). Attempt counter and `max_attempts` live there → the advertised 3-strikes self-destruct is trivially resettable/forgeable. Derive this key from the master password or merge the state into `bunker.cfg`. |
| P1-2 | High | `BUNKER.py:1180, 1512` | **Add Profile and Edit Profile are entirely broken** on vaults created by the current setup: `manage_config(...)["timeout_value"]` raises `KeyError` (key no longer written) and the outer except swallows it. Use `load_ui_config().get("current_timeout", 60)`. |
| P1-3 | High | `BUNKER.py:4812, 4830` | Tag-folder note viewer decrypts a stale loop variable — selecting any note other than the last shows and **copies to clipboard the last note's content**. Use the selected note's own data (as `displayAllNotes` does). |
| P1-4 | High | `BUNKER.py:3778-3779` | `exportNotes` returns `True` on success, which the protocol reads as "timed out" → every successful note export silently logs out and exits the app. Return `False`. |
| P1-5 | High | `BUNKER.py:3164-3178` | Edit Note "Mark as private?" — assignment/`break` are dead code after `continue`; valid 'y'/'n' loops forever. Privacy can never be changed via edit. Dedent two lines. |
| P1-6 | High | `INITIALIZE.py:599-606` + ~100 call sites | Auto-logout timer is decorative: `timeoutInput` hardcodes 60s default and on timeout `os._exit(0)`s; nearly all prompts omit `timeout=`. With timer "disabled" (0), the login path force-logs-out instantly (`inputimeout(timeout=0)`), since `timeoutInput` lacks the `<=0` guard its twin `timeout_getpass` has. Thread the configured value through; bypass when 0. |
| P1-7 | Medium | `BUNKER.py:246-261` | Tamper response is disconnected: DB decryption failure prints "Self destructing..." but the call is commented out and execution continues with an undefined database — eventually hitting the P0-1 shredder anyway. The README's "instant vault wipe on tampering" claim is not wired up. Decide the behavior and implement it (without destroying the salt). |
| P1-8 | Medium | `BUNKER.py:1456, 2105, 2312, 2456, 2935, 3422, 4832, 5179` | Stored passwords/notes copied to clipboard are never auto-cleared (the 30-second `to_clipboard` helper is only used for *generated* passwords). Route all secret copies through it. |
| P1-9 | Medium | `SHARED_RESOURCES.py:117-135`, `INITIALIZE.py:657-659` | IP-fetch thread can't be stopped: dropping the reference doesn't end the `while True` loop, so the app keeps hitting `8.8.8.8`/ipify every 30s after the user disables IP display; re-enabling spawns a second thread; the cleanup sets `do_run` on the wrong module's globals and the loop never reads it. Use a `threading.Event`. Also: the fetch holds `cache_lock` for up to ~15s, stalling menu redraws — lock only the cache assignment. |
| P1-10 | Medium | `BUNKER.py:5045-5118` | `displayAllNotes` sizes the selection range by raw note count but indexes the decrypted-only list → `IndexError` aborts the whole view when any note fails to decrypt. Use `len(decrypted_notes)` (the profile views already do). |
| P1-11 | Medium | `BUNKER.py:1371` | Favorited *notes* leak into the FAVORITE PROFILES view as `N/A` rows (shared db dict, filter checks only `favorite`). Add `and "password" in v`. |
| P1-12 | Medium | `BUNKER.py:3607-3628, 3800-3829, 4144-4161, 4407-4433` | Export/import paths accept raw user paths (`../../x` → `../../x.json`): arbitrary file write/read outside the working directory. Restrict to a basename in a known export dir. |
| P1-13 | Medium | `sample_notes_encrypted.json` vs `INITIALIZE.py:501-581` | The bundled encrypted sample is a legacy Fernet payload; current import decrypts with AES-GCM → the shipped import demo cannot be imported. Add a Fernet fallback or regenerate the sample. |
| P1-14 | Medium | `BUNKER.py:1897-1912` | `deleteProfileData` misaligns display indices with deletion keys when any profile fails to decrypt: "delete all" deletes records never shown; selecting a failed index raises `KeyError` and aborts. |
| P1-15 | Medium | `BUNKER.py:2557-2565` | Note-manager "refresh" opens the binary vault in text mode (`"r"`) — `UnicodeDecodeError` every time, silently swallowed by `except: pass`; the refresh feature is dead. Open `"rb"`. |
| P1-16 | Low | `INITIALIZE.py:1675` | "New password same as current" check never fires: key derived without the pepper used everywhere else (`derive_key_hybrid(pw, salt)` vs `(pw, salt, pw)`). |
| P1-17 | Low | `INITIALIZE.py:97-101, 1157-1162` | Memory "wiping" is cosmetic: `secure_wipe` zeroes a guard buffer that never held secrets; `del locals()[var]` is a no-op. Temper claims; use `bytearray` where wiping matters. |
| P1-18 | Low | `SHARED_RESOURCES.py:473` | `self_destruct` treats `"*.bak.*"` as a literal filename — backups would survive a wipe. Use `glob.glob`. |
| P1-19 | Low | `INITIALIZE.py:308, 160` | Class methods missing `self`: `load_timeout_value` works by accident (instance binds to an unused param); `decode_and_decrypt` (class copy) can never work — it's dead, drifted from BUNKER.py's own divergent copy. |
| P1-20 | Low | `BUNKER.py:682-692` | Passwords longer than 32 chars are declared "weak." Long passwords are penalized by the strength checker. |

---

## P2 — Packaging, docs, repo hygiene (what paying customers hit first)

1. **Broken install command.** `gumroad.md`'s `pip install cryptography pyperclip psutil requests` omits `inputimeout` and `argon2-cffi` → ImportError on first run. Real dependencies: `cryptography`, `argon2-cffi`, `inputimeout`, `pyperclip`, `psutil`, `requests`. `keyboard` is imported (`BUNKER.py:3`) but never used — and requires root on Linux; drop it from code and README. **Add `requirements.txt`** (or `pyproject.toml` with a console entry point).
2. **"Open source" vs. the license.** gumroad.md repeatedly says open source; `LICENSE.txt` is restrictive personal/internal-use-only, no redistribution. Resolve this — it's a real commercial/legal inconsistency.
3. **README filename case bug.** "Delete the `BUNKER.mmf` file" — the file is `Bunker.mmf`; misleads Linux users. gumroad.md also says the box contains "BUNKER.py (the main script)" without mentioning that `main/` is required — copying just the script gives an instant ImportError.
4. **No `.gitignore`; live vault artifacts are tracked.** `Bunker.mmf`, `bunker.salt`, `bunker.cfg`, `config.cfg` are committed (one `.gitignore` was added and then deleted in commit `f4beb9a`). A customer who keeps a real vault in the clone can have `config.cfg` clobbered by `git checkout` — which, via P0-1, destroys their vault — or can accidentally commit/push their real encrypted vault and salt. Gitignore `*.mmf`, `*.salt`, `*.cfg`, `*.bak.*`, `__pycache__/`, `.DS_Store`; move demo data (demo password `rootroot` is published in the README) into a `demo/` folder.
5. **Duplicate/diverged docs.** `main/README.md` is byte-identical to the root README; `main/LICENSE.txt` differs from root by two cosmetic words. Keep one canonical copy of each. README's "Coming Soon: ZeroMarks VPN (Q1 2025)" is stale.
6. **Marketing vs. reality.** README advertises AES-256 + tamper-wipe + secure memory handling; in reality `config.cfg` is AES-192 under a public key (P1-1), tamper-wipe is commented out (P1-7), and memory wiping is cosmetic (P1-17). Align the claims with the implementation (preferably by fixing the implementation).
7. **No tests, no CI.** The pure functions (KDF round-trip, encrypt/decrypt, export verifier, password strength/generation) are trivially testable without a TTY. A minimal `py_compile` + pytest workflow would have caught the broken install line and several P1s.

---

## P3 — Structural recommendations

1. **Unify the duplicated profile/notes CRUD (large).** ~48% of the codebase (~4,000 lines of `BUNKER.py`) is the same feature set written twice and drifting: measured similarity between note/profile twins ranges 8–71%; bugs fixed in one copy persist in the other (the council found several such pairs — export return values, index handling, favorite filters). A single parameterized record manager (type, field schema, formatter) halves the file and ends this bug class.
2. **Delete dead code (small).** Never-called: `overwrite_db` (fix and use it instead — see P0-2), `cleanupDatabase`, `load_max_attempts`, `fileSetup`, `load_encrypted_file`, `verify_setup`, `manage_*` family, `setup_secure_exit_handlers` (imported, never called — so no SIGTERM handler is actually installed), `get_config_paths`, `display_network_information`, the `BUNKER.py:46-63` commented prototype, duplicate `base64` import, unused `Scrypt`/`Fernet`/`traceback`/`keyboard`. Move the mid-file `__main__` guard (`INITIALIZE.py:1174`) to end-of-file or remove it.
3. **Centralize constants (medium).** `"Bunker.mmf"` appears 33 times, the `*TIMEOUT*` sentinel is string-compared 202 times (and is user-spoofable — typing it fakes a timeout), and the "Press enter to return" prompt is hand-rolled 56 times. The vault class already defines filename attributes; use them.
4. **Make error handling intentional (medium).** 121 `except Exception` blocks + 7 bare `except` + ~87 lone `pass`/`continue`. In a security product, blanket swallowing hides exactly the corruption/tampering events the product claims to detect. Introduce a small exception hierarchy (VaultCorrupt, AuthFailure, ConfigError) and let unexpected errors surface (without triggering destruction — see P0-1).
5. **Rename `INITIALIZE.py` (small).** It is the crypto/persistence core, not initialization; the name actively misleads. `vault.py`/`core.py` plus a one-line import fix in two files.
6. **Break up mega-functions (medium).** `exportProfiles` 357 lines, `display_user_guide` 328, `system_info` 309, `editNoteData` 297, `main()` 259 mixing setup detection, login, attempt counting, and dispatch.

---

## What the council found done well

- **Vault encryption:** AES-256-GCM, fresh `os.urandom(12)` nonce per operation, authenticated; no nonce reuse found.
- **Key derivation:** Argon2id (t=3, m=100 MB, p=8) chained into PBKDF2-HMAC-SHA3-256 ×110k — well above typical, giving real offline brute-force resistance (this, not the attempt counter, is the product's true protection).
- **Randomness:** `secrets`/`os.urandom` everywhere it matters; no `random` for security material.
- **Hygiene:** `0o600` permissions on sensitive files (POSIX); JSON-only data handling; no `eval`/`exec`/`pickle`; no telemetry of vault contents (only opt-in public-IP lookups).
- **Export design:** per-export random salt + passphrase verifier checked before decryption; confirm-entry and minimum length enforced.
- **Right instincts in places:** `overwrite_db`'s backup/verify/restore design and `timeout_getpass`'s `<=0` guard are exactly correct — they just need to be the versions actually in use.

---

## Council verdict

The product's foundation (crypto core) deserves trust; its failure handling does not. Until the P0 class is fixed, every user of this product is one power flicker, one interrupted write, or one stray exception away from total, unrecoverable loss of their vault — with the salt destroyed so backups can't save them. Fix P0-1 through P0-4 first; they are small, surgical changes (scoped destruction, atomic writes, ordered key rotation). Then restore the broken features (P1-2..6 are one-to-five-line fixes), close the forgeable-lockout hole (P1-1), and repair the customer-facing packaging (P2-1..3) before the next sale.
