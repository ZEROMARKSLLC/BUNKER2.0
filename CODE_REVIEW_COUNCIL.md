# BUNKER 2.0 — Code Review Council Report

**Date:** 2026-06-12
**Scope:** Full end-to-end review of the codebase at HEAD (`2dc70c8`):
`BUNKER.py` (5,379 lines), `main/INITIALIZE.py` (1,992 lines), `main/SHARED_RESOURCES.py` (1,132 lines), plus docs, license, samples, and git history.
**Method:** Four independent review seats run in parallel — Security & Cryptography, Correctness & Bugs, Architecture & Code Quality, Repo Hygiene/Docs/Packaging — followed by cross-seat synthesis. All findings were verified against actual code with file:line evidence; several were confirmed by compiling/parsing the code.

---

## Executive Summary

BUNKER 2.0 is built on sound cryptographic primitives (Argon2id, AES-GCM/Fernet, `os.urandom` salts, `secrets`-based generation), but the implementation around them currently undermines the product's core promises. The council's unanimous verdict: **not production-ready for real secrets until the P0 items below are fixed.** The single most dangerous pattern — flagged independently by two seats — is that **ordinary bugs and recoverable I/O errors are routed into vault-destruction code paths**, converting transient failures into permanent, irreversible loss of every password and note.

### The five problems that matter most (P0)

1. **Generic error handlers destroy the vault.** `BUNKER.py:392-394` calls `vault.secure_delete_on_failure()` on *any* exception in the main manager loop, and `load_ui_config` (`INITIALIZE.py:611-622`) calls `self_destruct()` if the 107-byte `config.cfg` is missing or corrupt. A guaranteed `NameError` trigger exists (`contents` undefined at `BUNKER.py:337/347`), and `config.cfg` is rewritten non-atomically on every login. A power loss at the wrong moment deletes all user data.
2. **Every vault save is a non-atomic truncate-then-write** at ~10 call sites; the only safe writer (`overwrite_db`, with backup/restore) is imported but never called. Disk-full or crash mid-write empties `Bunker.mmf` — and the resulting decrypt failure then feeds into the destruction handlers above.
3. **The advertised brute-force/self-destruct protection is trivially bypassable.** The attempt counter lives in `config.cfg`, which is encrypted under a hardcoded all-zero key (`INITIALIZE.py:611-630`), so an attacker resets it at will. Additionally, `self_destruct()` never deletes `Bunker.mmf.bak.*` backups because the glob string `"*.bak.*"` is tested as a literal filename (`SHARED_RESOURCES.py:472`).
4. **Stored secrets are copied to the clipboard with no auto-clear** at 8 call sites; only the password *generator* uses the 30-second clearing helper. Decrypted passwords and notes sit in the OS clipboard indefinitely.
5. **The app frequently cannot even start for customers.** `BUNKER.py:1940` is a SyntaxError on Python ≤ 3.11 (PEP 701 f-string); the unused `import keyboard` (`BUNKER.py:3`) crashes non-root Linux at import time; and the Gumroad install one-liner omits two required packages (`inputimeout`, `argon2-cffi`), so paying customers get an ImportError on first launch.

### Cross-cutting trust issue

Marketing claims exceed what the code delivers: "100% local / data never leaves your device" (the app contacts ipify, ifconfig.me, icanhazip.com, and 8.8.8.8 in a background loop), "secure memory wipe" (Python strings cannot be wiped; the `del locals()` cleanup is a no-op), "DoD 3-pass erase" (ineffective on SSDs/CoW filesystems, and misses backups), and "open source" on the sales page while the license is a proprietary no-modification CPSL. For a paid security product these are refund/reputation/liability risks.

### Priority matrix

| Priority | Theme | Findings |
|---|---|---|
| **P0 — fix before anything else** | Vault destruction in error paths; non-atomic writes; zero-key lockout counter; clipboard; app won't start (3.12 syntax, `keyboard` import, broken install docs) | C1, C2, C3, C4, C5, S3, S5, S7, S15, H1, H2, H3 |
| **P1 — fix this release** | Untrack runtime binaries + `.gitignore` + `requirements.txt`; `changeMasterPassword` lockout path; tagNotes shows wrong note; private-flag infinite loop; export exits app; license/marketing contradiction | S6, H5, H6, H7, C7, C6, C8, C11 |
| **P2 — schedule** | Timeout system rework; IP-thread stop/locking; password length floor; export verifier; dedup notes/profiles; package split; tests | S13, S14, S16, C9, C13, A-roadmap |
| **P3 — cleanup** | Dead code, naming, docs accuracy, commit hygiene | A3, A6, H8, H9, H10 |

(Keys: S = Security seat, C = Correctness seat, A = Architecture seat, H = Hygiene seat — full findings below.)

### Note for the parallel teams

Two other teams are working in parallel sessions. The highest-risk collaboration hazard found: **the app mutates four tracked binary files (`Bunker.mmf`, `bunker.cfg`, `bunker.salt`, `config.cfg`) in the repo root at runtime**, and a missing/changed `config.cfg` (e.g., after `git checkout -- .` or a merge) **triggers the self-destruct wipe**. Until those files are untracked (`git rm --cached` + `.gitignore`, see Seat 4), nobody should run the app inside a working clone that has uncommitted vault state, and binary merge conflicts on these files should be expected.

---

## Seat 1 — Security & Cryptography

### Findings

**S1. KDF is not Scrypt — it's a custom Argon2id→PBKDF2 chain; imports are misleading.** *(Medium — `BUNKER.py:4`, `main/INITIALIZE.py:127-156`)*
`Scrypt` is imported but never used (zero call sites). The actual KDF, `derive_key_hybrid`, runs Argon2id (`time_cost=3, memory_cost=102400` KiB ≈ 100 MB, `parallelism=8`, `hash_len=32`) and feeds the result into PBKDF2-HMAC-SHA3_256 with `iterations=110000`. Chaining adds essentially no security over Argon2id alone; `parallelism=8` is hardcoded regardless of host cores. **Fix:** drop the dead `Scrypt` import; use Argon2id alone with documented, tuned parameters.

**S2. Password used as its own pepper — pointless and inconsistent.** *(Medium — `INITIALIZE.py:152, 198`, `BUNKER.py:152`)*
Login/verification call `derive_key_hybrid(password, salt, password)` (pepper = the password itself), adding no secret. Export paths and `verify_setup` pass no pepper at all. A real `PEPPER`/`BUNKER_PEPPER` env mechanism exists (`INITIALIZE.py:609, 1090`) but is never passed into the KDF. **Fix:** remove the anti-pattern; if a pepper is wanted, derive it from a real secret and apply uniformly.

**S3. Login-attempt counter stored under a hardcoded all-zero key — anti-brute-force trivially bypassable.** *(High — `INITIALIZE.py:611-630`, `BUNKER.py:72-76, 203-227`)*
`config.cfg` is AES-GCM-encrypted with `key = hashed_pass or b"0"*32`, and every caller passes no key — so it is always encrypted under a publicly known 32-byte zero key. It holds `attempts`, `max_attempts`, `disable_ipv4`, `current_timeout`. An attacker resets `attempts` before each guess, defeating the headline "3 strikes → self-destruct" protection. **Fix:** store the counter inside the password-encrypted `bunker.cfg`, or use a tamper-evident counter that can't be rolled back without the master key.

**S4. "Secure memory wipe" is a false sense of hygiene.** *(Low — `INITIALIZE.py:97-101, 1159-1162`, `BUNKER.py:232-237, 270`)*
`secure_wipe()` zeroes a 32-byte guard bytearray holding nothing sensitive; actual keys/passwords/decrypted DB are immutable `str`/`bytes`/`dict` that cannot be scrubbed. `del locals()[var]` is a known no-op. **Fix:** stop advertising secure wiping, or hold keys in zeroed `bytearray`s; remove the no-op lines.

**S5. Stored passwords/notes copied to clipboard with NO auto-clear.** *(High — `BUNKER.py:1456, 2105, 2312, 2456, 2935, 3422, 4832, 5179`)*
`to_clipboard()` (30-second clear thread) is used only by the password generator. All 8 sites that copy real stored secrets call `pyperclip.copy()` directly — secrets persist in the clipboard indefinitely. **Fix:** route every copy through `to_clipboard()`.

**S6. Real salt, vault, and known-key config committed to the repo; no `.gitignore`.** *(High — repo root)*
`bunker.salt`, `Bunker.mmf`, `bunker.cfg`, `config.cfg`, `sample_notes_encrypted.json` are all tracked. `config.cfg` is decryptable by anyone (S3). Cloners inherit the author's salt/config instead of a clean setup. **Fix:** untrack, add `.gitignore` (see Seat 4), ship only sample fixtures.

**S7. `self_destruct()` leaves vault backups behind — glob never expands.** *(High — `SHARED_RESOURCES.py:463-550`, `INITIALIZE.py:445-455`)*
`overwrite_db()` creates `Bunker.mmf.bak.<ts>` backups; `self_destruct()`'s list contains the literal string `"*.bak.*"` checked via `os.path.exists` — globs are never expanded, so no backup is ever deleted. Full encrypted vault copies survive self-destruct and can be brute-forced offline against the (committed) salt. The "DoD 3-pass" overwrite is also largely theater on SSD/CoW filesystems. **Fix:** `glob.glob("Bunker.mmf.bak.*")` and include results; limit/rotate backups; don't overstate erase guarantees.

**S8. Destruction targets are CWD-relative.** *(Low — `SHARED_RESOURCES.py:466-487`, `INITIALIZE.py:231-235`)*
Run from the wrong directory, the app neither finds nor protects the real vault and self-destruct silently deletes nothing. **Fix:** anchor all paths to one resolved vault directory.

**S9. "Zero cloud" app silently contacts third parties.** *(Medium — `SHARED_RESOURCES.py:137-159, 649-678`)*
Background IP thread and banner hit ipify, ifconfig.me, icanhazip.com; `check_internet_connection()` opens a socket to `8.8.8.8:53` on a 30-second loop — contradicting "Zero Exposure to Cloud Risks." **Fix:** make network features strictly opt-in/off by default; document the contact.

**S10. `shell=True` in `check_vpn()`.** *(Low — `SHARED_RESOURCES.py:629, 631`)* Constant strings, not injectable today, but unnecessary. **Fix:** list-form `subprocess.run`.

**S11. DEBUG prints and secrets in terminal scrollback.** *(Medium — `BUNKER.py:419, 1452`; `INITIALIZE.py:580`)*
Raw DEBUG output in `displayTimeout` and export verification; shown passwords persist in scrollback. **Fix:** remove DEBUG prints; clear scrollback after showing secrets.

**S12. Unused `keyboard` dependency requires root and is keylogging-capable.** *(Medium — `BUNKER.py:3`)*
Never called; on Linux it pushes users to run a password vault as root (error text at `BUNKER.py:5292` even suggests it). **Fix:** remove entirely; never instruct users to run as root.

**S13. Auto-logout is bypassable and inconsistent.** *(Medium — `BUNKER.py:5265`, `SHARED_RESOURCES.py:795`, `INITIALIZE.py:308-320, 599-606`)*
Timeout value lives in the zero-key `config.cfg` (S3); per-prompt `inputimeout` rather than a global idle timer; several screens print "BEWARE PAGE DOES NOT TIME OUT" and hold the decrypted DB open indefinitely. **Fix:** one authoritative idle timer, value stored under the master key.

**S14. Password length floor weak and inconsistent (6 vs 8); strength meter advisory only.** *(Medium — `INITIALIZE.py:430-432, 1049, 1071, 1665`)*
`MIN_PASSWORD_LENGTH = 6` defined but `< 8` enforced; `"aaaaaaaa"` accepted; `MAX_PASSWORD_LENGTH` never enforced. **Fix:** floor of 12+, enforce a minimum strength score, reconcile constants.

**S15. Vault writes are non-atomic; corruption triggers destruction paths.** *(Medium→Critical in combination — `BUNKER.py:1314, 1746, 2755, 3210, 5007, 4585`; `INITIALIZE.py:894-917, 438-499`)*
Direct `open("Bunker.mmf","wb")` truncate-writes; a partial write plus the decrypt-failure→self-destruct chain means permanent data loss. **Fix:** temp file + `fsync` + `os.replace()` everywhere; centralize on one save function. *(Corroborated by Seat 2, finding C3.)*

**S16. Export verifier is a known-plaintext oracle; weak passphrase floor makes exports the weakest link.** *(Low — `INITIALIZE.py:501-581`)*
Verifier = `Fernet.encrypt(b"VALID_EXPORT_KEY")` enables offline guess-testing; SHA256 squeeze of the derived key is unnecessary. **Fix:** Argon2id directly to the Fernet key; rely on the AEAD tag, or randomize the verifier.

**S17. `random` instead of `secrets` in one delete path.** *(Info — `INITIALIZE.py:263`)* Filename randomness only; use `secrets` consistently.

**S18. Export filenames not path-contained.** *(Low — `BUNKER.py:3608-3618, 4330-4336, 5348`)* User input passed to `open()` unsanitized; `basename()` and restrict to an exports dir.

### Verdict
Sound primitives, undermined by the surrounding implementation. Treat as **not production-ready for real secrets** until S3, S5, S6, S7, and S15 are fixed.

---

## Seat 2 — Correctness & Bugs

### Critical — data destruction / data loss

**C1. Any unexpected exception in the main menu securely wipes the entire vault — with a guaranteed NameError path into it.** *(`BUNKER.py:392-394`, trigger at `331-337`/`341-347`, wipe in `INITIALIZE.py:229-294`)*
The generic `except Exception:` around `manage_passwords_and_notes` calls `vault.secure_delete_on_failure()`, which overwrites and deletes `bunker.cfg`, `Bunker.mmf`, `bunker.salt`. The fallback at 337/347 references `contents` before assignment (first set at line 384), so a transient failure of the very first vault read raises `NameError` → propagates → vault wiped. **Fix:** never destroy data from generic handlers; reserve destruction for explicit tamper/max-attempts logic; fix the undefined `contents`.

**C2. Corrupt/missing `config.cfg` self-destructs the vault; the file is rewritten non-atomically on every login.** *(`INITIALIZE.py:611-630`; called at `BUNKER.py:72, 191, 206, 309, 1102, 2527`)*
`load_ui_config`'s `except: self_destruct()` plus plain truncate-write of `config.cfg` on every attempt: a crash mid-write of a *settings* file destroys all passwords and notes on next launch. **Fix:** regenerate defaults on unreadable UI config; write atomically.

**C3. Every database save is non-atomic truncate-then-write; the one safe writer is never called.** *(`INITIALIZE.py:894-905`; repeated at `BUNKER.py:1314, 1746, 1945, 2573, 2590, 2613, 2755, 3210, 4585, 5007`)*
`open("Bunker.mmf","wb")` zeroes the vault before writing; the "file too small" sanity check fires after the original is already destroyed. `overwrite_db` (backup + restore, `INITIALIZE.py:438-499`) is imported but invoked nowhere. Truncated vault → failed decrypt → C12 → C1's wipe. **Fix:** temp + `fsync` + `os.replace`; one rolling backup.

**C4. SyntaxError on Python ≤ 3.11 — the app cannot start on the most widely deployed Pythons.** *(`BUNKER.py:1940`)*
`print(f"{f'{GOLD},\n{LPURPLE}'.join(...)}")` — backslash in f-string expression is PEP 701 (3.12+). Verified via `ast.parse` on 3.11 → SyntaxError. **Fix:** hoist the separator into a variable (one line).

### High

**C5. Unused `import keyboard as kb` breaks startup on Linux without root.** *(`BUNKER.py:3`)* Import-time `ImportError` for non-root Linux; zero usages. **Fix:** delete the import.

**C6. editNoteData privacy prompt: unreachable code → infinite loop; the private flag can never be changed.** *(`BUNKER.py:3174-3178`)*
The assignment and `break` sit after `continue` inside the invalid-input branch (indent copy-paste bug; compare the correct favorite-flag block at 3155-3162). Typing `y`/`n` re-prompts forever. **Fix:** dedent to match the favorites block.

**C7. tagNotes views/copies the WRONG note's content (stale loop variable).** *(`BUNKER.py:4695, 4773, 4812, 4830`)*
After the display loop, `info` holds the *last* note; selection decrypts with leftover `info`, so any selection other than the last shows/copies another note's content under the selected title. **Fix:** carry `info` in the selection tuple as `displayAllNotes:5119` does.

**C8. changeMasterPassword can permanently lock the user out.** *(`INITIALIZE.py:1644-1738`)*
No confirmation of the new password (typo in hidden input = lockout); `saveDatabase` return ignored at 1733 — on save failure the salt/config are re-keyed but the DB stays under the old key → next login fails → wipe chain. The "same as current" check at 1675-1676 compares keys derived with different pepper conventions and can never match (dead). Rebuild at 1724-1729 silently resets the logout timer to 60. **Fix:** confirm the new password; check the save result and roll back salt/config on failure.

**C9. Configured auto-logout timer is ignored almost everywhere; timer = 0 instantly exits on some paths.** *(`INITIALIZE.py:599-605, 841-843`; `BUNKER.py:137-140, 321`)*
Nearly every prompt uses the default `timeout=60` regardless of the user's setting; with the timer "disabled" (0), the show-password login path times out instantly. Because `timeoutInput` calls `timeoutCleanup()` (`os._exit(0)`) directly, every `== timeoutGlobalCode` branch in all three files is unreachable and the `return True` "timedOut" protocol is fiction. **Fix:** thread the configured value through; handle 0 as "no timeout" uniformly.

**C10. Any failure opening `Bunker.mmf` at startup is treated as "vault missing" — setup then overwrites the existing vault and salt.** *(`BUNKER.py:32-44`; `INITIALIZE.py:1086-1130`)*
A permission/transient error routes into `vaultSetup`, which unconditionally saves an empty DB and rewrites `bunker.salt`/`bunker.cfg`, making any surviving DB undecryptable. `print(vaultSetup())` ignores the result; declining setup proceeds anyway into a `self_destruct()` path (`BUNKER.py:275-277`). **Fix:** distinguish FileNotFoundError from other errors; abort on probe failure; honor the user's decline.

### Medium

**C11. Successful note export exits the whole application.** *(`BUNKER.py:3779` vs correct `4372`)* `return True` means "timed out" in this codebase → bubbles up to `sys.exit(0)`. Export notes, get logged out. **Fix:** `return False`.

**C12. Failed initial DB decrypt swallowed; execution continues with undefined `dataBase`.** *(`BUNKER.py:246-261, 266`)* Prints "Self destructing…" but the call is commented out; then proceeds anyway and lands in C1's wipe handler. **Fix:** fail closed with a clear error, no destruction.

**C13. IP-fetch thread can't be stopped and holds the lock during network I/O.** *(`SHARED_RESOURCES.py:117-135, 172-180`; `INITIALIZE.py:657-659`)*
`stop_ip_fetch_thread` only drops the reference; the `while True` loop keeps curling every 30s after "disable" (privacy-relevant). The `do_run` flag poked at cleanup targets the wrong module's globals and is never read. Lock held across ~10s curl stalls menu renders; banner can show "INTERNET IP: None". **Fix:** a real `threading.Event` stop flag; fetch outside the lock.

**C14. `loadDatabase` missing-file path: prints "Creating new empty database." then self-destructs; `return {}` unreachable.** *(`INITIALIZE.py:931-934`)*

**C15. deleteProfileData: index map has holes when a profile fails to decrypt.** *(`BUNKER.py:1836-1878, 1958`)* `KeyError` on selection; `'a'` deletes profiles the user was never shown. 

**C16. exportProfiles: duplicated `except` clause (second unreachable) and possibly-unbound `field` in the live handler.** *(`BUNKER.py:4282-4295`)*

**C17. main_note_manager refreshes the DB in text mode — `UnicodeDecodeError` swallowed, silently operates on stale data.** *(`BUNKER.py:2556-2565`; correct `"rb"` elsewhere)*

**C18. Undecryptable entries silently vanish from listings; count/index mismatch can IndexError.** *(`BUNKER.py:1386-1388, 2407-2409`; `displayAllNotes:5107-5118`)*

### Low

**C19. Login attempt display: unreachable `elif attempts == 3` branch; counter resettable (see S3); "Attempt 0 of 3" wording.** *(`BUNKER.py:89-105`)*
**C20. `setup_secure_exit_handlers` imported but never called — signal/atexit/excepthook machinery is dead code.** *(`INITIALIZE.py:809-828`; `BUNKER.py:12`)*
**C21. Sample-file schema drift: samples use a `watermark` array, exports write a string; samples don't round-trip.** *(`sample_note.json`, `sample_profile.json` vs `BUNKER.py:3733, 3838, 4315, 4441`)*
**C22. `self_destruct` can't delete backups (see S7); `timeoutCleanup` claims "all data securely saved" even when discarding input, and `os._exit` skips `finally` cleanup.** *(`SHARED_RESOURCES.py:470-474`; `INITIALIZE.py:706`)*

### Top 3 to fix first
1. **Stop destroying the vault in generic error handlers** (C1, C2, C14) and fix the `contents` NameError.
2. **Make all writes atomic** (C3) — one `saveDatabase` with temp + `fsync` + `os.replace`, used everywhere.
3. **Make the program runnable** (C4, C5), then fix `changeMasterPassword`'s unchecked re-key (C8).

---

## Seat 3 — Architecture & Code Quality

**A1. Structure.** Import flow is strictly one-directional (BUNKER → INITIALIZE → SHARED_RESOURCES) — no circular-import risk, good news for splitting. `BUNKER.py` (34 top-level functions) is six modules in one file: app shell/login, profiles CRUD, notes CRUD, tools (generator/strength/system info), settings, crypto helpers. **Eight functions exceed 250 lines** (`exportProfiles` 357, `system_info` 309, `editNoteData` 297, `tagNotes` 281, `exportNotes`/`editProfileData` 270, `main` 259; in INITIALIZE: `display_user_guide` 328); ~20 exceed 140.

**A2. Duplication.** Every profile operation has a hand-copied note twin: `manageNotes`(3486)/`manageProfiles`(4006) are **97% identical**; `main_pwd_manager`/`main_note_manager` 72%; export pair 54% including a verbatim passphrase block (3666/4202); the 20–40% pairs are worse — diverged copies where fixes land in one twin only (C6/C7/C11 are exactly this class of bug). Estimated **600–900 recoverable lines** via a generic "encrypted record collection" parameterized by field schema. The decrypt-loop idiom repeats 10+ times.

**A3. Dead code & imports.** Duplicate `base64` import (`BUNKER.py:1`); unused `keyboard`, `traceback`, `Scrypt`, `Fernet` imports; `overwrite_db` imported, never called. Dead functions: `decrypt_note` (BUNKER.py:1067), `load_encrypted_file` (INITIALIZE.py:583), `fileSetup` (871), `load_max_attempts` (955), `cleanupDatabase` (1925, 68 lines). A vestigial `if __name__ == "__main__":` block sits mid-file at `INITIALIZE.py:1164-1175`. ~29 commented-out lines from an abandoned encrypted-settings experiment (`BUNKER.py:48-63, 161-164, 195, 218-220, 493-510`).

**A4. Dependencies.** Actually used: `cryptography`, `argon2-cffi`, `inputimeout`, `pyperclip`, `psutil`, `requests`. **No requirements.txt/pyproject.toml.** README lists the unused root-requiring `keyboard`; gumroad.md omits `inputimeout` and `argon2-cffi` (customers get ImportError). `psutil`/`requests` could be optional extras.

**A5. Global state.** Module-level `vault = SecureVaultEnhanced()` singleton (INITIALIZE.py:429) with hardcoded relative paths; mutable globals `cached_ip`/`ip_fetch_thread` in SHARED_RESOURCES; the `"*TIMEOUT*"` string sentinel is compared **202 times** in BUNKER.py; `"Bunker.mmf"` is hardcoded 36 times across two files *in addition to* `vault.database_file` — two sources of truth.

**A6. Consistency.** 36 of 98 functions camelCase vs 60 snake_case, mixed within the same file. **Two divergent `generate_password` implementations** (BUNKER.py:1349, 5 lines, `string.punctuation` vs SHARED_RESOURCES.py:1049, 84 lines, curated set) — different password quality under one name. Security parameters (Argon2/PBKDF2 values) inline rather than named constants. 16 ANSI color constants re-imported in three files; imports appear mid-file in SHARED_RESOURCES (line 72).

**A7. Testability — extract and test first.** Zero tests exist. Best candidates: (1) `SecureVaultEnhanced.encrypt_data`/`decrypt_data`/`derive_key_hybrid` round-trip + wrong-key; (2) `generate_export_encryption`/`verify_export_encryption`; (3) `check_password_strength` (pure, table-driven); (4) both `generate_password`s (a test would have caught the divergence); (5) `decode_and_decrypt*` + `saveDatabase`/`loadDatabase` with injectable paths.

**A8. Refactor roadmap (ordered, no rewrite).**
1. **Hygiene pass (½ day, zero risk):** `requirements.txt`; fix the gumroad install line; drop `keyboard`; delete dead imports/functions/commented blocks and the mid-file `__main__`; fix the `contents` NameError.
2. **Package + constants (1 day):** `bunker/` package with `theme.py` and `constants.py` (KDF params, file names, timeout sentinel); keep `BUNKER.py` as a thin launcher so customer instructions don't change; replace the 36 hardcoded vault-path strings.
3. **Split along existing seams (2–3 days, move-only):** `profiles.py`, `notes.py`, `tools.py`, `app.py`; functions already take `(hashed_pass, db)` so they move cleanly; diff reviewable as pure moves.
4. **First tests + CI (1 day), before dedup:** pytest on the A7 list; delete BUNKER.py's 5-line `generate_password` in favor of the SHARED_RESOURCES one.
5. **Deduplicate incrementally:** start with the 97% pair, then a shared `record_menu(...)`, then a common export/import flow; only unify the 20% pairs when touched. Target ~600–900 fewer lines and single-point bug fixes.

Steps 1–2 alone fix the things most likely to cost real customers and take under two days.

---

## Seat 4 — Repo Hygiene, Docs & Packaging

**H1. README claims the wrong Python version — the app doesn't compile below 3.12.** *(High)*
README says "latest stable Python 3 (recommended)"; verified `py_compile` failure on 3.11 at `BUNKER.py:1940` (PEP 701). **Fix:** state "Requires Python 3.12+" in both READMEs, or apply the one-line 3.8+-compatible fix (C4) to widen the paying customer base.

**H2. `keyboard` is a dead dependency that blocks Linux/macOS users.** *(High)* Zero usages; root required on Linux, Accessibility permissions on macOS; listed as required in `README.md:66` with no warning. **Fix:** delete the import; drop from docs.

**H3. gumroad.md install one-liner is broken — paying customers get an ImportError.** *(High — `gumroad.md:62`)*
Missing `inputimeout` and `argon2-cffi`; the root README's bulleted dependency list also omits `argon2-cffi`; gumroad's "WHAT'S IN THE BOX" omits the `main/` package without which the import fails. **Fix:** ship `requirements.txt`, point all docs at `pip install -r requirements.txt`, list the full file set.

**H4. "Military-grade / uncrackable / data never leaves your device" overclaims.** *(High)*
"Military-Grade"/"uncrackable" (`README.md:10,12,18,118`; `gumroad.md:19`); "100% Local… no tracking" vs outbound calls to three IP services and `8.8.8.8:53` (`SHARED_RESOURCES.py:653-662, 162-166`); gumroad simultaneously markets brute-force protection while admitting "attempts is plaintext—fix coming!". **Fix:** replace with verifiable statements ("AES-256-GCM with Argon2id key derivation"); disclose the optional IP-lookup network contact. For a paid security product, overclaims are a refund/reputation/liability risk.

**H5. Proprietary "CPSL v1.0" license while the sales page says "Open Source" — direct contradiction.** *(High)*
CPSL forbids modification/derivatives; `gumroad.md:13,82` says "open source, so you can tweak it yourself" — tweaking violates CPSL §2. The two LICENSE copies also differ textually. Dependencies (Apache-2.0/BSD/MIT) pose no conflict since users install them. **Fix:** pick a real source-available license and remove "open source" from the sales page, or actually go MIT/GPL; keep a single LICENSE copy.

**H6. Live encrypted vault + salt + binary configs committed; no `.gitignore` at HEAD.** *(High)*
All four runtime files tracked since the initial commit; a `.gitignore` existed and was **deleted in `f4beb9a "v1"`**. History scan: nothing sensitive ever committed in plaintext (deleted `.cc.rtf` is pasted CSS; samples are fake data); the committed vault is decryptable by anyone since the demo password `rootroot` is published in `README.md:110`. **Fix:** `git rm --cached Bunker.mmf bunker.salt bunker.cfg config.cfg`; ship a demo vault as an explicitly named fixture; commit the `.gitignore` below. History rewrite not needed today.

**H7. The app mutates tracked binary files in the repo at runtime — guaranteed merge pain, possible wipe.** *(High)*
Relative paths hardcoded (`INITIALIZE.py:31-34`); backups written into the repo (`447-449`); **a missing/corrupted `config.cfg` triggers self-destruct** (`614-629`) — exactly what a checkout/merge/clean can cause with multiple teams in parallel. **Fix:** untrack the runtime files and move state to a user data dir (`~/.bunker/` or `platformdirs`). *The single most important pre-collaboration fix.*

**H8. Duplicated README/LICENSE in `main/`; `main` is a collision-prone package name; casing inconsistencies.** *(Medium)*
`main/README.md` byte-identical to root only by luck (different edit counts); no `__init__.py`; `README.md:93` tells users to delete "`BUNKER.mmf`" which doesn't exist on case-sensitive filesystems (it's `Bunker.mmf`). **Fix:** delete the duplicates; rename the package `bunker/` with `__init__.py`; one casing convention.

**H9. Git history: 15 same-day commits, eight named "README.md"/"Update README.md", author name flips SNOW/Snow, `.DS_Store` churn, no tags despite "v1"/"v1.1" commit messages.** *(Medium)* **Fix:** descriptive messages, `git tag` releases, consistent `user.name`, small scoped commits.

**H10. Stale/erroneous docs.** *(Low)* "ZeroMarks VPN (Q1 2025)" is 18 months past; the pip-requires-this-directory claim is false; Reddit link malformed (`reddit.com/zeromarksllc` → `/r/zeromarksllc`); Troubleshooting split across two sections.

### Proposed `.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/

# Editors / OS
.vscode/
.idea/
.DS_Store
.qodo

# BUNKER runtime state — created/mutated by the app; never commit
Bunker.mmf
Bunker.mmf.bak.*
bunker.salt
bunker.cfg
config.cfg

# User exports (may contain real secrets)
*_export*.json
```

*(Note: the four runtime files are currently tracked — `.gitignore` alone won't help; `git rm --cached` first.)*

### Proposed `requirements.txt`

```text
# BUNKER 2.0 — requires Python >= 3.12 (PEP 701 f-string at BUNKER.py:1940)
cryptography>=42.0    # AES-GCM, Fernet (BUNKER.py:4-5, main/INITIALIZE.py:6-10)
argon2-cffi>=23.1     # Argon2id KDF (main/INITIALIZE.py:11)
inputimeout>=1.0.4    # timed input (main/INITIALIZE.py:13)
pyperclip>=1.8        # clipboard copy/clear
psutil>=5.9           # system info dashboard
requests>=2.31        # external IP lookup
# keyboard            # imported at BUNKER.py:3 but NEVER used; requires root on
#                     # Linux — delete the import instead of installing this
```

---

## Consolidated remediation order

1. **Defuse the data-destruction paths** (C1, C2, C10, C12, C14): remove `secure_delete_on_failure()`/`self_destruct()` from generic exception handlers; fix the `contents` NameError; regenerate UI-config defaults instead of wiping.
2. **Atomic writes everywhere** (C3/S15): one `saveDatabase` and one `save_ui_config` using temp + `fsync` + `os.replace`; route all ~10 raw write sites through them.
3. **Unbreak startup & install** (C4/H1, C5/H2/S12, H3): fix the 3.12-only f-string, delete the `keyboard` import, ship `requirements.txt`, fix gumroad.md.
4. **Fix the lockout/self-destruct security model** (S3, S7, C19): move the attempt counter under the master key; glob-expand and delete backups in self-destruct.
5. **Clipboard hygiene** (S5): route all 8 secret-copy sites through `to_clipboard()`.
6. **Repo decontamination** (S6, H6, H7): `git rm --cached` the four runtime files, commit `.gitignore`, move runtime state out of the repo CWD — do this before the parallel teams collide on binary files.
7. **User-facing correctness** (C6, C7, C8, C11): private-flag infinite loop, tagNotes wrong-note bug, master-password change rollback + confirmation, exportNotes exiting the app.
8. **Truth in marketing & licensing** (H4, H5, S4, S9): align claims with behavior; resolve the open-source/CPSL contradiction.
9. **Architecture** (A8 roadmap): hygiene pass → package split → tests → dedup, in that order.
