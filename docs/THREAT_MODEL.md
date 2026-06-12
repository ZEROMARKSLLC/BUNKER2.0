# BUNKER 2.0 — Threat Model

A persona-based threat model of the *running* application (complements the
code-level audit in `COUNCIL_REVIEW.md`). Status reflects the hardened branch:
atomic writes + `.bak`, force-gated self-destruct, device-bound config key,
pepper fix with legacy fallback, universal auto-logout, clipboard auto-clear
on all secret copies.

## Personas — what each attacker gets

### 1. Stolen/lost laptop (powered off, no full-disk encryption)
Attacker holds every file and can guess offline against the verifier with no
rate limit. **The math holds:** Argon2id(t=3, 100 MiB, p=8) → PBKDF2-SHA3
limits a serious single rig to ~100 guesses/sec (~31 bits/year). A random
12-char password or 5-word passphrase survives indefinitely; an 8-char
dictionary-ish password falls in days-to-weeks. `bunker.devkey` only unlocks
non-secret UI state — by design. **Wildcard:** if the machine slept while the
vault was unlocked, keys/plaintext may be carved from swap/hibernation,
bypassing the KDF entirely (Python strings cannot be wiped).
**Mitigation:** enforce a real strength gate at setup (wire in the existing
`check_password_strength`); document that FDE is required.

### 2. Snatched unlocked session
Full vault access until logout. Auto-logout now applies to every
`timeoutInput` prompt (configured value, 0 = disabled by explicit choice);
remaining gaps are bare `input()` confirms and the network-info page.
Clipboard copies of stored passwords now auto-clear after 30 s. Viewed
secrets are printed to the screen; `clear_screen()` emits `\033[3J` on the
next redraw, but terminals that ignore it (or tmux capture/recorders) retain
scrollback.

### 3. User-level malware on the host
**Out of scope — BUNKER trusts the host.** A keylogger captures the master
password; memory scraping lifts keys from the Python heap; nothing prevents
replacing `BUNKER.py` itself. The README must say this plainly.

### 4. Evil maid (edit code, return later)
Three added lines to `BUNKER.py` exfiltrate the master password on next
login. **Nothing detects modified code** — the "Checking files for
tampering" spinner performs no check (AES-GCM authenticates data files
only). Mitigation: a startup hash-manifest self-check at the spinner's hook
point (advisory; real protection is FDE/verified boot).

### 5. Coercion / border crossing
The burner story works: 3 wrong guesses wipe vault + salt + devkey + all
`.bak` files (glob fix verified). Caveats: destruction is loudly announced
(nuke art — escalation risk), SSD wear-leveling means overwrite is
best-effort, and a pre-coercion disk image makes destruction moot. **No
decoy/duress vault exists** — the only lever is visible destruction.

### 6. Shoulder surfer / nosy housemate
Masked by default; the "show password" login option is the main exposure.
A housemate idly guessing 3 times destroys the vault (counter persists
across sessions — intentional, but warn when attempts > 0 at launch).

## Residual risk

| Persona | Residual risk after current hardening |
|---|---|
| Stolen laptop, no FDE | HIGH with weak password; LOW with strong password + FDE |
| Snatched unlocked session | MEDIUM (timer now universal; scrollback remains) |
| User-level malware | CRITICAL — out of scope by design |
| Evil maid | CRITICAL — no code integrity check |
| Coercion | HIGH — no decoy; destruction is overt |
| Shoulder surfer | MEDIUM — show-password option; 3-try wipe footgun |

## Top mitigations by (risk reduced ÷ effort)

1. ~~Universal auto-logout + clipboard auto-clear on all copies~~ **DONE on this branch.**
2. Strength gate / generated passphrase at vault setup (use existing `check_password_strength`). Effort S.
3. Duress/decoy vault + silent lockout wipe (second password → benign vault). Effort M.
4. Startup integrity self-check replacing the cosmetic tamper spinner. Effort M.
5. Grace warning / typed confirmation before the third (destructive) attempt; warn at launch when attempts > 0. Effort S.

## README-ready honest threat model

> ### What BUNKER protects against — and what it doesn't
>
> BUNKER encrypts your vault with AES-256-GCM and derives the key from your
> master password using Argon2id + PBKDF2-SHA3. **Everything depends on (a)
> your master password's strength and (b) the security of the computer you
> run it on.**
>
> **BUNKER protects you against:**
> - **Someone who finds your vault files without your password** — provided
>   the password is strong. A random 12+ character password or 5+ random-word
>   passphrase is effectively uncrackable offline; a short or guessable one
>   is not.
> - **Accidental data loss** — saves are crash-safe (atomic writes with a
>   `.bak` backup) and ordinary errors never delete your vault.
> - **Casual snooping** — passwords are masked by default and the clipboard
>   auto-clears 30 seconds after any copy.
>
> **BUNKER does NOT protect you against (a local terminal app can't):**
> - **Malware on your computer** — a keylogger captures your master password;
>   memory scrapers can read secrets while BUNKER runs. Keep the machine clean.
> - **A tampered copy of BUNKER** — the program does not verify its own code.
>   Protect the device with full-disk encryption and Secure Boot.
> - **A stolen laptop without full-disk encryption** — and if the machine
>   slept while unlocked, keys may be recoverable from swap/hibernation.
>   Always enable FDE.
> - **An unlocked, unattended session** — lock your screen; don't disable the
>   auto-logout timer.
> - **Coercion** — there is no decoy vault; unlocking reveals your real data.
>   Three wrong attempts permanently destroy the vault (including backups).
>
> **Bottom line:** BUNKER is a strong *local* vault for a *trusted* computer
> with a *strong* master password and full-disk encryption underneath it.
