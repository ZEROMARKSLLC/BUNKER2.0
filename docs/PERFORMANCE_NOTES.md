# BUNKER 2.0 — Performance Notes

Measured on a 4-core x86 dev box (Python 3.11). Phone numbers are estimates
anchored to these measurements (low-end Android ≈ 4-8× slower for memory-hard
KDF work).

## Login KDF (measured)

| Component | Time |
|---|---|
| Argon2id (t=3, m=100 MiB, p=8) | 178 ms |
| PBKDF2-HMAC-SHA3-256 (110k iters) | 141 ms |
| **One full derivation** | **319 ms** (peak ~123 MiB) |

**Fixed on this branch:** `derive_candidate_keys` is now lazy and the login
verifier check reuses the key that decrypted the config instead of
re-deriving. Result: new-scheme vault login = **1 derivation (~0.32 s)**;
legacy vault = 2 (~0.64 s, drops to 1 after the next master-password change);
wrong password = 2 (unavoidable with the legacy fallback).

## Remaining recommendations (not yet applied)

| # | Item | Impact | Effort |
|---|---|---|---|
| 1 | **Calibrate Argon2 at vault creation** for the device (~0.5-1 s target; RFC 9106 constrained floor t=3/m=64 MiB/p=4; p=min(4, cores)); store params plaintext beside the salt (they are not secret — every Argon2 encoded hash embeds them). Required for phones: current 100 MiB/p=8 projects to 1.3-2.6 s per derivation and risks lmkd OOM kills on 2 GB Android devices. | Phone login ~1 s | M |
| 2 | Swap PBKDF2-SHA3-256 → PBKDF2-SHA256 for new vaults (SHA3 has no hardware acceleration; it is 44% of KDF time for symmetric attacker/user cost). | −141 ms/derivation | S |
| 3 | **Cut animation sleeps**: `spinning_line` + `loading_bar` block up to ~3.9 s before the password prompt — more than 10× the actual crypto. Cap at ~0.3 s or overlap with real work. | −1 to −3.6 s perceived startup | S |
| 4 | Lazy-import `requests` and `psutil` inside the screens that use them (~175 ms of every desktop startup, ~1 s phone, for screens most sessions never open). | Faster startup | S |
| 5 | Lazy field decryption / per-session domain cache on list screens (only matters past ~1,000 entries: 564 ms desktop at 10k). | Large-vault list screens | M |
| 6 | Replace recursion-based retry loops (`changeMasterPassword`, browse screens) with loops — stack growth pins secrets in dead frames. | Hygiene | S |

## Fixed on this branch

- KDF deduplication (3-4 runs/login → 1-2).
- IP-fetch thread is now event-stoppable (was: one permanently-leaked thread
  per display toggle, each hitting the network every 30 s) and no longer holds
  the cache lock during the network call (was: UI freezes up to ~15 s).
- `timeoutInput` reads the configured auto-logout value (one tiny config
  decrypt per prompt — negligible).

## Measured: what NOT to change

- **Keep** the `saveDatabase` round-trip verify: ≤24 ms even at 10,000 entries
  — the cheapest insurance in the codebase.
- **Keep** desktop KDF cost. Whole-DB crypto scales fine (10k entries:
  load 29 ms, save 48 ms).
