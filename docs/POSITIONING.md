# BUNKER 2.0 — Market & Positioning

**The strategic call:** BUNKER cannot win as a serious security tool against
KeePassXC (audited, free, 10+ years) or `pass` — so don't compete there.
Position it as a **security-themed terminal experience with real crypto**:
"the password manager that's also a vibe." The burner-vault is the identity
hook; radical honesty (the threat model) is the trust mechanism; the video
channels are the growth engine.

## Competitive reality

| vs. | They win on | BUNKER wins on |
|---|---|---|
| pass/gopass | Maturity, GPG, git sync, scriptability | Personality, zero-ceremony setup |
| KeePassXC | Independent audit, browser/TOTP/hardware keys, .kdbx open format | Experience, burner concept, PWYW impulse buy |
| Bitwarden/1Password CLI | Sync, audits, enterprise trust | Fully offline, no account, one file |

Concede openly: no audit, no sync, no browser integration, proprietary
format, solo dev. Own openly: nothing else *feels* like anything —
`keepassxc-cli` is a tax form, BUNKER is a hacker movie. That difference is
real, defensible, and the only one visible in a 30-second video.

## Personas (priority order)

1. **Terminal Aesthete** (r/unixporn, dotfiles culture) — wants another
   beautiful TUI. Pitch: "the most cinematic thing in your terminal — and it
   actually encrypts." Bounces on: broken installs. First 90 seconds are
   everything.
2. **OPSEC Hobbyist** — loves the burner fantasy. Pitch: "three wrong
   guesses and it's gone forever, by design." Will read THREAT_MODEL.md —
   publish it prominently; honesty is the only way to hold this persona.
3. **Security Student** — wants to read real Argon2id/AES-GCM code.
   Currently blocked by the no-modification license.

## Positioning statement

> For terminal enthusiasts and privacy hobbyists, BUNKER is the offline
> vault that turns password management into an experience — real
> AES-256-GCM and Argon2id under full-screen hacker-movie theater, with a
> burner-vault self-destruct that means it. It's not trying to be your
> enterprise password manager; it's the cold vault with a personality, and
> it tells you its exact limits up front.

**Taglines:** brand line — *"Real encryption. Maximum drama."* Video hook —
*"Three strikes and it's ash."* Retire "Your Digital Fortress" (generic, and
points at the unwinnable serious-tool framing).

## Pricing / offer

- **$0+ BUNKER Core** (the free tier IS the marketing) with **suggested
  price $7** — anchoring roughly doubles average contribution vs a bare $0+.
- **$15 Supporter Edition:** theme packs (amber CRT, matrix green,
  blackout), custom art slots, name in SUPPORTERS, early mobile access,
  feature-queue vote. **Never paywall security fixes.**
- Sober expectations: terminal-tool PWYW is a $50–300/month category with
  viral spikes ($500–2k in a good week). Primary ROI = audience growth for
  the channels and future products; Gumroad revenue is the bonus.
- **License:** recommended dual-track — open-source the crypto/storage core
  (MIT/Apache), keep art/themes/supporter extras proprietary. Source-
  available currently blocks awesome-lists, AUR/Homebrew, and persona 3.
  Minimum fix: permit personal modification, and delete "open source" from
  all copy.

## Distribution & content

10 video ideas (YouTube/TikTok), led by:
1. **"I gave my password manager a self-destruct"** — the flagship; pin it.
2. POV horror-comedy: sweating through attempt 3 of 3.
3. "Zero to encrypted vault in 60 seconds" speedrun.
4. "Your password manager is a SaaS. Mine is a bunker." (punch at clouds,
   never at KeePassXC/pass — their communities are your distribution).
5. "What's actually inside the encryption" — 90s Argon2id→AES-GCM explainer.
6. "I tried to crack my own vault" — the threat model as content.
7. ASCII-art making-of (r/unixporn crossover; invite theme submissions).
8. "Things my password manager will NOT protect you from" — read the threat
   model's honest list to camera.
9. BUNKER on a phone (when Termux ships).
10. "Roast my code" live hardening series.

**Venue rules:** r/unixporn/r/commandline = lead with aesthetics.
r/privacy/HN = lead with the threat model and concede limits in your own
top comment; overclaiming there is permadeath. Terminal Trove/awesome-lists
often require OSI licenses (another CPSL cost).

**Sequencing rule:** video channels now; HN/r/privacy only after the
Gumroad page is rewritten (see Risks).

## Top 3 risks

1. **"Military-grade" backlash — currently armed.** The Gumroad page still
   says "open source" (false per license), "military-grade," and "fresh 3
   tries every session" (false — counter persists). Rewrite it to match the
   README's honest voice **before any technical-venue promotion**. Claims
   rule: every security statement must trace to THREAT_MODEL.md.
2. **The burner eats a real user's data.** One credible "BUNKER deleted my
   passwords" post ends the product. Done on this branch: wipe gated to the
   lockout path, atomic saves, .baks. Still recommended: warn at launch when
   attempts > 0, typed confirmation before the fatal third attempt, and
   consider shipping self-destruct **off by default** behind an explicit
   "arm the burner" ceremony (keep the identity, save casual users).
3. **License friction poisons OSS venues.** "Auditable but unforkable"
   reads as marketing to the exact communities the distribution plan needs.
   See the dual-track recommendation above.
