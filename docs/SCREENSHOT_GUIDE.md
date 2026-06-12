# BUNKER 2.0 — Screenshot & Visual Asset Guide

A repeatable recipe for replacing the video-grab screenshots with crisp, consistent,
leak-free assets. End-to-end this is roughly a 2-hour job.

## Why the old screenshots look bad

The current README images are ~1005px frame-grabs from YouTube. Video codecs (H.264/VP9)
use 4:2:0 chroma subsampling, which halves color resolution — and BUNKER's entire UI is
1px-wide cyan/gold glyphs on black, the worst case for that compression. The result is
smeared, ringing text. The fix is to capture the terminal **directly as a lossless PNG**,
at 2x scale, from a deliberately configured window. Never route the pixels through video.

Other problems to fix: odd/mismatched dimensions, visible window chrome and desktop edges,
mid-keystroke cursor states, washed-out contrast, and (critically) real data in frame.

## The "studio" terminal profile

Set this up once and reuse it for every shot. **Target 124 columns × 34 rows** (the app
minimum is 120×27; the margin stops `check_terminal_size()` from firing its resize escape
mid-capture).

- **Font:** JetBrains Mono Regular, 13–14pt, anti-aliased, **ligatures off**.
- **Background:** solid near-black `#0b0e14`; foreground `#e6e6e6`. Keep bright ANSI vivid.
  Good schemes: One Dark / One Half Dark / Builtin Dark. **Avoid Solarized** (it mutes the
  gold prompts to olive).
- **Chrome:** hide title bar/tabs (iTerm2 "Minimal" theme; Windows Terminal focus mode;
  Alacritty `decorations = "None"`). Hide scrollbars. Padding ~12px.
- **Cursor:** underline, blinking off.
- **Color emoji:** ensure the terminal renders it (Linux: install `fonts-noto-color-emoji`).

**Capture at 2x.** On a Retina Mac, `Cmd+Shift+4` → `Space` → click the window gives a
pixel-perfect 2x PNG with a native drop shadow (free framing). On Windows/Linux, use a
HiDPI display at 100%/200% scaling (never fractional 125/150% — it blurs text), or bump the
font large enough that the source PNG is ≥1800px wide, then downscale once with Lanczos:

```bash
magick raw.png -filter Lanczos -resize 1600x docs/img/02-main-menu.png
```

> Carbon / ray.so won't work here — they re-render *plain source text*, not live ANSI
> output. For non-interactive command output you could use `termshot` or Charm's
> `freeze --execute`, but BUNKER is an interactive loop, so real window screenshots are the
> primary method.

## Animated hero — VHS (recommended)

Charm's [VHS](https://github.com/charmbracelet/vhs) records from a scripted `.tape` file, so
the demo is reproducible and re-shoots identically after any UI change. The ready-to-run
tape lives at the repo root: **`bunker-demo.tape`**.

```bash
brew install vhs            # macOS;  Linux: go install …/vhs@latest + ttyd + ffmpeg
vhs bunker-demo.tape        # writes docs/img/bunker-demo.gif
gifsicle -O3 --lossy=80 --colors 128 docs/img/bunker-demo.gif -o docs/img/bunker-demo.gif
```

Storyboard (~25s): ACCESS page (3s) → login (3s) → main menu linger (3s) → generate a
16-char password (5s) → add an `example.com` profile (7s) → notes glance (3s) → logout (1s).
One idea per beat; never two screens in under 2 seconds. Target GIF **< 2.5 MB** (drop to
`Set Framerate 12` if it's stubborn).

Lighter alternative: `asciinema rec` + `agg` — also gives you a shareable `.cast` to embed.

## Shot list

All stills: same 124×34 window, captured at 2x, downscaled once to **1600px wide**. Shoot
them in one sitting so colors/dimensions match.

| # | File | What's on screen | Caption |
|---|------|------------------|---------|
| 0 | `docs/img/bunker-demo.gif` | Animated walkthrough | "BUNKER 2.0 — 25-second tour" |
| 1 | `docs/img/01-access.png` | ACCESS page: full bunker ASCII art, "KEEP OUT" sign, `(IP fetching disabled)`, clearance prompt | "The vault door: brute-force tracking and self-destruct after 3 failed attempts." |
| 2 | `docs/img/02-main-menu.png` | MAIN MENU: BUNKER figlet, timer readout, both option rows | "Everything is local — accounts, notes, generator, system info." |
| 3 | `docs/img/03-account-manager.png` | ACCOUNT MANAGER menu | "AES-256-encrypted profiles with tags, favorites, and search." |
| 4 | `docs/img/04-view-profile.png` | A viewed demo profile (masked password, clipboard-cleared message) | "Passwords stay masked; clipboard auto-clears after 30 seconds." |
| 5 | `docs/img/05-notes.png` | Notes list with 2–3 demo titles | "Encrypted notes for everything that isn't a password." |
| 6 | `docs/img/06-generator.png` | Generator with a fresh 16-char result | "Cryptographically secure passwords (`secrets`), any length." |
| 7 | `docs/img/07-self-destruct.png` | Red nuke art + "The Bunker Got NUKED!" | "Three strikes and the vault shreds itself — by design." |
| 8 | `docs/img/08-system-info.png` *(optional)* | System/Hardware sections only (crop before network details) | "Built-in system monitor." |

**Hero choice:** the GIF up top; for a static hero/Gumroad cover (1280×720) use a 16:9 crop
of `01-access.png` — the bunker art is the most brandable frame in the app.

> **Capturing shot 7 safely:** self-destruct really shreds the vault files. Do it in a
> throwaway copy: `cp -r BUNKER2.0 /tmp/bunker-shoot && cd /tmp/bunker-shoot`, fail login 3×,
> screenshot, delete the copy.

## Safety: fake-data discipline

Build a dedicated demo vault (delete `Bunker.mmf` in the shoot copy, run setup, password
`rootroot`) and seed only obviously-fake data:

- Domains: `example.com`, `mail.example.org`, `vault.example.net` (reserved, unmistakably fake)
- Usernames: `demo@bunker.local`, `operator.b022@bunker.local`
- Passwords: shown masked (`••••••••`); any generated value is a throwaway shown once
- Notes: "Cabin WiFi — Router Setup", "Demo Backup Codes (FAKE)" with bodies like `XXXX-0000-DEMO`

**Hard rules for every capture:**
1. **IP display OFF** — the ACCESS art and watermark print your real public IP when enabled.
   The frame must read `(IP fetching disabled)`.
2. Never screenshot your real vault, even "just the menu."
3. System-info shot: crop/skip Network Information (real IPs, MACs, hostname, PIDs).
4. Generated passwords shown on screen are generated for the shot and reused nowhere.
5. Before committing, zoom each PNG to 100% and proofread for IPs, hostname, username, real
   domains, and any menu-bar clock/notifications.

## Asset hygiene

```
docs/img/
  README.md            # shoot settings note (terminal, font, window, "IP off, demo only")
  bunker-demo.gif
  01-access.png … 08-system-info.png
  gumroad-cover.png
```

- Reference images with **relative paths** (`docs/img/…`), not anonymous
  `github.com/user-attachments/…` blobs — versioned, renamable, reusable on Gumroad.
- **Consistent dimensions:** every still exactly 1600px wide; images sharing a README row
  must match exactly or GitHub renders them ragged.
- **Alt text on every image** — descriptive, for accessibility and SEO.
- **Compress** (terminal shots compress beautifully — target <150KB/PNG, <2.5MB GIF):

```bash
pngquant --quality 70-95 --ext .png --force docs/img/*.png
oxipng -o 4 --strip safe docs/img/*.png
gifsicle -O3 --lossy=80 --colors 128 docs/img/bunker-demo.gif -o docs/img/bunker-demo.gif
```

- Don't commit raw 2x originals or `.cast` working files (gitignore a `docs/img/raw/`).

## Execution order

1. Build the studio terminal profile.
2. Make a `/tmp` shoot copy + demo vault + IP display off.
3. Shoot stills 1–8 in one sitting.
4. Record `vhs bunker-demo.tape`.
5. Compress everything.
6. Proofread at 100% zoom for leaks.
7. Commit to `docs/img/` and swap `docs/README.draft.md` in as the live `README.md`.
