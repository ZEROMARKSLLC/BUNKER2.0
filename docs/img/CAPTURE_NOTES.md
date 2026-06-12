# README Screenshot Capture Notes

All images in this directory are **real captures of the running app**, produced
fully headless by `capture_screens.py` (in this directory). They contain **only
fake demo data** and were taken with IP display **disabled** (the default).

## How they were generated

Pipeline (no display server, no terminal emulator window):

1. **Throwaway shoot copies.** The repo is copied to `/tmp/shoot` (and
   `/tmp/shoot2` for the self-destruct shot). All vault files (`Bunker.mmf`,
   `bunker.cfg`, `bunker.salt`, `config.cfg`, `bunker.devkey`) are deleted so
   each run starts from a **fresh demo vault** (password `rootroot`, the
   public demo password). A stub `pyperclip.py` is dropped into the shoot copy
   so clipboard calls succeed on headless Linux (no xclip) — repo files are
   never modified, and the app is never run inside the repo checkout.
2. **Driving the app.** `BUNKER.py` runs under a pty via `pexpect` with a
   124x34 terminal. The script answers the `vaultSetup()` prompts (show
   password: `y`, password `rootroot`, default 60 s auto-logout), then walks
   the menus, seeding 3 fake profiles (`example.com`, `mail.example.org`,
   `vault.example.net` with `*@bunker.local` users) and 2 fake notes
   ("Cabin WiFi — Router Setup", "Demo Backup Codes (FAKE)" with
   `XXXX-0000-DEMO`-style placeholder bodies).
3. **Screen capture.** Child output is fed into a `pyte` virtual terminal
   (124x34). At each target screen the script waits for a landmark string and
   then for the screen to stop changing, then snapshots every cell with its
   character, fg/bg color, and bold flag.
4. **Rendering.** Snapshots are rendered to PNG with Pillow at ~2x scale:
   DejaVu Sans Mono 22 px on a `#0b0e14` background, 28 px line height, 24 px
   padding (1691x1000 px output). pyte's 256-color cells (e.g. `38;5;159`,
   `38;5;214`) map straight to hex; classic bright colors use a dark-theme
   terminal palette. Emoji that DejaVu lacks are rendered through **Noto Color
   Emoji** (CBDT bitmaps, downscaled per cell), so the menu icons appear in
   color rather than as tofu.
5. The self-destruct shot is taken in a **second disposable copy**
   (`/tmp/shoot2`): three failed logins trigger the real wipe there, and the
   final red nuke screen is captured at process exit.

## Captured screens

| File | Screen |
|------|--------|
| `01-access.png` | BUNKER ACCESS page at the password prompt (bunker art, KEEP OUT, "(IP fetching disabled)", Attempt 0 of 3) |
| `02-main-menu.png` | MAIN MENU after login (both option rows + auto-logout readout) |
| `03-account-manager.png` | ACCOUNT MANAGER menu |
| `04-view-profile.png` | Favorite profiles list — domains/usernames visible, passwords not displayed |
| `05-notes.png` | View-all-notes list with the 2 demo note titles |
| `06-generator.png` | Password generator with a freshly generated throwaway password |
| `07-self-destruct.png` | Red nuke screen after 3 failed logins (taken in the disposable copy) |
| `08-hero.png` | Hero shot (re-render of the access page snapshot) |

## Limitations

- **Emoji metrics:** emoji are drawn from Noto Color Emoji into their terminal
  cell; exact spacing around emoji can differ by a cell from GPU terminal
  emulators (pyte counts some emoji single-width). Variation selectors
  (U+FE0F) are stripped from the stream — pyte 0.8.2 otherwise drops the rest
  of the line after one.
- The spinner/loading animations are transient and not captured.
- Colors use a fixed dark palette approximating a modern terminal theme; a
  user's terminal theme will differ.

## Regenerating

```bash
pip install pexpect pyte Pillow fonttools
python3 docs/img/capture_screens.py            # writes PNGs to docs/img/
python3 docs/img/capture_screens.py /some/dir  # or elsewhere
```

The script only ever runs the app in `/tmp/shoot` / `/tmp/shoot2`; the
self-destruct it triggers wipes those throwaway vaults only. Raw snapshots
(text + JSON, for debugging or re-rendering) land in `/tmp/bunker_snaps`.
