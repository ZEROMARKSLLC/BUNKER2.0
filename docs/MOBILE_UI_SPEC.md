# BUNKER 2.0 — Mobile UI Spec (Termux / ≤70-col terminals)

Mobile BUNKER keeps every keybinding, flow, and screen of the desktop app
but swaps the 120-col art/menus for a **56-col vertical layout** selected
once at startup, implemented as `main/UI_MOBILE.py` overriding the same
names `BUNKER.py` already imports from `SHARED_RESOURCES.py`. Core logic is
untouched; the only `BUNKER.py` edits are six inline presentation sites.

**Design target:** 58×32 (Termux portrait). Graceful range 50×25…70×40.
**Max content width: 56 columns.**

## 1. Design principles

1. Vertical, not horizontal — every pipe-separated menu row becomes one
   option per line; single column everywhere.
2. Max content width 56 (ANSI stripped); layout never breaks at 50 cols.
3. **Muscle-memory parity** — keys byte-identical to desktop (`a s d f g c
   r e t x`, view `v/c/.c`, generate `.g`, cancel `.c`); mobile adds only
   `n`/`p` pagination.
4. Art budget ≤8 rows of branding per screen (login art gets 9 — it IS the
   screen; nuke art exempt, app is exiting).
5. **Never resize the terminal** — mobile `check_terminal_size()` measures
   only, warns below 50 cols, emits zero `\033[8;…t` escapes.
6. ASCII-safe glyphs only: no emoji (`⭐→*`, `🔒→[PRIVATE]`), `◢◤` divider →
   `/\`, braille spinner → `- \ | /`.
7. Prompt-adjacent context: soft keyboard leaves ~12–16 rows; everything
   needed to answer a prompt sits in the 14 rows above it. Branding may
   scroll off.
8. Widths computed as `w = min(56, max(48, cols - 2))`.

## 2. Compact branding (canonical — copy verbatim)

`title_art` (5 rows, ≤37 cols; smoke rows FBLUE, letters CYAN):

```
    ( )\    ( /(   ( /(    ( )\ )
    )((_)   )\())  )\())  ( (()/(
  | _ )| | | || \| || |/ / | __|| _ \
  | _ \| |_| || .` || ' <  | _| |   /
  |___/ \___/ |_|\_||_|\_\ |___||_|_\
```

`subwm` (1 row, right-aligned to col 56):

```
                      --=[ PROPERTY OF ZEROMARKSLLC ]=--
```

`divider` (exactly 56 cols, FBLUE): `"/\\" * 28`

Standard mobile header = wordmark + watermark + divider + title line
(8 rows total).

## 3. Screen mockups (58-col frames; `_` = cursor)

### 3.1 Login / BUNKER ACCESS

```
       /\        /\         _
      /$$\  /\  /$$\       ((   +--------------+
     /$$$$\/$$\/$$$$\  /\   `   | PROPERTY OF  |
    / ^ ^ \^ ^/ ^ ^  \/ ^\      | ZEROMARKSLLC |
   / ^ ^ ^ ^ ____ ^ ^ ^ ^ \     |  KEEP OUT!   |
  / ^ ^ __|    |_________ ^\    +--------------+
 / ^ ^ /__________________\ ^\
/^ ^   ||| B-022 |||   |||  ^ \  IP: (disabled)
oooooooooooooooooooooooooooooooooooooooooooooooooo
BUNKER ACCESS
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
Attempt 0 of 3
Security clearance required!
Show your password? (y/n) or exit (e): _
```

Colors: mountains/trees DBLUE, wall grey/CYAN, KEEP OUT! RED, attempt
PURPLE, prompts GOLD. `loading_bar` runs with `length=20`.

### 3.2 Main menu (grouped, vertical)

```
  [ 8-row standard header ]
MAIN MENU - BETA - Auto-Logout: ON
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
 VAULT
  (a) Manage accounts
  (s) Manage notes
 TOOLS
  (f) Generate password
  (r) Check password strength
  (g) User guide
 SETTINGS
  (c) Change login password
  (t) Auto-logout timer
  (d) Display IP
  (e) System info

  (x) Logout

Enter your choice? _
```

Group headers FBLUE, `(key)` GOLD, text CYAN, `(x)` PURPLE.

### 3.3 Account manager (same shape for notes manager)

```
ACCOUNT MANAGER - BETA - Auto-Logout: ON
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
  (a) Add profile        (s) Favorite profiles
  -- rendered one per line:
  (a) Add profile
  (s) Favorite profiles
  (d) Delete profile
  (f) Find profile
  (e) Edit profile
  (r) Read all profiles
  (t) Tags folder
  (c) Export / Import

  (x) Back

What would you like to do? _
```

### 3.4 Profile list (2 lines per entry, paginated)

```
Found 23 profiles - page 1/3

  1* github.com
     u: zeromarks     e: zeromarksllc@gmail.com
  3  my-very-long-self-hosted-domain.duckdns..
     u: admin         e: N/A

(1-23) view pwd  (n)ext  (p)rev  (.c) cancel
Select profile: _
```

Truncation: `{idx:>3}{fav} {domain}` domain budget 51 (49+`..`); line 2 =
username 13 (11+`..`), email 29 (27+`..`). Selection numbers are GLOBAL.

### 3.5 Profile detail / view

```
Profile 3 *
  Domain : my-very-long-self-hosted-domain.duckdns
           .org
  User   : admin
  Email  : N/A
  Pass   : ************

(v) view  (c) copy  (.c) cancel
Do you want to display or copy it? : _
```

Mask is ALWAYS exactly 12 `*` (never leak length). Values >47 chars
chunk-wrap at 47 with 11-space hanging indent — never terminal-wrapped.

### 3.6 Add-profile form — one field per prompt + progress tag

```
ADD A PROFILE                              [1/5]
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
Website domain name  (.c = cancel)
> _
```

`[n/5]` right-aligned col 48, LPURPLE. Label line + bare `> ` input line so
soft-keyboard input wraps under the `>`. Same pattern for edit-profile and
add-note (`[1/4]`).

### 3.7 Notes list + view

```
Found 7 notes - page 1/1

  1* wifi codes
     [home, router]  "admin pass is..."
  2  journal
     [PRIVATE]

(1-7) view  (n)ext  (p)rev  (.c) cancel
Select note: _
```

Tags budget 20 (18+`..`); 3-word preview (matches desktop); private notes
show only `[PRIVATE]` in RED. Note content wrapped with
`textwrap.wrap(width=56)` per paragraph.

### 3.8 Generator

```
GENERATE RANDOM PASSWORD
/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
Min: 6   Max: 64   Recommended: 16

Password length  (.c = cancel)
> _
```

Result: password on its own indented line (chunk-wraps at 54), then
`** Copied to clipboard. Auto-clears in 30s. **` (GREEN).

### 3.9 Timer / settings

```
CHANGE AUTO-LOGOUT TIMER
Current: 60s    Min: 10s   Max: 3600s   Rec: 60s
'0' turns auto-logout OFF (not recommended)

New value in seconds (enter = 60, .c = cancel)
> _
```

### 3.10 Final-attempt warning

```
Attempt 3 of 3
** ALERT: SELF-DESTRUCTING AFTER THIS ATTEMPT **
```

(ALERT on its own ≤48-char RED line.)

### 3.11 Nuke screen (≤48 cols, all RED, last line CYAN)

```
** ALERT: SELF DESTRUCT INITIATED **
+----------------------------------------------+
|        **  THE BUNKER GOT NUKED!  **         |
+----------------------------------------------+
              _.-^^---....,,--
          _--                  --_
         <                        >)
         |                         |
          \._                   _./
             ```--. . , ; .--'''
                   | |   |
                .-=||  | |=-.
                `-=#$%&%$#=-'
                   | ;  :|
          _____.,-#%&$@%#&#~,._____

BUNKER setup will start on next launch
```

## 4. Interaction adaptations

- **Soft keyboard:** prompt + needed context within 14 rows above the
  cursor; footer key-hints always the line immediately above the input;
  `(x)` last in menus; one field per prompt in forms.
- **Pagination:** `page_size = max(4, min(8, (rows - 18) // 2))`; `n`/`p`
  keys additive to existing digit/`.c` loops; count line always shows
  `Found N - page i/k`.
- **Long strings:** lists hard-truncate with `..` (display-only); passwords
  never truncated or terminal-wrapped (dedicated chunk-wrapped line);
  detail views reveal full values.
- **Clipboard:** try `termux-clipboard-set` (timeout 4s) → fall back to
  pyperclip → graceful message: "Clipboard unavailable. Fix: pkg install
  termux-api AND the Termux:API app. Use (v) view instead." The 30-s
  auto-clear uses the same backend it copied with.
- **Timeout display:** `Auto-Logout: ON` (15 chars); degrades to `AL:ON`
  when a title would exceed 56.

## 5. Implementation map

`main/UI_MOBILE.py` overrides (same names): `title_art`, `subwm`,
`divider`, `nuke_art`, `nuke_text`, `display_bunker`, `display_watermark`,
`check_terminal_size` (measure-only), `to_clipboard`/`clear_clipboard`
(termux-aware), ASCII spinner set. (`displayHeader`/`spinning_line` need no
copies — they read module globals.)

New shared render helpers in SHARED_RESOURCES.py (desktop bodies reproduce
today's output byte-for-byte): `menu_header(title)`, `MENU_MAIN`,
`MENU_ACCOUNTS`, `MENU_NOTES`, `render_profile_row`,
`render_profile_detail`, `render_note_row`, `page_size()`.

**Only BUNKER.py edits (presentation, zero logic):** the three menu print
blocks (~349, ~1142, ~2565), the profile list/detail prints (~2444, ~2475),
the notes list print (~5122), plus `n`/`p` in the two list loops.

**Selection — once at startup** (`main/PLATFORM_DETECT.py`):

```python
import os, shutil, sys
def detect_ui():
    forced = os.environ.get("BUNKER_UI", "").lower()
    if forced in ("mobile", "desktop"): return forced
    if os.environ.get("TERMUX_VERSION"): return "mobile"
    if hasattr(sys, "getandroidapilevel"): return "mobile"
    if shutil.get_terminal_size((120, 27)).columns < 100: return "mobile"
    return "desktop"
```

Appended as the LAST lines of SHARED_RESOURCES.py:

```python
from main.PLATFORM_DETECT import detect_ui
IS_MOBILE = (detect_ui() == "mobile")
if IS_MOBILE:
    from main.UI_MOBILE import *   # rebinds art/display symbols
```

This works without touching core logic because BUNKER.py's `from
main.SHARED_RESOURCES import (...)` executes after the module body, so it
binds the already-swapped mobile objects. UI_MOBILE.py must re-declare the
ANSI color literals locally (circular import otherwise).

**Wiring steps (each keeps the app runnable):** 1) PLATFORM_DETECT.py;
2) shared render helpers + point the six BUNKER.py sites at them —
golden-diff desktop output (byte-identical); 3) UI_MOBILE.py; 4) the 3-line
conditional rebinding; 5) `n`/`p` pagination; 6) test matrix
`BUNKER_UI=desktop` (golden) and `=mobile` at 58×32 / 50×25 / 70×40.

## 6. Acceptance checklist

1. Every screen ≤56 visible cols; zero uncontrolled wraps at 50 cols.
2. No resize escapes emitted on mobile (grep + runtime capture).
3. Every flow completable in Termux portrait with soft keyboard open.
4. Keybindings byte-identical to desktop; `n`/`p` the only additions.
5. No emoji / ambiguous-width glyphs in mobile output.
6. Pagination + global indices + truncation rules hold for 60-char values.
7. Masked passwords constant-width; revealed passwords never truncated.
8. Clipboard works via termux-api; absent → graceful message, no crash.
9. `BUNKER_UI=desktop` output byte-identical to pre-port (golden test);
   override order BUNKER_UI > TERMUX_VERSION > width; detection runs once.
10. Zero diffs in crypto/storage/session logic — change set is
    PLATFORM_DETECT.py + UI_MOBILE.py + SHARED_RESOURCES additions + six
    presentation sites.
