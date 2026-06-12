#!/usr/bin/env python3
"""
BUNKER 2.0 — headless README screenshot pipeline.

Drives BUNKER.py inside a pty (pexpect), interprets the ANSI output with a
virtual terminal (pyte, 124x34), and renders color-faithful PNGs with Pillow
(DejaVu Sans Mono + Noto Color Emoji fallback for glyphs DejaVu lacks).

SAFETY: this script must ONLY ever be pointed at throwaway copies of the repo
under /tmp (default /tmp/shoot and /tmp/shoot2). The self-destruct sequence
really wipes vault files in its working directory.

Usage:  python3 capture_screens.py [output_dir]
"""

import codecs
import json
import os
import shutil
import sys
import time

import pexpect
import pyte
from PIL import Image, ImageDraw, ImageFont

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
COLS, ROWS = 124, 34
SHOOT_DIR = "/tmp/shoot"
SHOOT2_DIR = "/tmp/shoot2"
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "/home/user/BUNKER2.0/docs/img"
SNAP_DIR = "/tmp/bunker_snaps"          # raw snapshots (json + txt) for debugging
DEMO_PASSWORD = "rootroot"              # demo vault password (public, fake)

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FONT_EMOJI = "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf"
FONT_SIZE = 22
LINE_H = 28                              # ~1.27x line height
PAD = 24
BG = "#0b0e14"
FG_DEFAULT = "#d4d4d4"

# Map pyte's classic color names to hex (dark-theme terminal palette).
PALETTE = {
    "black": "#1c2027",
    "red": "#cd4a4a",
    "green": "#0dbc79",
    "brown": "#d7a700",          # pyte's name for ANSI yellow (33)
    "blue": "#3273c4",
    "magenta": "#bc3fbc",
    "cyan": "#11a8cd",
    "white": "#d4d4d4",
    "brightblack": "#707a8a",
    "brightred": "#f14c4c",
    "brightgreen": "#23d18b",
    "brightyellow": "#f5e34a",
    "brightblue": "#3b8eea",
    "brightmagenta": "#d670d6",
    "brightcyan": "#29b8db",
    "brightwhite": "#ffffff",
    "default": FG_DEFAULT,
}

# ----------------------------------------------------------------------------
# Glyph coverage (which chars DejaVu can draw, which need the emoji font)
# ----------------------------------------------------------------------------
try:
    from fontTools.ttLib import TTFont
    _DEJAVU_CMAP = set(TTFont(FONT_REG).getBestCmap().keys())
    _EMOJI_CMAP = set(TTFont(FONT_EMOJI).getBestCmap().keys())
except Exception:                        # degrade: assume DejaVu covers all
    _DEJAVU_CMAP = None
    _EMOJI_CMAP = set()


def glyph_class(ch):
    """'text' | 'emoji' | 'blank' for a single character."""
    cp = ord(ch)
    if cp in (0xFE0F, 0x200D):
        return "blank"
    if _DEJAVU_CMAP is None or cp in _DEJAVU_CMAP:
        return "text"
    if cp in _EMOJI_CMAP:
        return "emoji"
    return "blank"


# ----------------------------------------------------------------------------
# Terminal driver
# ----------------------------------------------------------------------------
class Term:
    """pexpect child + pyte virtual screen."""

    def __init__(self, cwd):
        env = dict(os.environ)
        env.update({
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "COLUMNS": str(COLS),
            "LINES": str(ROWS),
        })
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream = pyte.Stream(self.screen)
        # pyte 0.8.2 mis-renders emoji variation selectors (U+FE0F): it drops
        # the rest of the line after one. Decode incrementally and strip them.
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.child = pexpect.spawn(
            sys.executable, ["BUNKER.py"],
            cwd=cwd, env=env, dimensions=(ROWS, COLS), timeout=10,
        )

    # -- plumbing ------------------------------------------------------------
    def _pump(self, wait=0.05):
        """Feed any pending child output into pyte. Returns bytes consumed."""
        got = 0
        while True:
            try:
                data = self.child.read_nonblocking(size=65536, timeout=wait)
            except pexpect.TIMEOUT:
                break
            except pexpect.EOF:
                break
            if not data:
                break
            text = self._decoder.decode(data)
            self.stream.feed(text.replace("\ufe0f", "").replace("\u200d", ""))
            got += len(data)
            wait = 0.05
        return got

    def display(self):
        return "\n".join(self.screen.display)

    def wait_for(self, text, timeout=120):
        """Wait until `text` shows up on the virtual screen."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._pump(0.1)
            if text in self.display():
                return True
        raise TimeoutError(f"never saw {text!r}; screen:\n{self.display()}")

    def wait_stable(self, quiet=0.8, max_wait=10):
        """Wait until the screen stops changing for `quiet` seconds."""
        deadline = time.time() + max_wait
        last = self.display()
        last_change = time.time()
        while time.time() < deadline:
            self._pump(0.1)
            cur = self.display()
            if cur != last:
                last, last_change = cur, time.time()
            elif time.time() - last_change >= quiet:
                return
        return

    def sendline(self, s=""):
        self.child.sendline(s)

    def drain_to_eof(self, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = self.child.read_nonblocking(size=65536, timeout=0.5)
                if data:
                    text = self._decoder.decode(data)
                    self.stream.feed(text.replace("\ufe0f", "").replace("\u200d", ""))
            except pexpect.TIMEOUT:
                if not self.child.isalive():
                    return
            except pexpect.EOF:
                return

    def close(self):
        try:
            self.child.close(force=True)
        except Exception:
            pass

    # -- capture ---------------------------------------------------------------
    def snapshot(self):
        """Freeze the screen into [[(char, fg, bg, bold), ...] x ROWS]."""
        rows = []
        buf = self.screen.buffer
        for y in range(ROWS):
            line = buf[y]
            row = []
            for x in range(COLS):
                c = line[x]
                data = c.data.replace("\ufe0f", "")
                row.append((data, c.fg, c.bg, bool(c.bold), bool(c.reverse)))
            rows.append(row)
        return rows


# ----------------------------------------------------------------------------
# Renderer
# ----------------------------------------------------------------------------
_font_reg = ImageFont.truetype(FONT_REG, FONT_SIZE)
_font_bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)
try:
    _font_emoji = ImageFont.truetype(FONT_EMOJI, 109)   # CBDT strike size
except Exception:
    _font_emoji = None
_CW = _font_reg.getlength("M")           # monospace advance (float)
_emoji_cache = {}


def _emoji_tile(ch, height):
    key = (ch, height)
    if key in _emoji_cache:
        return _emoji_cache[key]
    if _font_emoji is None:
        return None
    img = Image.new("RGBA", (160, 160), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    try:
        d.text((8, 8), ch, font=_font_emoji, embedded_color=True)
    except Exception:
        return None
    box = img.getbbox()
    if not box:
        return None
    img = img.crop(box)
    w = max(1, round(img.width * height / img.height))
    tile = img.resize((w, height), Image.LANCZOS)
    _emoji_cache[key] = tile
    return tile


def color_of(name, default):
    if name == "default":
        return default
    if name in PALETTE:
        return PALETTE[name]
    if len(name) == 6:                   # pyte gives 256-color values as hex
        return "#" + name
    return default


def render(snap, out_path):
    width = PAD * 2 + int(round(COLS * _CW))
    height = PAD * 2 + ROWS * LINE_H
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)
    emoji_h = LINE_H - 4

    for y, row in enumerate(snap):
        ty = PAD + y * LINE_H + 2
        # group cells into same-style runs of text
        x = 0
        while x < COLS:
            ch, fg, bg, bold, rev = row[x]
            if ch == "":                 # wide-char continuation cell
                x += 1
                continue
            base = ch[0] if ch else " "
            cls = glyph_class(base) if base != " " else "text"
            if cls == "blank":           # unrenderable glyph -> space
                base, cls = " ", "text"
            fg_hex = color_of(fg, FG_DEFAULT)
            bg_hex = color_of(bg, BG)
            if rev:
                fg_hex, bg_hex = bg_hex, fg_hex
            px = PAD + x * _CW
            if cls == "emoji":
                if bg_hex != BG:
                    draw.rectangle([px, ty - 2, px + 2 * _CW, ty - 2 + LINE_H], fill=bg_hex)
                tile = _emoji_tile(base, emoji_h)
                if tile is not None:
                    img.paste(tile, (int(round(px)), ty), tile)
                x += 1
                continue
            # text run: extend while same style and same glyph class
            run = []
            x0 = x
            while x < COLS:
                ch2, fg2, bg2, bold2, rev2 = row[x]
                if ch2 == "":
                    break
                b2 = ch2[0] if ch2 else " "
                c2 = glyph_class(b2) if b2 != " " else "text"
                if c2 == "blank":
                    b2, c2 = " ", "text"
                if c2 != "text" or (fg2, bg2, bold2, rev2) != (fg, bg, bold, rev):
                    break
                run.append(b2)
                x += 1
            text = "".join(run)
            if bg_hex != BG:
                draw.rectangle(
                    [px, ty - 2, PAD + x * _CW, ty - 2 + LINE_H], fill=bg_hex)
            if text.strip():
                draw.text((px, ty), text,
                          font=_font_bold if bold else _font_reg, fill=fg_hex)
    img.save(out_path, optimize=True)
    return img.size


def save_snapshot(snap, name):
    os.makedirs(SNAP_DIR, exist_ok=True)
    with open(os.path.join(SNAP_DIR, name + ".json"), "w") as f:
        json.dump(snap, f)
    with open(os.path.join(SNAP_DIR, name + ".txt"), "w") as f:
        for row in snap:
            f.write("".join((c[0] or " ") for c in row).rstrip() + "\n")


def capture(term, name):
    term.wait_stable()
    snap = term.snapshot()
    save_snapshot(snap, name)
    size = render(snap, os.path.join(OUT_DIR, name + ".png"))
    print(f"  [captured] {name}.png {size}")
    return snap


# ----------------------------------------------------------------------------
# Shoot environment helpers
# ----------------------------------------------------------------------------
PYPERCLIP_STUB = '''"""Headless stub of pyperclip for screenshot capture (no X11 clipboard)."""
class PyperclipException(RuntimeError):
    pass
_clip = ""
def copy(text):
    global _clip
    _clip = str(text)
def paste():
    return _clip
def determine_clipboard():
    return copy, paste
def set_clipboard(name):
    pass
'''

VAULT_FILES = ["Bunker.mmf", "bunker.cfg", "bunker.salt", "config.cfg",
               "bunker.devkey", "Bunker.mmf.bak", "bunker.cfg.bak",
               "bunker.salt.bak", "config.cfg.bak"]


def make_shoot_copy(dest, repo="/home/user/BUNKER2.0"):
    assert dest.startswith("/tmp/"), "shoot copies must live in /tmp"
    if os.path.exists(dest):
        shutil.rmtree(dest)
    shutil.copytree(repo, dest,
                    ignore=shutil.ignore_patterns(".git", "__pycache__",
                                                  ".pytest_cache", ".ruff_cache"))
    for f in VAULT_FILES:                # force a FRESH demo vault
        p = os.path.join(dest, f)
        if os.path.exists(p):
            os.remove(p)
    with open(os.path.join(dest, "pyperclip.py"), "w") as f:
        f.write(PYPERCLIP_STUB)          # shadows real pyperclip (headless)


def run_vault_setup(term):
    """Drive vaultSetup() until the login screen (password `rootroot`)."""
    term.wait_for("ready to setup bunker password")
    term.sendline("y")
    term.wait_for("Do you want to show your password?")
    term.sendline("y")
    term.wait_for("Enter Password:")
    term.sendline(DEMO_PASSWORD)
    term.wait_for("Confirm password:")
    term.sendline(DEMO_PASSWORD)
    term.wait_for("timeout value in seconds", timeout=180)   # KDF runs before this
    term.sendline("")                                        # default 60s
    term.wait_for("SUCCESS: Vault setup complete")
    term.wait_for("Press ENTER to continue")
    term.sendline("")


def add_profile(term, domain, email, user, password, favorite):
    term.wait_for("Website domain name")
    term.sendline(domain)
    term.wait_for("Email address")
    term.sendline(email)
    term.wait_for("Username (")
    term.sendline(user)
    term.wait_for("show your password while typing")
    term.sendline("y")
    term.wait_for("Enter the password")
    term.sendline(password)
    term.wait_for("Mark this profile as a favorite?")
    term.sendline("y" if favorite else "n")
    term.wait_for("SUCCESS: Profile successfully created")
    term.wait_for("add another profile")


def add_note(term, title, content, tags, favorite):
    term.wait_for("Enter a title for the note")
    term.sendline(title)
    term.wait_for("Enter the content of the note")
    term.sendline(content)
    term.wait_for("Enter tags for the note")
    term.sendline(tags)
    term.wait_for("Mark this note as a favorite?")
    term.sendline("y" if favorite else "n")
    term.wait_for("Mark this note as private?")
    term.sendline("n")
    term.wait_for("SUCCESS: Note successfully created")
    term.wait_for("add another note")


# ----------------------------------------------------------------------------
# Main shoots
# ----------------------------------------------------------------------------
def shoot_main():
    print("== shoot 1: main app tour (fresh demo vault) ==")
    make_shoot_copy(SHOOT_DIR)
    term = Term(SHOOT_DIR)
    try:
        run_vault_setup(term)

        # --- 01: BUNKER ACCESS page at the password prompt --------------------
        term.wait_for("BUNKER ACCESS")
        term.wait_for("Do you want to show your password? (y/n) or exit(e):")
        access_snap = capture(term, "01-access")

        # --- login ------------------------------------------------------------
        term.sendline("y")
        term.wait_for("bunker access code")
        term.sendline(DEMO_PASSWORD)

        # --- 02: MAIN MENU ------------------------------------------------------
        term.wait_for("MAIN MENU", timeout=180)
        term.wait_for("Enter your choice?")
        capture(term, "02-main-menu")

        # --- 03: ACCOUNT MANAGER ------------------------------------------------
        term.sendline("a")
        term.wait_for("ACCOUNT MANAGER")
        term.wait_for("What would you like to do?")
        capture(term, "03-account-manager")

        # --- seed fake profiles ---------------------------------------------------
        term.sendline("a")
        add_profile(term, "example.com", "demo@bunker.local", "demo",
                    "Xx9!demoPass##22", favorite=True)
        term.sendline("r")
        add_profile(term, "mail.example.org", "operator.b022@bunker.local",
                    "operator.b022", "Qm4#demoMail!!71", favorite=True)
        term.sendline("r")
        add_profile(term, "vault.example.net", "", "demo-ops",
                    "Tr8$demoVault&&05", favorite=False)
        term.sendline("")                # back to account manager

        # --- 04: viewing profiles (favorites list, passwords masked) -----------
        term.wait_for("What would you like to do?")
        term.sendline("s")
        term.wait_for("Select the profile to view its password")
        capture(term, "04-view-profile")
        term.sendline(".c")

        # back to main menu
        term.wait_for("What would you like to do?")
        term.sendline("x")
        term.wait_for("Enter your choice?")

        # --- notes ----------------------------------------------------------------
        term.sendline("s")
        term.wait_for("NOTES MANAGER")
        term.wait_for("What would you like to do?")
        term.sendline("a")
        add_note(term, "Cabin WiFi — Router Setup",
                 "Router admin 192.0.2.1 — login admin / FAKE-demo-0000. "
                 "SSID: BUNKER-CABIN (demo data only)",
                 "wifi, demo", favorite=True)
        term.sendline("r")
        add_note(term, "Demo Backup Codes (FAKE)",
                 "Recovery codes: XXXX-0000-DEMO, YYYY-1111-DEMO, ZZZZ-2222-DEMO "
                 "— placeholders for README screenshots",
                 "backup, demo", favorite=False)
        term.sendline("")                # back to notes manager

        # --- 05: notes list ---------------------------------------------------------
        term.wait_for("What would you like to do?")
        term.sendline("r")
        term.wait_for("Select the note to view its full content")
        capture(term, "05-notes")
        term.sendline(".c")
        term.wait_for("What would you like to do?")
        term.sendline("x")
        term.wait_for("Enter your choice?")

        # --- 06: password generator -----------------------------------------------
        term.sendline("f")
        term.wait_for("GENERATE RANDOM PASSWORD")
        term.wait_for("Password length")
        term.sendline("20")
        term.wait_for("Generated Password:")
        term.wait_for("return to menu")
        capture(term, "06-generator")
        term.sendline("")

        # --- 08: hero (re-render of the access page) --------------------------------
        size = render(access_snap, os.path.join(OUT_DIR, "08-hero.png"))
        print(f"  [captured] 08-hero.png {size} (re-render of 01-access)")

        # clean logout
        term.wait_for("Enter your choice?")
        term.sendline("x")
        term.drain_to_eof(timeout=30)
    finally:
        term.close()


def shoot_self_destruct():
    print("== shoot 2: self-destruct (disposable vault in /tmp/shoot2) ==")
    make_shoot_copy(SHOOT2_DIR)
    term = Term(SHOOT2_DIR)
    try:
        run_vault_setup(term)
        term.wait_for("Do you want to show your password? (y/n) or exit(e):")
        for n, bogus in enumerate(["wrong-pass-1", "wrong-pass-2", "wrong-pass-3"], 1):
            term.sendline("y")
            term.wait_for("bunker access code")
            term.sendline(bogus)
            if n < 3:
                term.wait_for(f"Attempt {n} of 3", timeout=300)
        # third failure triggers the wipe + nuke art, then the process exits
        term.wait_for("SELF DESTRUCT INITIATED", timeout=300)
        term.drain_to_eof(timeout=60)
        term.wait_stable()
        snap = term.snapshot()
        save_snapshot(snap, "07-self-destruct")
        size = render(snap, os.path.join(OUT_DIR, "07-self-destruct.png"))
        print(f"  [captured] 07-self-destruct.png {size}")
    finally:
        term.close()


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    shoot_main()
    shoot_self_destruct()
    print("done.")
