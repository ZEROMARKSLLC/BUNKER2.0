# BUNKER 2.0 — Release Engineering Plan

**The path:** ship `bunker-vault` on PyPI with a `bunker` console command
(`pipx install bunker-vault`) as primary; keep a CI-built source zip as the
GitHub-Release/Gumroad secondary; **skip single-file binaries entirely**.
One blocking prerequisite: the CWD problem (below). Versioning starts at
**2.1.0**.

## Packaging decisions (written down so they aren't relitigated)

| Channel | Verdict |
|---|---|
| **PyPI `bunker-vault` + pipx** | **Primary.** `pipx` sidesteps PEP 668 ("externally-managed-environment") pain. PyPI name `bunker` is squatted (dead 2019 package); `bunker-vault` is free. |
| CI-built source zip | Secondary — auditors, Gumroad buyers, `python3 BUNKER.py` users. Same artifact for GitHub Release and Gumroad = no drift. |
| zipapp / shiv `.pyz` | Rejected: still needs system Python, and cryptography/argon2-cffi compiled extensions force per-OS builds anyway. |
| PyInstaller / Nuitka binary | **Rejected:** cffi hidden-import quirks; an unsigned binary that enumerates processes, fetches your IP, and multi-pass-shreds files is *behaviorally a wiper* — guaranteed AV-heuristic flags; signing certs (Windows EV ~$200–500/yr, Apple $99/yr) cost more than PWYW earns; opaque binary undercuts the "audit every line" promise. |
| Termux | Served by the pip package: `pkg install python python-cryptography clang libffi termux-api` then `pip install bunker-vault`. Recommend `BUNKER_HOME=$HOME/.bunker`. |

License note: CPSL forbids redistribution — add an explicit grant line to
LICENSE.txt authorizing distribution via official package indexes by
ZeroMarks LLC (PyPI mirrors redistribute).

## The CWD problem (BLOCKS PyPI)

Vault files are opened by bare relative filename → they land wherever the
process launches from. Fine for `cd BUNKER2.0`; catastrophic for an
installed `bunker` command — and `self_destruct` shreds by relative path,
so a lockout in the wrong CWD wipes the wrong directory's copies.

~61 filename mentions funnel through ~8 chokepoints: `_atomic_write` and
its callers (`saveDatabase`, `save_ui_config`, `save_salt`, devkey mint,
setup writes, rotation), `loadDatabase`/`load_ui_config`/`load_salt` raw
reads, `SecureVaultEnhanced.__init__` filename attrs + wipe list, the
raw `open("Bunker.mmf")` stragglers in BUNKER.py (main/menu re-reads), and
`self_destruct`'s wipe list (which must drop its `main/`/`config/`
candidate scan entirely).

**The fix — `main/paths.py`:**

```python
"""Single source of truth for where BUNKER's data files live.
Resolution: $BUNKER_HOME > legacy CWD (if vault files present) >
platformdirs user_data_dir('bunker', 'ZeroMarks')."""
import os
import functools
from platformdirs import user_data_dir

_VAULT_MARKERS = ("Bunker.mmf", "bunker.salt", "bunker.cfg")

@functools.lru_cache(maxsize=1)
def data_dir() -> str:
    env = os.environ.get("BUNKER_HOME")
    if env:
        d = os.path.abspath(os.path.expanduser(env))
    elif any(os.path.exists(m) for m in _VAULT_MARKERS):
        d = os.getcwd()          # legacy layout keeps working in place
    else:
        d = user_data_dir("bunker", "ZeroMarks")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d

def data_path(filename: str) -> str:
    return os.path.join(data_dir(), filename)
```

Add `platformdirs>=4.0` to requirements. `lru_cache` pins the answer at
first touch so a mid-session CWD change can never redirect the
self-destruct. **No auto-migration** — print a one-time notice telling
legacy users where new installs store data and how to move (silently
relocating a burner vault with a persistent attempt counter is how you
generate "BUNKER deleted my passwords" reviews).

## Versioning

- Create `main/__init__.py` (needed anyway — the package has none):
  `__version__ = "2.1.0"`.
- Replace the three hardcoded `Version: BETA` strings (main menu, account
  manager, notes manager) with the constant.
- `pyproject.toml` reads it dynamically; tag format `vX.Y.Z`; CHANGELOG.md
  in keep-a-changelog format (2.1.0 entry = this branch's actual work: P0
  data-loss fixes, persistent counter + devkey, pepper, atomic saves,
  3.10 compat, CI/tests, screenshots, README).

## pyproject.toml (key decisions)

```toml
[project]
name = "bunker-vault"
dynamic = ["version"]
requires-python = ">=3.10"
license = "LicenseRef-CPSL-1.0"
license-files = ["LICENSE.txt"]
dependencies = [
  "cryptography>=42.0.0", "argon2-cffi>=23.1.0", "inputimeout>=1.0.4",
  "pyperclip>=1.8.2", "psutil>=5.9.0", "requests>=2.32.0",
  "platformdirs>=4.0",
]

[project.scripts]
bunker = "BUNKER:main"

[tool.setuptools]
py-modules = ["BUNKER"]
packages = ["main"]

[tool.setuptools.dynamic]
version = { attr = "main.__version__" }
```

**Layout flag:** installing a top-level package literally named `main` into
site-packages is a collision time bomb. Acceptable for 2.1.0; the 2.2.0
restructure is ~30 minutes: `main/` → `bunker_vault/`, `BUNKER.py` →
`bunker_vault/app.py`, root `BUNKER.py` becomes a 3-line shim so
`python3 BUNKER.py` keeps working for zip users.

## Release workflow (tag push → tests → build → draft release → PyPI)

On `v*.*.*` tag: test matrix (ubuntu/windows × 3.10/3.13: py_compile,
pytest, test_p0_fixes) → verify tag matches `main.__version__` → build
sdist/wheel + a **clean source zip** (BUNKER.py, main/, requirements.txt,
README, CHANGELOG, LICENSE, docs/img PNGs) with a guard step that FAILS the
build if any vault artifact (`Bunker.mmf*`, `bunker.salt*`, `bunker.cfg*`,
`config.cfg*`, `bunker.devkey*`, `*.bak`) leaks in → extract the version's
CHANGELOG section as release notes → **draft** GitHub Release (founder
eyeballs before publishing) → PyPI publish via OIDC trusted publishing
(no API token to leak).

**Demo vault decision: exclude all vault artifacts from release zips.**
First-run setup creates a vault in under a minute (the product's own
selling point). Update README/Gumroad from "Demo password: rootroot" to
"first launch creates your vault in 60 seconds."

## Gumroad deliverable

The zip buyers download IS the GitHub Release artifact (never hand-rolled):

```
bunker-X.Y.Z/
├── BUNKER.py            ├── requirements.txt
├── main/ (__init__, paths, INITIALIZE, SHARED_RESOURCES, LICENSE)
├── README.md  ├── CHANGELOG.md  ├── LICENSE.txt  └── docs/img/*.png
```

Excluded (CI-enforced): vault files, tests, .github/, gumroad.md,
COUNCIL_REVIEW.md, caches.

## Release-day checklist (~15 minutes)

1. Bump `__version__`; move `[Unreleased]` → dated CHANGELOG section;
   commit; CI green.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Review the draft GitHub Release; publish (triggers PyPI).
4. Download the zip from the release; upload to Gumroad; update the
   version line in the product description.
5. Smoke test as a stranger: clean venv, `pipx install bunker-vault`,
   create vault, add entry, relaunch, log in. Then announce with the
   changelog link.

## Action items

| Priority | Item |
|---|---|
| P0 (blocks PyPI) | `main/paths.py` + thread `data_path()` through the chokepoints (esp. `_atomic_write` callers and `self_destruct`) |
| P0 | `main/__init__.py` with `__version__`; replace the three `Version: BETA` strings |
| P1 | pyproject.toml, CHANGELOG.md, release workflow; PyPI trusted-publisher setup |
| P1 | Strip demo vault from artifacts; fix gumroad.md (still says "resets every session" and "open source" — both wrong) |
| P2 | 2.2.0 restructure (`main/` → `bunker_vault/` + root shim) |
| P2 | LICENSE index-distribution grant; Termux install snippet in README |
