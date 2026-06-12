"""Headless verification of the P0 reliability fixes.

Runs in an isolated temp directory — never touches the real repo files.
Exercises: atomic saveDatabase round-trip + .bak, load_ui_config recovery
paths, self_destruct gating, and crash-mid-save survival.
"""
import json, os, shutil, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.abspath(__file__))

work = tempfile.mkdtemp(prefix="bunker-test-")
os.makedirs(os.path.join(work, "main"), exist_ok=True)
for f in ("INITIALIZE.py", "SHARED_RESOURCES.py"):
    shutil.copy(os.path.join(REPO, "main", f), os.path.join(work, "main", f))
open(os.path.join(work, "main", "__init__.py"), "a").close()
os.chdir(work)
sys.path.insert(0, work)

import main.INITIALIZE as INIT

passed, failed = [], []
def check(name, cond):
    (passed if cond else failed).append(name)
    print(("PASS  " if cond else "FAIL  ") + name)

key = INIT.vault.derive_key_hybrid("testpass123", os.urandom(32), "testpass123")

# 1. saveDatabase round-trip via atomic writer
db = {"profile1": {"domain": "example.com"}}
check("saveDatabase returns True", INIT.saveDatabase(db, key) is True)
check("loadDatabase round-trips", INIT.loadDatabase(key) == db)

# 2. Second save creates a rolling .bak holding the previous version
db2 = dict(db, profile2={"domain": "example.org"})
INIT.saveDatabase(db2, key)
check("rolling .bak exists", os.path.exists("Bunker.mmf.bak"))
with open("Bunker.mmf.bak", "rb") as f:
    old = INIT.vault.decrypt_data(f.read(), key)
check(".bak holds previous good version", json.loads(old) == db)

# 3. saveDatabase failure (bad key type) leaves the vault intact and returns False
before = open("Bunker.mmf", "rb").read()
ok = INIT.saveDatabase(db2, "not-a-valid-key-object")
check("bad-key save returns False", ok is False)
check("vault untouched after failed save", open("Bunker.mmf", "rb").read() == before)

# 4. load_ui_config: missing file -> defaults regenerated, vault untouched
check("no config.cfg yet", not os.path.exists("config.cfg"))
cfg = INIT.load_ui_config()
check("missing config.cfg -> defaults", cfg["max_attempts"] == 3 and cfg["attempts"] == 0)
check("defaults persisted", os.path.exists("config.cfg"))
check("vault survived config regen", os.path.exists("Bunker.mmf"))

# 5. load_ui_config: corrupt file -> sys.exit(1), vault and salt PRESERVED
with open("config.cfg", "wb") as f:
    f.write(os.urandom(64))
INIT.save_salt(os.urandom(32))
try:
    INIT.load_ui_config()
    check("corrupt config exits", False)
except SystemExit as e:
    check("corrupt config exits with code 1", e.code == 1)
check("vault survived corrupt config", os.path.exists("Bunker.mmf"))
check("salt survived corrupt config", os.path.exists("bunker.salt"))

# 6. self_destruct without force=True must NOT delete anything (exits instead)
import main.SHARED_RESOURCES as SR
files_before = sorted(os.listdir("."))
try:
    SR.self_destruct(reason="unit test - ungated call")
    check("ungated self_destruct exits", False)
except SystemExit as e:
    check("ungated self_destruct exits without wiping", e.code == 1)
check("all files survived ungated self_destruct", sorted(os.listdir(".")) == files_before)

# 7. Kill-mid-save: SIGKILL the process between fsync and replace; old vault must survive
snapshot = open("Bunker.mmf", "rb").read()
kill_script = r"""
import os, sys
sys.path.insert(0, os.getcwd())
import main.INITIALIZE as INIT
_real_replace = os.replace
def killing_replace(src, dst):
    if dst == "Bunker.mmf":
        os._exit(9)          # simulate power loss at the worst moment
    return _real_replace(src, dst)
os.replace = killing_replace
key = INIT.vault.derive_key_hybrid("testpass123", b"0"*32, "testpass123")
INIT.saveDatabase({"huge": "x" * 10000}, key)
"""
r = subprocess.run([sys.executable, "-c", kill_script], cwd=work, capture_output=True)
check("subprocess died mid-save (exit 9)", r.returncode == 9)
check("old vault intact after kill-mid-save", open("Bunker.mmf", "rb").read() == snapshot)
check("old vault still decrypts", INIT.loadDatabase(key) == db2)

print(f"\n{len(passed)} passed, {len(failed)} failed")
shutil.rmtree(work, ignore_errors=True)
sys.exit(1 if failed else 0)
