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

# 8. Security round: device-bound UI-config key
import subprocess as sp
for f in ("config.cfg", "bunker.devkey"):
    if os.path.exists(f):
        os.remove(f)
# A pre-upgrade user: legacy static-key config exists BEFORE any devkey —
# the one-time migration must adopt it
legacy_cfg = INIT.vault.encrypt_data(json.dumps({"attempts": 0}).encode(), INIT.LEGACY_UI_KEY)
with open("config.cfg", "wb") as f:
    f.write(legacy_cfg)
migrated = INIT.load_ui_config()
check("legacy config migrates on first run", migrated == {"attempts": 0})
check("devkey created during migration", os.path.exists("bunker.devkey"))
with open("config.cfg", "rb") as f:
    on_disk = f.read()
devkey = INIT._ui_config_key()
check("migrated config now under device key",
      json.loads(INIT.vault.decrypt_data(on_disk, devkey)) == {"attempts": 0})
check("config readable under device key",
      INIT.load_ui_config() == {"attempts": 0})

# Once the devkey exists, a static-key FORGERY (attacker resetting the
# lockout counter from source knowledge) must be rejected, not migrated
forged = INIT.vault.encrypt_data(json.dumps({"attempts": 0, "max_attempts": 9999}).encode(),
                                 INIT.LEGACY_UI_KEY)
with open("config.cfg", "wb") as f:
    f.write(forged)
r = sp.run([sys.executable, "-c",
            "import sys, os; sys.path.insert(0, os.getcwd());"
            "import main.INITIALIZE as I; I.load_ui_config()"],
           cwd=work, capture_output=True)
check("static-key forgery rejected once devkey exists", r.returncode == 1)

# A config encrypted under a DIFFERENT machine's devkey is rejected too
other_key = INIT.base64.urlsafe_b64encode(os.urandom(32))
with open("config.cfg", "wb") as f:
    f.write(INIT.vault.encrypt_data(b'{"attempts": 99}', other_key))
r = sp.run([sys.executable, "-c",
            "import sys, os; sys.path.insert(0, os.getcwd());"
            "import main.INITIALIZE as I; I.load_ui_config()"],
           cwd=work, capture_output=True)
check("foreign-key config rejected (locked, not wiped)", r.returncode == 1)
check("vault survived foreign-key config", os.path.exists("Bunker.mmf"))
os.remove("config.cfg")

# 9. Security round: pepper fix with legacy fallback
salt = os.urandom(32)
new_key = INIT.vault.derive_key_hybrid("hunter2pass", salt, INIT.PEPPER)
legacy_key = INIT.vault.derive_key_hybrid("hunter2pass", salt, "hunter2pass")
check("new scheme differs from legacy", new_key != legacy_key)
cands = list(INIT.derive_candidate_keys("hunter2pass", salt))
check("candidates = [new, legacy]", cands == [new_key, legacy_key])

# verify_password_enhanced accepts BOTH a new-scheme and a legacy verifier
v_new = INIT.vault.encrypt_data(b"BUNKER_VERIFIED", new_key)
v_old = INIT.vault.encrypt_data(b"BUNKER_VERIFIED", legacy_key)
check("verifier (new scheme) -> new key",
      INIT.vault.verify_password_enhanced("hunter2pass", salt, v_new) == new_key)
check("verifier (legacy vault) -> legacy key",
      INIT.vault.verify_password_enhanced("hunter2pass", salt, v_old) == legacy_key)
check("wrong password rejected",
      INIT.vault.verify_password_enhanced("wrongpass99", salt, v_old) is False)

print(f"\n{len(passed)} passed, {len(failed)} failed")
shutil.rmtree(work, ignore_errors=True)
sys.exit(1 if failed else 0)
