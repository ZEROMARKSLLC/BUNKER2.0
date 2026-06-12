"""Council round-2 regression tests: interrupted password-rotation recovery,
the forced-wipe/.bak interaction, and a real-KDF smoke test that the shipped
demo vault still opens.

These pin the two blocker fixes from CODE_REVIEW_COUNCIL_ROUND2.md:
- the max-attempts wipe must never destroy the .bak recovery files, and
- a crash mid-rotation must leave a state the OLD password can recover,
  detectable via the bunker.salt.bak mismatch (which the login loop uses to
  avoid burning lockout attempts on the user's new password).
"""
import base64
import json
import os
import shutil

import pytest

from tests.conftest import REPO
import main.INITIALIZE as INIT
import main.SHARED_RESOURCES as SR


def _make_vault(password, salt):
    """Create bunker.salt + bunker.cfg the way vaultSetup does."""
    key = INIT.vault.derive_key_hybrid(password, salt, INIT.PEPPER)
    config = {
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(
            INIT.vault.encrypt_data(b"BUNKER_VERIFIED", key)).decode(),
    }
    INIT._atomic_write(
        "bunker.cfg", INIT.vault.encrypt_data(json.dumps(config).encode(), key))
    INIT.save_salt(salt)
    return key


def _open_config(password, salt, encrypted_config):
    """Replicate the login loop's candidate-key search; (config, key) or (None, None)."""
    for key in INIT.derive_candidate_keys(password, salt):
        try:
            config = json.loads(INIT.vault.decrypt_data(encrypted_config, key).decode())
            return config, key
        except Exception:
            continue
    return None, None


def test_interrupted_rotation_old_password_recovers(vault_dir):
    old_salt = os.urandom(32)
    old_key = _make_vault("old password", old_salt)
    db = {"p1": {"domain": "example.com"}}
    assert INIT.saveDatabase(db, old_key) is True

    # Simulate a crash mid-rotation: DB and salt are published under the new
    # password, bunker.cfg is not (rotation order: DB -> salt -> config).
    new_salt = os.urandom(32)
    new_key = INIT.vault.derive_key_hybrid("new password", new_salt, INIT.PEPPER)
    assert INIT.saveDatabase(db, new_key) is True
    INIT.save_salt(new_salt)  # rolls the old salt into bunker.salt.bak
    # -- crash: bunker.cfg never rewritten --

    with open("bunker.cfg", "rb") as f:
        encrypted_config = f.read()
    on_disk_salt = INIT.load_salt()

    # Neither password opens the config under the on-disk (new) salt...
    assert _open_config("old password", on_disk_salt, encrypted_config) == (None, None)
    assert _open_config("new password", on_disk_salt, encrypted_config) == (None, None)

    # ...and the state is detectable exactly the way BUNKER.py's login loop
    # checks it before deciding NOT to count a failure toward the lockout.
    assert os.path.exists("bunker.salt.bak")
    assert INIT.load_salt("bunker.salt.bak") != on_disk_salt

    # The login fallback: OLD password + backup salt opens the config.
    bak_salt = INIT.load_salt("bunker.salt.bak")
    assert bak_salt == old_salt
    config, recovered_key = _open_config("old password", bak_salt, encrypted_config)
    assert config is not None
    assert INIT.vault.decrypt_data(
        base64.b64decode(config["verifier"]), recovered_key) == b"BUNKER_VERIFIED"

    # And the database backup from before the rotation decrypts under it.
    with open("Bunker.mmf.bak", "rb") as f:
        backup_db = f.read()
    assert json.loads(INIT.vault.decrypt_data(backup_db, recovered_key)) == db


def test_forced_wipe_preserves_bak_recovery_files(vault_dir):
    for name in ("Bunker.mmf", "bunker.cfg", "bunker.salt", "config.cfg",
                 "bunker.devkey"):
        with open(name, "wb") as f:
            f.write(b"x" * 64)
    for name in ("Bunker.mmf.bak", "bunker.cfg.bak", "bunker.salt.bak"):
        with open(name, "wb") as f:
            f.write(b"recovery")

    with pytest.raises(SystemExit):
        SR.self_destruct(reason="test lockout", force=True)

    for name in ("Bunker.mmf", "bunker.cfg", "bunker.salt", "config.cfg",
                 "bunker.devkey"):
        assert not os.path.exists(name), f"{name} should be wiped"
    for name in ("Bunker.mmf.bak", "bunker.cfg.bak", "bunker.salt.bak"):
        assert os.path.exists(name), f"{name} must survive the lockout wipe"
        with open(name, "rb") as f:
            assert f.read() == b"recovery"


@pytest.mark.slow
def test_demo_vault_opens_with_rootroot(vault_dir, monkeypatch):
    """The committed demo vault must keep opening with the published password.

    Uses the REAL KDF (overriding the suite-wide cheap parameters) because the
    demo vault's keys were derived with production parameters; this is the one
    test that would catch a key-derivation regression breaking shipped vaults.
    """
    from argon2.low_level import hash_secret_raw as real_argon2
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as real_pbkdf2
    monkeypatch.setattr(INIT, "hash_secret_raw", real_argon2)
    monkeypatch.setattr(INIT, "PBKDF2HMAC", real_pbkdf2)

    for name in ("Bunker.mmf", "bunker.cfg", "bunker.salt"):
        shutil.copy(os.path.join(REPO, name), name)

    salt = INIT.load_salt()
    with open("bunker.cfg", "rb") as f:
        encrypted_config = f.read()

    config, key = _open_config("rootroot", salt, encrypted_config)
    assert config is not None, "demo vault no longer opens with 'rootroot'"
    assert INIT.vault.decrypt_data(
        base64.b64decode(config["verifier"]), key) == b"BUNKER_VERIFIED"

    db = INIT.loadDatabase(key)
    assert isinstance(db, dict) and len(db) > 0
