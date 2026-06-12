"""Shared fixtures. Every test runs chdir'd into a throwaway tmp dir, so the
suite can NEVER touch real vault files, and with cheap KDF parameters so the
whole suite runs in seconds instead of minutes."""
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import main.INITIALIZE as INIT  # noqa: E402


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Same code path, same algorithms, minimal cost parameters.
    INITIALIZE imports hash_secret_raw and PBKDF2HMAC into its own namespace,
    so patching the module attributes is enough."""
    from argon2.low_level import hash_secret_raw as real_argon2

    def cheap_argon2(**kw):
        kw.update(time_cost=1, memory_cost=8, parallelism=1)
        return real_argon2(**kw)

    monkeypatch.setattr(INIT, "hash_secret_raw", cheap_argon2)

    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as RealPBKDF2

    def cheap_pbkdf2(*, algorithm, length, salt, iterations, backend=None):
        return RealPBKDF2(algorithm=algorithm, length=length, salt=salt,
                          iterations=1, backend=backend)

    monkeypatch.setattr(INIT, "PBKDF2HMAC", cheap_pbkdf2)
    # Pin the pepper so results don't depend on the developer's environment
    monkeypatch.setattr(INIT, "PEPPER", "")


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    """Isolated working directory — all of BUNKER's relative-path file I/O
    (Bunker.mmf, bunker.salt, bunker.cfg, config.cfg, bunker.devkey) lands here."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def salt():
    return os.urandom(32)


@pytest.fixture
def key(vault_dir, salt):
    """A current-scheme master key with the salt persisted, vault dir ready."""
    INIT.save_salt(salt)
    return INIT.vault.derive_key_hybrid("correct horse battery", salt, INIT.PEPPER)


@pytest.fixture
def populated_vault(vault_dir, key):
    db = {"p1": {"domain": "example.com"}}
    assert INIT.saveDatabase(db, key) is True
    return db
