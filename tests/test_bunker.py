"""Unit tests for BUNKER 2.0 core logic (ported from the yma5h3 council branch).

Run from the repository root with:  python3 -m pytest tests/ -v

These cover the pure/crypto pieces the code-review council identified: key
derivation, vault encrypt/decrypt, database save/load round-trip and
atomicity, export passphrase verification, password strength scoring, and
password generation.

Fixtures are function-scoped so the suite-wide autouse `fast_kdf` fixture in
conftest.py (cheap Argon2id/PBKDF2 parameters) is in effect when keys are
derived — a session-scoped key would be built before fast_kdf patched the KDF
and would not match keys re-derived inside the tests.
"""
import os

import pytest

from main.INITIALIZE import (
    SecureVaultEnhanced,
    _atomic_write,
    generate_export_encryption,
    verify_export_encryption,
    saveDatabase,
    loadDatabase,
)
from main.SHARED_RESOURCES import check_password_strength, generate_password


@pytest.fixture
def vault():
    return SecureVaultEnhanced()


@pytest.fixture
def derived_key(vault):
    return vault.derive_key_hybrid("correct horse battery staple", b"\x01" * 32)


class TestKeyDerivation:
    def test_deterministic(self, vault, derived_key):
        again = vault.derive_key_hybrid("correct horse battery staple", b"\x01" * 32)
        assert again == derived_key

    def test_password_changes_key(self, vault, derived_key):
        other = vault.derive_key_hybrid("correct horse battery stapl3", b"\x01" * 32)
        assert other != derived_key

    def test_salt_changes_key(self, vault, derived_key):
        other = vault.derive_key_hybrid("correct horse battery staple", b"\x02" * 32)
        assert other != derived_key


class TestVaultEncryption:
    def test_round_trip(self, vault, derived_key):
        plaintext = b'{"notes": {"1": {"title": "hello"}}}'
        encrypted = vault.encrypt_data(plaintext, derived_key)
        assert encrypted != plaintext
        assert vault.decrypt_data(encrypted, derived_key) == plaintext

    def test_wrong_key_fails(self, vault, derived_key):
        encrypted = vault.encrypt_data(b"secret", derived_key)
        wrong = vault.derive_key_hybrid("not the password", b"\x01" * 32)
        with pytest.raises(Exception):
            vault.decrypt_data(encrypted, wrong)

    def test_ciphertext_randomized(self, vault, derived_key):
        # AES-GCM uses a fresh nonce per encryption
        a = vault.encrypt_data(b"same plaintext", derived_key)
        b = vault.encrypt_data(b"same plaintext", derived_key)
        assert a != b


class TestDatabaseSaveLoad:
    def test_round_trip(self, vault_dir, derived_key):
        db = {"profiles": {"1": {"domain": "ZW5jcnlwdGVk"}}, "notes": {}}
        assert saveDatabase(db, derived_key) is True
        assert os.path.exists("Bunker.mmf")
        assert loadDatabase(derived_key) == db

    def test_no_temp_file_left_behind(self, vault_dir, derived_key):
        saveDatabase({"profiles": {}}, derived_key)
        leftovers = [f for f in os.listdir(".") if f.endswith(".tmp")]
        assert leftovers == []

    def test_failed_save_preserves_original(self, vault_dir, derived_key):
        saveDatabase({"profiles": {"1": {}}}, derived_key)
        original = open("Bunker.mmf", "rb").read()
        # A key encrypt_data cannot use must fail before the vault is replaced
        result = saveDatabase({"profiles": {}}, object())
        assert result is False
        assert open("Bunker.mmf", "rb").read() == original


class TestAtomicWrite:
    def test_writes_content(self, tmp_path):
        target = str(tmp_path / "out.bin")
        _atomic_write(target, b"abc123")
        assert open(target, "rb").read() == b"abc123"
        assert not os.path.exists(target + ".tmp")

    def test_overwrites_existing(self, tmp_path):
        target = str(tmp_path / "out.bin")
        _atomic_write(target, b"old")
        _atomic_write(target, b"new")
        assert open(target, "rb").read() == b"new"

    def test_save_completes_when_backup_step_fails(self, tmp_path, monkeypatch):
        # A3: the .bak copy is best-effort. If it raises, the primary atomic
        # replace must still happen (the vault is updated) and no .tmp is left.
        import main.INITIALIZE as INIT

        target = str(tmp_path / "out.bin")
        _atomic_write(target, b"old")  # create an existing file so .bak runs

        real_mkstemp = INIT.tempfile.mkstemp

        def flaky_mkstemp(*args, **kwargs):
            # Force only the rolling-backup temp to fail; the primary .tmp ok.
            if str(kwargs.get("prefix", "")).find(".bak.") != -1:
                raise OSError("simulated backup failure")
            return real_mkstemp(*args, **kwargs)

        monkeypatch.setattr(INIT.tempfile, "mkstemp", flaky_mkstemp)

        _atomic_write(target, b"new")

        assert open(target, "rb").read() == b"new"  # primary file updated
        leftovers = [f for f in os.listdir(str(tmp_path)) if f.endswith(".tmp")]
        assert leftovers == []


class TestExportEncryption:
    def test_correct_passphrase_verifies(self):
        fernet_key, salt, verifier = generate_export_encryption("hunter2hunter2")
        assert fernet_key is not None
        assert len(salt) == 16
        result = verify_export_encryption("hunter2hunter2", salt, verifier)
        assert result is not None

    def test_wrong_passphrase_rejected(self):
        _, salt, verifier = generate_export_encryption("hunter2hunter2")
        assert verify_export_encryption("wrong passphrase", salt, verifier) is None


class TestPasswordStrength:
    def test_returns_score_and_feedback(self):
        strength, feedback = check_password_strength("x")
        assert 0 <= strength <= 5
        assert isinstance(feedback, list)

    def test_strong_beats_weak(self):
        weak, _ = check_password_strength("abc")
        strong, _ = check_password_strength("K9#mQ!x7Zw@4Lp$v")
        assert strong > weak

    def test_common_password_scores_low(self):
        score, _ = check_password_strength("password123")
        assert score <= 2


class TestGeneratePassword:
    def test_length(self):
        for n in (12, 16, 32):
            assert len(generate_password(n)) == n

    def test_unique_each_call(self):
        assert generate_password(16) != generate_password(16)

    def test_contains_each_class(self):
        pwd = generate_password(16)
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(not c.isalnum() for c in pwd)
