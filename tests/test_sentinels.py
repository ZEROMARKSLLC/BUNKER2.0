"""Tripwires pinned to the council's worst bugs. Each test is one invariant;
if any of these ever fails, a previously-shipped vault-eating bug is back."""
import os
import re

import pytest

from conftest import REPO
import main.INITIALIZE as INIT
import main.SHARED_RESOURCES as SR


def _src(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as f:
        return f.read()


BUNKER_SRC = _src("BUNKER.py")
INIT_SRC = _src(os.path.join("main", "INITIALIZE.py"))


def test_self_destruct_without_force_deletes_nothing(vault_dir):
    (vault_dir / "Bunker.mmf").write_bytes(b"vault")
    (vault_dir / "bunker.salt").write_bytes(b"salt")
    with pytest.raises(SystemExit):
        SR.self_destruct(reason="sentinel")
    assert (vault_dir / "Bunker.mmf").read_bytes() == b"vault"
    assert (vault_dir / "bunker.salt").read_bytes() == b"salt"


def test_secure_delete_on_failure_without_force_is_noop(vault_dir):
    (vault_dir / "Bunker.mmf").write_bytes(b"vault")
    INIT.vault.secure_delete_on_failure()
    assert (vault_dir / "Bunker.mmf").read_bytes() == b"vault"


def _live_lines(src):
    return [l for l in src.splitlines() if not l.lstrip().startswith("#")]


def test_exactly_one_forced_self_destruct_call_site():
    # Only the max-failed-logins lockout path may pass force=True.
    # DOTALL + comment-stripped whole-source scan so multi-line calls
    # cannot slip past a per-line check.
    call = re.compile(
        r"(self_destruct|secure_delete_on_failure)\([^)]*force\s*=\s*True",
        re.DOTALL)
    assert len(call.findall("\n".join(_live_lines(BUNKER_SRC)))) == 1
    assert len(call.findall("\n".join(_live_lines(INIT_SRC)))) == 0


def test_save_failure_leaves_vault_bytes_identical(vault_dir, key, populated_vault):
    before = (vault_dir / "Bunker.mmf").read_bytes()
    assert INIT.saveDatabase({"x": 1}, "garbage-key") is False
    assert (vault_dir / "Bunker.mmf").read_bytes() == before


def test_no_truncate_writes_of_the_vault():
    # Every write of any vault file must route through _atomic_write.
    pat = re.compile(
        r'open\(\s*"(Bunker\.mmf|bunker\.cfg|bunker\.salt|config\.cfg|bunker\.devkey)"\s*,\s*"wb"')
    live_init = [l for l in _live_lines(INIT_SRC) if pat.search(l)]
    live_bunker = [l for l in _live_lines(BUNKER_SRC) if pat.search(l)]
    assert live_init == [] and live_bunker == []


def test_fresh_vault_addprofile_reads_current_timeout():
    # The KeyError pattern that broke add/edit on every fresh vault:
    assert not any('manage_config(hashed_pass)["timeout_value"]' in l
                   for l in _live_lines(BUNKER_SRC))
    # and the fixed read is actually present:
    assert 'load_ui_config().get("current_timeout"' in BUNKER_SRC


def test_no_keyboard_import():
    assert not re.search(r"^\s*import keyboard", BUNKER_SRC, re.MULTILINE)


def test_corrupt_config_locks_but_preserves_vault_and_salt(vault_dir, key, populated_vault):
    (vault_dir / "config.cfg").write_bytes(os.urandom(64))
    with pytest.raises(SystemExit) as exc:
        INIT.load_ui_config()
    assert exc.value.code == 1
    assert (vault_dir / "Bunker.mmf").exists()
    assert (vault_dir / "bunker.salt").exists()


def test_rotation_reencrypts_db_before_publishing_salt():
    # Source-order tripwire: the moment someone "tidies" changeMasterPassword
    # back to salt-first, this fails before any vault does.
    assert INIT_SRC.index("saveDatabase(db, new_derived_key)") \
        < INIT_SRC.index("save_salt(new_salt)")


def test_pepper_scheme_is_first_candidate():
    salt = os.urandom(32)
    cands = list(INIT.derive_candidate_keys("pw123456", salt))
    assert cands[0] == INIT.vault.derive_key_hybrid("pw123456", salt, INIT.PEPPER)


def test_stored_password_copies_have_autoclear():
    # Every clipboard write of a secret must go through to_clipboard (30s clear);
    # bare pyperclip.copy is allowed only for clearing ("").
    bare = re.findall(r"pyperclip\.copy\(([^)]*)\)", BUNKER_SRC)
    assert all(arg.strip() in ('""', "''") for arg in bare), bare


def test_timeout_zero_means_disabled(vault_dir, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a, **k: "answer")
    assert INIT.timeoutInput("? ", timeout=0) == "answer"


def test_empty_pepper_candidates_are_deduplicated(monkeypatch):
    # (a) With PEPPER == "" the candidates are exactly current + legacy:
    # the empty-pepper candidate must NOT be derived/yielded a second time
    # (the current scheme already uses an empty pepper). conftest's fast_kdf
    # already pins PEPPER == "", but be explicit so intent is local.
    monkeypatch.setattr(INIT, "PEPPER", "")
    pw, salt = "pw123456", os.urandom(32)
    cands = list(INIT.derive_candidate_keys(pw, salt))
    current = INIT.vault.derive_key_hybrid(pw, salt, "")
    legacy = INIT.vault.derive_key_hybrid(pw, salt, pw)
    assert cands == [current, legacy]
    # (b) A vault key made with an empty pepper is among the candidates.
    assert current in cands
    # (c) De-dup holds: no duplicate keys are ever yielded.
    assert len(cands) == len(set(cands))


def test_empty_pepper_candidate_present_when_custom_pepper_set(monkeypatch):
    # With a custom pepper, the empty-pepper key (for a vault created with NO
    # pepper) is offered as an additional, de-duplicated candidate.
    monkeypatch.setattr(INIT, "PEPPER", "s3cret-pepper")
    pw, salt = "pw123456", os.urandom(32)
    cands = list(INIT.derive_candidate_keys(pw, salt))
    current = INIT.vault.derive_key_hybrid(pw, salt, "s3cret-pepper")
    empty = INIT.vault.derive_key_hybrid(pw, salt, "")
    legacy = INIT.vault.derive_key_hybrid(pw, salt, pw)
    assert cands == [current, empty, legacy]
    assert len(cands) == len(set(cands))


def test_autoclear_does_not_wipe_user_clipboard(monkeypatch):
    # ISSUE 3: if the user copies something else after BUNKER copied a secret,
    # the auto-clear must NOT wipe it. Drive clear_clipboard directly with an
    # in-memory fake clipboard rather than sleeping out the 30s timer.
    fake = {"value": ""}
    monkeypatch.setattr(SR.pyperclip, "copy", lambda v: fake.__setitem__("value", v))
    monkeypatch.setattr(SR.pyperclip, "paste", lambda: fake["value"])
    # Stop the real timer from firing; we invoke clear ourselves.
    monkeypatch.setattr(SR.threading, "Timer",
                        lambda *a, **k: type("T", (), {"daemon": False,
                                                       "start": lambda self: None,
                                                       "cancel": lambda self: None})())
    SR.to_clipboard("SECRET-X")
    assert fake["value"] == "SECRET-X"
    token = SR._clip_token
    # Something else writes the clipboard.
    fake["value"] = "USER-COPIED-Y"
    # The pending clear fires now — it must leave Y untouched.
    SR.clear_clipboard(token)
    assert fake["value"] == "USER-COPIED-Y"


def test_autoclear_wipes_our_own_value(monkeypatch):
    # The compare-before-clear must still clear when the clipboard STILL holds
    # exactly what BUNKER wrote (no superseding copy).
    fake = {"value": ""}
    monkeypatch.setattr(SR.pyperclip, "copy", lambda v: fake.__setitem__("value", v))
    monkeypatch.setattr(SR.pyperclip, "paste", lambda: fake["value"])
    monkeypatch.setattr(SR.threading, "Timer",
                        lambda *a, **k: type("T", (), {"daemon": False,
                                                       "start": lambda self: None,
                                                       "cancel": lambda self: None})())
    SR.to_clipboard("SECRET-Z")
    SR.clear_clipboard(SR._clip_token)
    assert fake["value"] == ""
