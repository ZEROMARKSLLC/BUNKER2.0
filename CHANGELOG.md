# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic-ish versioning.

## [2.0.0] - 2026-06-15

### Changed

- **IRREVERSIBLE config migration.** On first run against an existing
  directory, `config.cfg` is re-encrypted from the old static key to a
  per-machine device key (`bunker.devkey`). This migration is one-way and
  cannot be undone. A one-time on-screen notice is shown when it happens.

### Security

- Login/unlock prompts now honor the auto-logout timeout (the unlock screen
  itself can time out and securely exit).
- Clipboard auto-clear now compares the clipboard against the value BUNKER
  wrote before clearing, so it no longer wipes something you copied later.
- Key-derivation now tries an additional empty-pepper candidate (de-duplicated)
  so a vault created with no `BUNKER_PEPPER` still opens if one is later set.
  Loud warnings are shown at vault creation and at startup when a custom
  `BUNKER_PEPPER` is active, because losing or changing it makes the vault
  permanently unopenable.
- Self-destruct / secure-delete overwrite is documented as **best-effort
  only** — ineffective on copy-on-write (btrfs/ZFS/APFS), SSD/flash
  (wear-leveling), and journaled filesystems.

### ⚠️ Unsafe downgrade

- **Do NOT run an older BUNKER release against a directory this version has
  touched.** Because `config.cfg` has been migrated to the device-key scheme,
  an older release may fail to read it and trigger the old **unconditional
  self-destruct**, **permanently wiping the vault**. Back up `Bunker.mmf`,
  `bunker.salt`, `config.cfg`, and `bunker.devkey` before any version change.
