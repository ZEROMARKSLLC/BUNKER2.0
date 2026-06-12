# Git History Scrub — Runbook (NOT yet executed)

The repo's git history contains the demo vault file set (`Bunker.mmf`,
`bunker.salt`, `bunker.cfg`, `config.cfg`) and `sample_notes_encrypted.json`.

## Decision needed first

These files are the **published demo vault** (password `rootroot` is in the
README), so as long as they only ever held demo data this is a *choice*, not
an emergency:

- **Keep the demo vault tracked** (current state): fine **only if** no real
  secret was ever stored in any committed version of these files. The new
  `.gitignore` already prevents `bunker.devkey` and `*.bak` files from being
  committed going forward.
- **Scrub the history** (recommended if there is any doubt): follow the steps
  below. Treat any password ever used with a committed vault as compromised
  and rotate it.

## Scrub steps (rewrites history — requires force-push; every clone/fork must re-clone)

```bash
# 0. Full local backup first
cp -a BUNKER2.0 BUNKER2.0.backup && cd BUNKER2.0

# 1. Stop tracking the files (keeps local copies)
git rm --cached Bunker.mmf bunker.salt bunker.cfg config.cfg sample_notes_encrypted.json
git rm --cached -r --ignore-unmatch __pycache__ main/__pycache__ .DS_Store main/.DS_Store .vscode
git commit -m "Stop tracking vault data files"

# 2. Rewrite history (git-filter-repo; removes the origin remote by design)
pip install git-filter-repo
git filter-repo --invert-paths \
  --path Bunker.mmf --path bunker.cfg --path bunker.salt --path config.cfg \
  --path sample_notes_encrypted.json \
  --path .DS_Store --path main/.DS_Store --path .vscode/settings.json \
  --path-glob '*.pyc' --path-glob 'Bunker.mmf.bak.*'

# 3. Re-add the remote and force-push ALL refs
git remote add origin <your-github-url>
git push origin --force --all
git push origin --force --tags

# 4. Verify
git rev-list --all --objects | grep -E 'Bunker.mmf|bunker.salt' || echo clean

# 5. Rotate: create a fresh vault with a NEW master password and new salt.
#    If the repo was ever public, assume the old files are permanently copied.
```

After scrubbing, ship a clean demo vault generated fresh (or document that
first run creates one), and keep the data files in `.gitignore`.
