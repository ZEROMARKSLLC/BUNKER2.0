# BUNKER 2.0 demo recording — run with: vhs bunker-demo.tape
# Produces docs/img/bunker-demo.gif (~25s walkthrough).
# Tune the Sleep values after one dry run; record against a THROWAWAY demo vault
# with IP display OFF. The demo password `rootroot` is published, so it's safe to show.

Output docs/img/bunker-demo.gif

Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1180
Set Height 760
Set Padding 16
Set Theme "Builtin Dark"
Set TypingSpeed 80ms

Hide
Type "cd ~/Desktop/BUNKER2.0 && python3 BUNKER.py"
Enter
Sleep 4s
Show

# --- ACCESS page (bunker art) ---
Sleep 2.5s
Type "n"  Enter          # don't show password
Sleep 500ms
Type "rootroot" Enter    # published demo password — safe to show
Sleep 2.5s

# --- MAIN MENU, linger so viewers can read it ---
Sleep 3s

# --- Generate a password ---
Type "f" Enter
Sleep 1s
Type "16" Enter
Sleep 3s
Type "x" Enter
Sleep 1s

# --- Account manager: add a demo profile ---
Type "a" Enter
Sleep 2s
Type "a" Enter
Sleep 1s
Type "example.com" Enter
Sleep 600ms
Type "demo@bunker.local" Enter
Sleep 600ms
# ...follow the remaining addProfile prompts with demo values...
Sleep 2.5s
Type "x" Enter

# --- Peek at notes manager, then logout ---
Type "s" Enter
Sleep 2.5s
Type "x" Enter
Sleep 1s
Type "x" Enter
Sleep 1.5s
