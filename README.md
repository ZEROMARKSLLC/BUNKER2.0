
# BUNKER 2.0: Your Digital Fortress (Terminal Edition) Price: FREE! $0 OR PAY WHAT YOU WANT! 

######## FULL SCREEN IS RECOMMENDED ########
<img width="1005" height="632" alt="och9kko23oufm3ny21w8hakint5x" src="https://github.com/user-attachments/assets/a64ccb84-0806-4e09-9270-c1bfc997a17b" />

---

## 🛡️ About BUNKER 2.0
*Local-First Encrypted Security Vault*

BUNKER 2.0 is a locally-stored, offline password and notes manager built with privacy-first principles. Using **AES-256-GCM encryption with Argon2id key derivation**, your data never leaves your device and is protected by modern, industry-standard cryptography.

https://youtu.be/DxMICmnFs_Y - DEMO VIDEO
https://zeromarks.gumroad.com/l/vmnbz - GUMROAD

**Key Features:**
- **AES-256-GCM Encryption** - Industry-standard authenticated encryption with Argon2id key derivation
- **100% Local Storage** - No cloud, no tracking, no data mining (optional IP-display feature contacts public IP-lookup services; disable it in Settings for fully offline use)
- **Self-Destruct Protection** - Multiple security triggers protect your vault
- **Auto-Logout Timer** - Configurable inactivity protection
- **Password Generator** - Create strong, random passwords instantly
- **Encrypted Notes** - Secure storage for sensitive information
- **IP Display Toggle** - Optional network monitoring
- **Brute-Force Protection** - Failed attempt tracking with vault lockdown

<img width="1005" height="648" alt="jl4s88eza1rti5bd10d4504bqk7n" src="https://github.com/user-attachments/assets/37696825-96c5-47f4-9b94-0b7baf19578f" />

---

## 🐍 Installing Python 3

To run this project, you need Python 3 installed on your system:

### 1. Visit Python.org
Go to the Python download page: https://www.python.org/downloads/

### 2. Select the Version
Download the latest stable version of Python 3 (recommended). **BUNKER 2.0 requires Python 3.10 or newer.**

### 3. Choose Your Installer
- **Windows:** Download the executable installer (`.exe`)
- **macOS:** Download the macOS installer (`.pkg`) 
- **Linux:** Use your package manager (`apt`, `yum`, `dnf`) or download source files

### 4. Run the Installer
Execute the downloaded installer and follow the setup instructions.

---

## 🚀 BUNKER 2.0 Setup Instructions

### Step 1: Navigate to BUNKER2.0 Folder

Open terminal and navigate to the BUNKER2.0 directory:

```bash
cd ~/Desktop/BUNKER2.0
```

**Note:** Ensure the BUNKER2.0 folder is located on your Desktop for this command to work.

### Step 2: Install Required Packages

**Required Dependencies:**
- `inputimeout` - Timeout handling for secure input
- `cryptography` - **AES-256 encryption library**
- `argon2-cffi` - Argon2 key derivation
- `pyperclip` - Secure clipboard management
- `psutil` - System information monitoring
- `requests` - Network utilities

**Installation Command:**
```bash
pip install -r requirements.txt
```

Or install the packages explicitly:
```bash
pip install inputimeout cryptography argon2-cffi pyperclip psutil requests
```
**Note:** `pip install` works from any directory (just point it at the right `requirements.txt` path). Being in the `BUNKER2.0` directory (showing `BUNKER2.0 %`) matters for *running* the app, since BUNKER reads and writes its vault files there.

### Step 3: Launch BUNKER 2.0

Run:
```bash
python3 BUNKER.py
```

On first run (no `Bunker.mmf` vault file present), BUNKER walks you through setup and creates a fresh encrypted vault with your own master password. On later runs, you'll reach the BUNKER ACCESS page and log in with that password.

**Starting Over:**
To wipe everything and start fresh, delete the `Bunker.mmf`, `bunker.salt`, `bunker.cfg`, and `config.cfg` files from the BUNKER2.0 folder, then run `python3 BUNKER.py` again. This is irreversible — your stored data cannot be recovered.

---

## 🔧 Troubleshooting

**Import Errors:**
If you encounter import errors on first run, install missing packages:
```bash
pip install [missing_package_name]
```

**Other Issues:**
If you experience different errors, please reach out through our social media channels for support.

---

## 💻 Security Features

**AES-256-GCM Encryption:**
- All passwords and notes encrypted with AES-256-GCM authenticated encryption
- Keys derived with Argon2id (time_cost=3, 100 MB memory, parallelism=8) chained into PBKDF2-HMAC-SHA3-256 (110,000 iterations)
- Master password never stored - validated through decryption challenge

**Self-Destruct Mechanisms:**
- Vault auto-deletion after maximum failed login attempts
- File tampering detection with instant vault wipe
- No recovery possible - intentional "burner vault" design
- **Honest caveat:** an attacker with direct disk access can reset the attempt counter (stored in `config.cfg`), so treat self-destruct as best-effort — your vault's real security rests on master-password strength and the key derivation above.

**Auto-Protection:**
- Configurable timeout (5min/30min/1hr options)
- Progressive delays between failed attempts
- Clipboard auto-clear after 30 seconds

---

## 📚 User Guide

Access the complete User Guide from the 🏚️ **MAIN MENU** 🏚️ for detailed information on all features and security settings.

---

## ⚠️ Important Disclaimer

This application is built for **educational purposes**. Use BUNKER 2.0 at your own risk. It is provided as-is, and neither the creator nor contributors take responsibility for any damage or loss incurred through its use.

**Security Note:** While BUNKER 2.0 uses industry-standard AES-256-GCM encryption, always maintain proper backup practices for critical data.

---

## 🌐 Connect with ZeroMarks LLC

**Official Channels:**
- **Website:** [zeromarks.net](http://www.zeromarks.net)
- **YouTube:** [@ZEROMARKSLLC](https://www.youtube.com/@ZEROMARKSLLC)
- **GitHub:** [github.com/zeromarksllc](https://www.github.com/zeromarksllc)
- **Reddit:** [r/zeromarksllc](https://www.reddit.com/r/zeromarksllc)

**Social Media:**
- **Twitter/X:** [@zeromarksvpn](https://x.com/zeromarksvpn)
- **TikTok:** [@zeromarksllc](https://www.tiktok.com/@zeromarksllc)
- **Instagram:** [@zeromarksllc](https://www.instagram.com/zeromarksllc)
- **Facebook:** [ZeroMarks LLC](https://www.facebook.com/zeromarksllc)

---

## 📅 Project Timeline

**Development Started:** May 10, 2024  
**Version 2.0 Completed:** June 20, 2024  
**Latest Update:** AES-256-GCM Encryption + Argon2id/PBKDF2 Hybrid Key Derivation
**gumroad** 06-15-25

**Created by:** @RIX (ZeroMarks LLC Founder)

---

## 🚀 Coming Soon

- **ZeroMarks VPN** - No-logs VPN service (release date TBD)
- **Crypto Wallet Manager** - Secure cryptocurrency key storage
- **Enhanced Brute-Force Protection** - Advanced security improvements
- **Mobile and tablet UI** - Detects Device and uses corresponding ui/ux

---

*Support privacy-first technology. Support ZeroMarks LLC.*
