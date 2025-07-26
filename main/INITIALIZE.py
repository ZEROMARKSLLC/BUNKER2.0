import base64, json, sys, getpass, os, gc, random, string, \
platform, subprocess, threading, time, pyperclip, signal,time,datetime

from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from queue import Queue
from inputimeout import inputimeout, TimeoutOccurred
from cryptography.fernet import Fernet

# Import other necessary functions
from main.SHARED_RESOURCES import (clear_screen, title_art, subwm,
divider, nuke_art, nuke_text, check_terminal_size, self_destruct,
displayHeader,)

# Constants
from main.SHARED_RESOURCES import (L_CYAN, BUNKER, DBLUE, 
FORANGE, FBLUE, FRED, GOLD, GREEN, RED, RESET, DPURPLE,
MUSTARD, VINTAGE, LPURPLE, PURPLE, CYAN )

###BUNKER HELPERS###

class SecureVaultEnhanced:
    def __init__(self):
        self.backend = default_backend()
        self.config_file = "bunker.cfg"  # Single configuration file
        self.database_file = "Bunker.mmf"
        self.salt_file = "bunker.salt"
        self.ui_config_file = "config.cfg"
        self._memory_guard = bytearray(32)
    
    
        
    def encrypt_data(self, data, key):
        """
        Encrypt data using AES-GCM
        
        Args:
            data: Bytes or string to encrypt
            key: Base64-encoded key
            
        Returns:
            Encrypted bytes (nonce + ciphertext)
        """
        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Generate a random 12-byte nonce
        nonce = os.urandom(12)
        
        # Create cipher and encrypt
        aesgcm = AESGCM(base64.urlsafe_b64decode(key))
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return nonce + ciphertext as bytes
        return nonce + ciphertext
        
    def decrypt_data(self, encrypted_data, key):
        """
        Decrypt data using AES-GCM
        
        Args:
            encrypted_data: Bytes containing nonce + ciphertext
            key: Base64-encoded key
            
        Returns:
            Decrypted bytes
        """
        # Ensure encrypted_data is bytes
        if isinstance(encrypted_data, str):
            try:
                # Try to decode as base64 first
                encrypted_data = base64.urlsafe_b64decode(encrypted_data)
            except:
                # If not base64, convert to bytes
                encrypted_data = encrypted_data.encode('utf-8')
        
        # Extract nonce and ciphertext
        nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
        
        # Create cipher and decrypt
        aesgcm = AESGCM(base64.urlsafe_b64decode(key))
        return aesgcm.decrypt(nonce, ciphertext, None)
        
    
    
    def __del__(self):
        """Secure cleanup when object is destroyed"""
        self.secure_wipe()
        
    def secure_wipe(self):
        """Securely wipe sensitive data from memory"""
        if hasattr(self, '_memory_guard'):
            for i in range(len(self._memory_guard)):
                self._memory_guard[i] = 0

    def generate_key(self) -> bytes:
        """Generate encryption key"""
        try:
            key = Fernet.generate_key()
            # Store key in the instance instead of file
            self.key = key
            # Create initial config with the key
            config = {
                "key": key.decode(),
                "timeout_value": 60,
                "settings": {"disable_ipv4": True},
                "attempts": 0,
                "last_exit": str(datetime.datetime.now().timestamp())
            }
            # Save config with the generated key
            self.save_config(config, key)
            return key
        except Exception as e:
            self.secure_wipe()
            raise ValueError(f"Key generation failed: {str(e)}")


    
    
    def derive_key_hybrid(self, password: str, salt: bytes, pepper: str = "") -> bytes:
        """Hybrid key derivation using Argon2 and PBKDF2, with optional pepper"""
        try:
            # Combine password and pepper
            password_peppered = password + pepper
            argon2_hash = hash_secret_raw(
                secret=password_peppered.encode(),
                salt=salt,
                time_cost=3,
                memory_cost=102400,
                parallelism=8,
                hash_len=KEY_SIZE,
                type=Type.ID
            )
            
            pbkdf2 = PBKDF2HMAC(
                algorithm=hashes.SHA3_256(),
                length=KEY_SIZE,
                salt=salt,
                iterations=110000,
                backend=self.backend
            )
            derived_key = pbkdf2.derive(argon2_hash)
            
            del argon2_hash
            return base64.urlsafe_b64encode(derived_key)
            
        except Exception as e:
            self.secure_wipe()
            raise ValueError(f"Key derivation failed: {str(e)}")
              
    # Add compatibility methods for import/export operations

    def decode_and_decrypt(field, profile_data, hashed_pass):
        """
        Decrypt and decode a field from a profile using AES-GCM.
        Args:
            field: The field name (e.g., 'domain', 'email', etc.)
            profile_data: The profile dictionary containing encrypted fields
            hashed_pass: The base64-encoded key for decryption
        Returns:
            The decrypted string, or "N/A" if not present or decryption fails
        """
        encrypted_value = profile_data.get(field)
        if encrypted_value is None:
            return "N/A"
        # If the value is a string, encode to bytes
        if isinstance(encrypted_value, str):
            encrypted_value = encrypted_value.encode()
        try:
            decrypted = vault.decrypt_data(encrypted_value, hashed_pass)
            return decrypted.decode("utf-8")
        except Exception:
            return "N/A"
    
    
    def secure_load(self, filename: str, key: bytes) -> bytes:
        """Securely load and decrypt data"""
        try:
            with open(filename, 'rb') as f:
                encrypted_data = f.read()
            return self.decrypt_data(encrypted_data, key)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {filename}")
        except Exception as e:
            self.secure_wipe()
            raise ValueError(f"Failed to load {filename}: {str(e)}") 
    
    def verify_password_enhanced(self, password, salt, verifier):
        """Verify password using config data"""
        try:
            key = self.derive_key_hybrid(password, salt, password)
            decrypted = self.decrypt_data(verifier, key)
            
            if decrypted == b"BUNKER_VERIFIED":
                return key
            return False
        except Exception:
            return False
        
    def secure_save(self, filename: str, data: bytes, key: bytes):
        """Securely save encrypted data with consistent format"""
        try:
            # Ensure data is bytes
            if isinstance(data, str):
                data = data.encode()
                
            # Encrypt the data
            encrypted_data = self.encrypt_data(data, key)
            
            # Write to file as bytes
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
                
            # Set proper permissions on Unix-like systems
            if os.name == 'posix':
                os.chmod(filename, 0o600)
                
        except Exception as e:
            self.secure_wipe()
            raise ValueError(f"Failed to save {filename}: {str(e)}")
        
    def secure_delete_on_failure(self):
        """Securely delete all sensitive files"""
        sensitive_files = [
            self.config_file,  
            self.database_file,
            self.salt_file,
        ]
        
        try:
            # Multiple overwrite passes for each file
            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    try:
                        file_size = os.path.getsize(file_path)
                        
                        # Multiple overwrite passes with different patterns
                        for pass_num in range(3):  # DoD standard uses 3 passes
                            with open(file_path, "wb") as file:
                                # Different patterns for each pass
                                if pass_num == 0:
                                    # Pass 1: Random data
                                    file.write(os.urandom(file_size))
                                elif pass_num == 1:
                                    # Pass 2: Zeros
                                    file.write(b'\x00' * file_size)
                                else:
                                    # Pass 3: Ones
                                    file.write(b'\xFF' * file_size)
                                    
                                # Ensure data is written to disk
                                file.flush()
                                os.fsync(file.fileno())
                        
                        # Rename file to random name before deletion to bypass file recovery
                        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                        random_path = os.path.join(os.path.dirname(file_path), random_name)
                        os.rename(file_path, random_path)
                        
                        # Platform-specific secure deletion
                        if platform.system() == 'Windows':
                            # On Windows, use low-level file deletion to bypass recycle bin
                            os.remove(random_path)
                        elif platform.system() == 'Darwin':  # macOS
                            # On macOS, use 'rm' with special flags to bypass trash
                            subprocess.run(['rm', '-P', random_path], check=False)
                        else:  # Linux and other Unix-like systems
                            # On Linux, use 'shred' for secure deletion
                            try:
                                subprocess.run(['shred', '-uzn', '3', random_path], check=False)
                            except FileNotFoundError:
                                # If shred is not available, fall back to secure overwrite
                                os.remove(random_path)
                    except Exception as e:
                        # If any step fails, try simple removal
                        try:
                            os.remove(file_path)
                        except:
                            pass
                    
        except Exception as e:
            # Don't reveal error details, just proceed with visual feedback
            pass
        finally:
            # Wipe memory
            gc.collect()  # Force garbage collection
            self.secure_wipe()

    def manage_timeout(self, key, new_timeout=None):
        """Handle timeout value operations"""
        try:
            config = self.load_config(key)
            if new_timeout is not None:
                config["timeout_value"] = new_timeout
                config["timestamp"] = str(time.time())
                self.save_config(config, key)
            return config.get("timeout_value", 60)
        except Exception as e:
            raise ValueError(f"Failed to manage timeout: {str(e)}")

    def load_timeout_value(hashed_pass):
        """Load timeout value using a temporary key approach"""
        try:
            # This is a simplified approach for loading timeout without full authentication
            # In practice, you should always use the user's password-derived key
            #temp
            #config = vault.manage_config(hashed_pass)
            #return config.get("timeout_value", 60)
            ui_config = load_ui_config()
            return ui_config.get("current_timeout", 60)
        except Exception as e:
            print(f"{GOLD}Warning: Could not load timeout value. Using default.{RESET}")
            return 60
        
    def manage_max_attempts(self, key):
        """Handle maximum attempts operations"""
        try:
            config = self.load_config(key)
            return config.get("max_attempts", 3)  # Default to 3 attempts
        except Exception as e:
            raise ValueError(f"Failed to get max attempts: {str(e)}")

    def manage_last_exit(self, key, new_timestamp=None):
        """Handle last exit timestamp operations"""
        try:
            config = self.load_config(key)
            if new_timestamp is not None:
                config["last_exit"] = str(new_timestamp)
                config["timestamp"] = str(time.time())
                self.save_config(config, key)
            return config.get("last_exit", None)
        except Exception as e:
            raise ValueError(f"Failed to manage last exit: {str(e)}")

    def manage_config(self, hashed_pass, **updates):
        """Central function for all config operations"""
        try:
            config = self.load_config(hashed_pass)
            
            # Update any provided values
            if updates:
                for k, v in updates.items():
                    if k in ['timeout_value', 'attempts', 'settings', 'last_exit']:
                        config[k] = v
                config["timestamp"] = str(time.time())
                self.save_config(config, hashed_pass)
            
            return config
        except Exception as e:
            raise ValueError(f"Failed to manage config: {str(e)}")


    def manage_settings(self, key, settings=None):
        """Handle all settings operations in one function"""
        try:
            config = self.load_config(key)
            if settings:
                # Save new settings
                config["settings"] = settings
                self.save_config(config, key)
            return config.get("settings", {"disable_ipv4": True})
        except Exception as e:
            raise ValueError(f"Failed to manage settings: {str(e)}")

    # Combined function for attempts management:
    def manage_attempts(self, key, new_attempts=None):
        """Handle all attempts operations in one function"""
        try:
            config = self.load_config(key)
            if new_attempts is not None:
                config["attempts"] = new_attempts
                config["timestamp"] = str(time.time())
                self.save_config(config, key)
            return config.get("attempts", 0)
        except Exception as e:
            raise ValueError(f"Failed to manage attempts: {str(e)}")

    def save_config(self, config_data, hashed_pass):
        """Save configuration data (always encrypted)"""
        try:
            # Encrypt the config dict as JSON using the provided key
            json_bytes = json.dumps(config_data).encode()
            encrypted = self.encrypt_data(json_bytes, hashed_pass)
            with open(self.config_file, "wb") as f:
                f.write(encrypted)
            if os.name == 'posix':
                os.chmod(self.config_file, 0o600)
        except Exception as e:
            raise ValueError(f"Failed to save config: {str(e)}")

    def load_config(self, hashed_pass):
        """Load configuration data (always decrypted)"""
        try:
            with open(self.config_file, "rb") as f:
                encrypted = f.read()
            # Decrypt and parse JSON
            decrypted = self.decrypt_data(encrypted, hashed_pass)
            return json.loads(decrypted.decode())
        except FileNotFoundError:
            return self.create_default_config(key=hashed_pass)
        except Exception as e:
            raise ValueError(f"Failed to load config: {str(e)}")

    def create_default_config(self, key):
        """Create default configuration with all necessary values"""
        config = {
            "salt": base64.b64encode(os.urandom(SALT_SIZE)).decode(),
            "verifier": "",
            #temp
            #"timeout_value": 60,
            #"max_attempts": 3,
            #"settings": {"disable_ipv4": True},
            #"attempts": 0,
            "last_exit": str(datetime.datetime.now().timestamp()),
            "timestamp": str(time.time())
        }
        self.save_config(config, key)
        return config
        

timeoutGlobalCode = "*TIMEOUT*"
vault = SecureVaultEnhanced()
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 32
RECOMMENDED_PASSWORD_LENGTH = 12
KEY_SIZE = 32
SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

def overwrite_db(new_contents):
    """Securely overwrite database with enhanced error handling and security
    
    Args:
        new_contents: The new contents to write to the database file
    """
    try:
        # Create a backup first
        try:
            if os.path.exists("Bunker.mmf"):
                backup_name = f"Bunker.mmf.bak.{int(time.time())}"
                with open("Bunker.mmf", "rb") as src, open(backup_name, "wb") as dst:
                    dst.write(src.read())
                    
                # Set proper permissions on Unix-like systems
                if os.name == 'posix':
                    os.chmod(backup_name, 0o600)
                print(f"{GOLD}Created backup: {backup_name}{RESET}")
        except Exception as e:
            print(f"{RED}Warning: Failed to create backup: {str(e)}{RESET}")
        
        # Ensure new_contents is in the correct format (bytes)
        if isinstance(new_contents, str):
            print(f"{GOLD}Converting string to bytes for database write...{RESET}")
            new_contents = new_contents.encode()
            
        # Write new contents as binary
        with open("Bunker.mmf", "wb") as file:
            file.write(new_contents)
            
        # Set proper permissions on Unix-like systems
        if os.name == 'posix':
            os.chmod("Bunker.mmf", 0o600)
            
        # Verify the write was successful
        if os.path.exists("Bunker.mmf"):
            with open("Bunker.mmf", "rb") as file:
                content = file.read()
                if content != new_contents:
                    raise ValueError("File verification failed")
                    
        print(f"{GREEN}Database saved successfully{RESET}")
        return True
        
    except Exception as e:
        print(f"{RED}** ALERT: Failed to overwrite database: {str(e)} **{RESET}")
        
        # Try to restore from backup if write failed
        try:
            backup_files = [f for f in os.listdir() if f.startswith("Bunker.mmf.bak.")]
            if backup_files:
                latest_backup = max(backup_files, key=lambda x: int(x.split(".")[-1]))
                print(f"{GOLD}Attempting to restore from backup: {latest_backup}{RESET}")
                
                with open(latest_backup, "rb") as src, open("Bunker.mmf", "wb") as dst:
                    dst.write(src.read())
                    
                print(f"{GREEN}Restored from backup{RESET}")
        except Exception as restore_error:
            print(f"{RED}** ALERT: Failed to restore from backup: {str(restore_error)} **{RESET}")
            
        return False

def generate_export_encryption(passphrase):
    """Generate encryption key and verifier for exports with enhanced security"""
    try:
        # Generate a random salt for this export
        salt = os.urandom(16)
        
        # Ensure passphrase is a string (not bytes)
        if isinstance(passphrase, bytes):
            passphrase_str = passphrase.decode('utf-8')
        else:
            passphrase_str = str(passphrase)
        
        # Create a new SecureVaultEnhanced instance
        temp_vault = SecureVaultEnhanced()
        
        # Derive export key using the passphrase and salt
        derived_key = temp_vault.derive_key_hybrid(passphrase_str, salt)
        
        # Fernet requires a 32-byte URL-safe base64-encoded key
        # The derived_key is already base64-encoded, but we need to ensure it's 32 bytes
        raw_key = base64.urlsafe_b64decode(derived_key)
        
        # Use SHA-256 to get exactly 32 bytes
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(raw_key)
        key_bytes = digest.finalize()
        
        # Create a proper Fernet key (32 bytes, base64-encoded)
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        
        # Create a verifier string using Fernet
        f = Fernet(fernet_key)
        verifier = f.encrypt(b"VALID_EXPORT_KEY")
        
        return fernet_key, salt, verifier
        
    except Exception as e:
        print(f"{RED}** ALERT: Failed to generate export encryption: {str(e)} **{RESET}")
        return None, None, None
      
def verify_export_encryption(passphrase, salt, verifier):
    """Verify export passphrase using salt and verifier with enhanced security"""
    try:
        # Ensure passphrase is a string (not bytes)
        if isinstance(passphrase, bytes):
            passphrase_str = passphrase.decode('utf-8')
        else:
            passphrase_str = str(passphrase)
            
        # Create a new SecureVaultEnhanced instance
        temp_vault = SecureVaultEnhanced()
        
        # Recreate the key from passphrase and salt
        derived_key = temp_vault.derive_key_hybrid(passphrase_str, salt)
        
        # Fernet requires a 32-byte URL-safe base64-encoded key
        # The derived_key is already base64-encoded, but we need to ensure it's 32 bytes
        raw_key = base64.urlsafe_b64decode(derived_key)
        
        # Use SHA-256 to get exactly 32 bytes
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(raw_key)
        key_bytes = digest.finalize()
        
        # Create a proper Fernet key (32 bytes, base64-encoded)
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        
        # Verify the key by decrypting the verifier
        try:
            f = Fernet(fernet_key)
            decrypted = f.decrypt(verifier)
            
            # Return the key if verification succeeds
            return fernet_key if decrypted == b"VALID_EXPORT_KEY" else None
        except Exception:
            return None
        
    except Exception as e:
        # Log the error but don't expose it to the user
        print(f"{RED}** DEBUG: Verification failed: {str(e)} **{RESET}")
        return None

def load_encrypted_file(filename, hashed_pass):
    """Load and decrypt an encrypted file with consistent format handling"""
    try:
        # Read file as binary
        with open(filename, "rb") as f:
            encrypted_data = f.read()
            
        # Decrypt the data
        decrypted_data = vault.decrypt_data(encrypted_data, hashed_pass)
        return decrypted_data
        
    except FileNotFoundError:
        raise ValueError(f"File not found: {filename}")
    except Exception as e:
        raise ValueError(f"Failed to load {filename}: {str(e)}")

def timeoutInput(caption, timeout=60, hashed_pass=None):
    """Handle timeout input with enhanced security"""
    try:
        user_input = inputimeout(prompt=caption, timeout=timeout)
    except TimeoutOccurred:
        user_input = timeoutGlobalCode
        timeoutCleanup()
    return user_input


PEPPER = os.environ.get("BUNKER_PEPPER", "default_pepper_value")

def load_ui_config(hashed_pass=None):
    try:
        key = hashed_pass or b"0"*32  # Replace with a real key if possible
        with open("config.cfg", "rb") as f:
            encrypted = f.read()
        decrypted = vault.decrypt_data(encrypted, key)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
            # Self-destruct if config.cfg is missing or corrupted
            print(f"{RED}** ALERT: UI config file missing or corrupted. Self-destructing... **{RED}")
            self_destruct()
            sys.exit(1)
    
def save_ui_config(config, hashed_pass=None):
    # If you have the password/key, use it; otherwise, use a static key for now
    key = hashed_pass or b"0"*32  # Replace with a real key if possible
    data = json.dumps(config).encode("utf-8")
    encrypted = vault.encrypt_data(data, key)
    with open("config.cfg", "wb") as f:
        f.write(encrypted)

def save_salt(salt, filename="bunker.salt"):
    with open(filename, "wb") as f:
        f.write(salt)

def load_salt(filename="bunker.salt"):
    with open(filename, "rb") as f:
        return f.read()

def generate_salt(length=32):
    return os.urandom(length)

 
def secure_cleanup_common():
    """
    Common cleanup operations shared by all exit scenarios.
    This handles the sensitive data cleanup without any user messaging.
    """
    try:
        # Reset global variables
        global cached_ip
        cached_ip = None
        
        # Clear any active threads
        try:
            # Stop any running background threads
            if 'ip_fetch_thread' in globals() and globals()['ip_fetch_thread'] is not None:
                if hasattr(globals()['ip_fetch_thread'], 'do_run'):
                    globals()['ip_fetch_thread'].do_run = False
        except Exception:
            # Silently handle thread cleanup errors
            pass
            
        # Clear clipboard if it contains sensitive data
        try:
            pyperclip.copy("")
        except Exception:
            # Silently handle clipboard errors
            pass
            
        # Secure memory cleanup
        try:
            # Create a vault instance for secure wiping
            vault.secure_wipe()
            
            # Force garbage collection to clean up memory
            import gc
            gc.collect()
        except Exception:
            # Silently handle memory cleanup errors
            pass
            
        return True
    except Exception as e:
        print(f"{RED}Error during common cleanup: {str(e)}{RESET}")
        return False

def timeoutCleanup():
    """
    Perform secure cleanup when a session timeout occurs.
    Clears sensitive data from memory, displays a timeout message, and exits the program.
    """
    try:
        # Clear the screen to remove any sensitive information
        clear_screen()
        
        # Run common cleanup operations
        secure_cleanup_common()
            
        # Display timeout message
        print(title_art)
        print(
            f"{CYAN}\n\nYour session has expired due to inactivity. For your security, the program has automatically logged you out.{RESET}"
        )
        print(
            f"{GREEN}All submitted data has been securely saved.{RESET}\n\n"
        )
            
        # Exit the program securely
        os._exit(0)  # Use exit code 0 for normal exit
        
    except Exception as e:
        # If any error occurs during cleanup, force exit
        print(f"{RED}Error during timeout cleanup: {str(e)}{RESET}")
        os._exit(1)  # Use exit code 1 for error exit

def interruptCleanup():
    """
    Perform secure cleanup when the user interrupts the program (Ctrl+C).
    Clears sensitive data from memory, displays an interrupt message, and exits the program.
    """
    try:
        # Clear the screen to remove any sensitive information
        clear_screen()
        
        # Run common cleanup operations
        secure_cleanup_common()
            
        # Display interrupt message
        print(title_art)
        print(
            f"{CYAN}\n\nProgram interrupted by user (Ctrl+C). For your security, the program has been safely terminated.{RESET}"
        )
        print(
            f"{GREEN}All submitted data has been securely saved.{RESET}\n\n"
        )
        print(
            f"{GOLD}Thank you for using BUNKER. Goodbye!{RESET}\n\n"
        )
            
        # Exit the program securely
        os._exit(0)  # Use exit code 0 for normal exit
        
    except Exception as e:
        # If any error occurs during cleanup, force exit
        print(f"{RED}Error during interrupt cleanup: {str(e)}{RESET}")
        os._exit(1)  # Use exit code 1 for error exit

def errorCleanup(error_message="An unexpected error occurred"):
    """
    Perform secure cleanup when an error occurs.
    Clears sensitive data from memory, displays an error message, and exits the program.
    
    Args:
        error_message: Specific error message to display
    """
    try:
        # Clear the screen to remove any sensitive information
        clear_screen()
        
        # Run common cleanup operations
        secure_cleanup_common()
            
        # Display error message
        print(title_art)
        print(
            f"{RED}\n\n** ALERT: {error_message} **{RESET}"
        )
        print(
            f"{CYAN}The program has been safely terminated to protect your data.{RESET}"
        )
        print(
            f"{GREEN}All submitted data has been securely saved.{RESET}\n\n"
        )
            
        # Exit the program securely
        os._exit(1)  # Use exit code 1 for error exit
        
    except Exception as e:
        # If any error occurs during cleanup, force exit
        print(f"{RED}Error during error cleanup: {str(e)}{RESET}")
        os._exit(1)  # Use exit code 1 for error exit

# Global keyboard interrupt handler
def keyboard_interrupt_handler(signal_num, frame):
    """
    Handle keyboard interrupt (Ctrl+C) by running the interruptCleanup function
    instead of showing the default traceback.
    """
    print(f"\n{RED}** ALERT: Program interrupted by user (Ctrl+C) **{RESET}")
    print(f"{GOLD}Running secure cleanup...{RESET}")
    interruptCleanup()  # This will exit the program

def register_handlers():
    """Register signal handlers for graceful termination"""
    try:
        # Register handler for SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, keyboard_interrupt_handler)
        
        # On Unix systems, also handle SIGTERM
        if platform.system() != "Windows":
            signal.signal(signal.SIGTERM, keyboard_interrupt_handler)
            
        return True
    except Exception as e:
        print(f"{RED}Warning: Could not register signal handlers: {str(e)}{RESET}")
        return False

def setup_secure_exit_handlers():
    """Set up all secure exit handlers"""
    # Register signal handlers
    register_handlers()
    
    # Register atexit handler as a backup
    import atexit
    atexit.register(timeoutCleanup)
    
    # Set up sys.excepthook to catch unhandled exceptions
    original_excepthook = sys.excepthook
    
    def custom_excepthook(exc_type, exc_value, exc_traceback):
        if exc_type == KeyboardInterrupt:
            keyboard_interrupt_handler(None, None)
        else:
            # For other exceptions, use the error cleanup
            errorCleanup(f"Unhandled exception: {str(exc_value)}")
    
    sys.excepthook = custom_excepthook

def getpass_thread(prompt, q):
    """Thread function to get password input securely"""
    try:
        password = getpass.getpass(prompt)
        q.put(password)
    except Exception as e:
        # Put the error in the queue instead of the password
        q.put(f"ERROR: {str(e)}")

def timeout_getpass(prompt, timeout):
    """Get password with timeout and enhanced error handling"""
    if timeout is None or timeout <= 0:
        # If timeout is invalid, use getpass directly
        return getpass.getpass(prompt)
        
    q = Queue()
    t = threading.Thread(target=getpass_thread, args=(prompt, q), daemon=True)
    t.start()
    t.join(timeout)
    
    if t.is_alive():
        # Thread is still running after timeout
        try:
            # Attempt to terminate the thread gracefully
            timeoutCleanup()
            # Raise TimeoutError to be caught by caller
            raise TimeoutError("Password input timed out")
        finally:
            # Exit if cleanup fails
            sys.exit(1)
    else:
        # Get the result from the queue
        result = q.get()
        
        # Check if the thread encountered an error
        if isinstance(result, str) and result.startswith("ERROR:"):
            raise ValueError(result)
            
        return result


def fileSetup(hashed_pass):
    """Setup and load encrypted files with enhanced security"""
    try:
        config = vault.manage_config(hashed_pass)
        
        # Get salt and verifier from config
        salt = base64.b64decode(config["salt"])
        verifier = base64.b64decode(config["verifier"])
        
        # Validate sizes
        if len(salt) != SALT_SIZE:
            raise ValueError(f"Invalid salt size: {len(salt)} bytes")
        if len(verifier) < 20:
            raise ValueError(f"Invalid verifier size: {len(verifier)} bytes")
            
        # Load database
        database = loadDatabase(hashed_pass)
        
        return salt, verifier, database
    except Exception as e:
        print(f"{RED}** ALERT: Error loading security files: {str(e)} **{RESET}")
        self_destruct()

def saveDatabase(db, hashed_pass):
    """Save database with enhanced security"""
    try:
        db_bytes = json.dumps(db).encode('utf-8')
        encrypted_db = vault.encrypt_data(db_bytes, hashed_pass)
        with open("Bunker.mmf", "wb") as f:
            f.write(encrypted_db)
        if os.name == 'posix':
            os.chmod("Bunker.mmf", 0o600)
        file_size = os.path.getsize("Bunker.mmf")
        if file_size < 100 and len(db) > 0:
            raise ValueError(f"Database file too small ({file_size} bytes)")
        # Only update config if it loads successfully
        try:
            vault.manage_config(
                hashed_pass,
                last_modified=str(datetime.datetime.now().timestamp())
            )
        except Exception as e:
            print(f"{GOLD}Warning: Could not update config last_modified: {str(e)}{RESET}")
        return True
    except Exception as e:
        print(f"{RED}** ALERT: Failed to save database: {str(e)} **{RESET}")
        return False
    
def loadDatabase(hashed_pass):
    """
    Load the main database (Bunker.mmf) with consistent format
    
    Args:
        hashed_pass: Decryption key
        
    Returns:
        Database dictionary
    """
    try:
        # Check if database file exists
        if not os.path.exists("Bunker.mmf"):
            print(f"{GOLD}Database file does not exist. Creating new empty database.{RESET}")
            self_destruct()
            return {}
            
        # Read the encrypted database in binary mode
        with open("Bunker.mmf", "rb") as f:
            encrypted_db = f.read()
            
        # Check file size
        file_size = len(encrypted_db)
        if file_size < 20:  # Even an empty encrypted database should be larger than this
            print(f"{GOLD}Database file is very small ({file_size} bytes). It may be corrupted.{RESET}")
            
        # Decrypt the database
        decrypted_bytes = vault.decrypt_data(encrypted_db, hashed_pass)
        
        # Parse the JSON data
        db = json.loads(decrypted_bytes.decode('utf-8'))
        return db
            
    except Exception as e:
        print(f"{RED}** ALERT: Failed to load database: {str(e)} **{RESET}")
        raise ValueError(f"Database format is invalid: {str(e)}")
def load_max_attempts(hashed_pass):
    """Load max attempts using manage_config"""
    try:
        config = vault.manage_config(hashed_pass)
        return config.get("max_attempts", 3)
    except Exception as e:
        print(f"{GOLD}Warning: Could not load max attempts. Using default value.{RESET}")
        return 3

def setup_timeout() -> Optional[int]:
    """Configure timeout settings"""
    while True:
        try:
            timeout_choice = input(
                f"{GOLD}Enter timeout value in seconds (10-3600, or 0 for no timeout. "
                f"Press enter for recommended 60 seconds, .c to cancel): {RESET}"
            )

            if timeout_choice == ".c":
                print(f"{GREEN}Operation cancelled...{RESET}")
                return None

            if timeout_choice.strip() == "":
                return 60

            timeout_value = int(timeout_choice)
            if timeout_value == 0:
                confirm = input(f"{RED}** WARNING: Are you sure you want to disable auto-logout? (y/n): {RESET}").lower()
                if confirm != 'y':
                    continue
                return 0
            elif 10 <= timeout_value <= 3600:
                return timeout_value
            else:
                print(f"{RED}** ALERT: Timeout must be between 10 and 3600 seconds, or 0 for no timeout. **{RESET}")
        except ValueError:
            print(f"{RED}** ALERT: Please enter a valid number. **{RESET}")
  
def verify_setup(vault: SecureVaultEnhanced, password: str, salt: bytes, verifier: bytes) -> bool:
    """Verify the vault setup"""
    try:
        derived_key = vault.derive_key_hybrid(password, salt)
        if not derived_key:
            return False
            
        decrypted = vault.decrypt_data(verifier, derived_key)
        # FIXED: Use the same verifier string as in vaultSetup
        return decrypted == b"BUNKER_VERIFIED"
    except Exception as e:
        print(f"{RED}** ALERT: Verification failed: {str(e)} **{RESET}")
        return False

def vaultSetup():
    """Setup vault with enhanced security while maintaining original process"""
    try:
        while True:
            setup_choice = input(f"\n{GOLD}Enter (.g) for simplified user guide, or (y/n) if you're ready to setup bunker password: {RESET}").lower()
            if setup_choice == 'y':
                break
            elif setup_choice == 'n':
                check_terminal_size()
                clear_screen()
                print(title_art)
                print(subwm)
                print(divider)
                print(f"{GREEN}Exiting...{RESET}")
                return False
            elif setup_choice == '.g':
                # Display user guide without requiring login
                display_setup_guide()
                continue
            else:
                print(f"{RED}** ALERT: Invalid input. Please enter y, n, or .g. **{RESET}")
                continue

        while True:
            show_password_choice = input(f"{GOLD}Do you want to show your password? (y/n) or (.c) to cancel: {RESET}").lower()
            if show_password_choice == 'y':
                show_password = True
                print(f"{RED}** ALERT: Your password will be shown as you type. **{RESET}")
                password_provided = input(f"{GOLD}Enter Password: {RESET}")
                if password_provided == '.c':
                    print(f"{GREEN}Operation cancelled...{RESET}")
                    return False
                    
                password_confirmation = input(f"{GOLD}Confirm password: {RESET}")
                if password_confirmation == '.c':
                    print(f"{GREEN}Operation cancelled...{RESET}")
                    return False
                    
                if password_provided != password_confirmation:
                    print(f"{RED}** ALERT: Passwords do not match. Please try again. **{RESET}")
                    continue
                    
                if len(password_provided) < 8:
                    print(f"{RED}** ALERT: Password must be at least 8 characters long. **{RESET}")
                    continue
                    
                break
                
            elif show_password_choice == 'n':
                show_password = False
                password_provided = getpass.getpass(f"{GOLD}Enter Password: {RESET}")
                if password_provided == '.c':
                    print(f"{GREEN}Operation cancelled...{RESET}")
                    return False
                    
                password_confirmation = getpass.getpass(f"{GOLD}Confirm password: {RESET}")
                if password_confirmation == '.c':
                    print(f"{GREEN}Operation cancelled...{RESET}")
                    return False
                    
                if password_provided != password_confirmation:
                    print(f"{RED}** ALERT: Passwords do not match. Please try again. **{RESET}")
                    continue
                    
                if len(password_provided) < 8:
                    print(f"{RED}** ALERT: Password must be at least 8 characters long. **{RESET}")
                    continue
                    
                break
                
            elif show_password_choice == '.c':
                print(f"{GREEN}Operation cancelled...{RESET}")
                return False
            else:
                print(f"{RED}** ALERT: Invalid input. Please enter y, n, or .c. **{RESET}")
                continue

        try:
            # Generate salt and save it separately
            salt = os.urandom(SALT_SIZE)
            save_salt(salt)

            # Derive key using password + salt (+ optional pepper)
            pepper = os.environ.get("BUNKER_PEPPER", "")
            derived_key = vault.derive_key_hybrid(password_provided, salt, password_provided)
            # Setup timeout with cancel option
            timeout_value = setup_timeout()
            if timeout_value is None:
                print(f"{GREEN}Operation cancelled...{RESET}")
                vault.secure_delete_on_failure()
                return False

            # Create initial config structure
            config = {
                "salt": base64.b64encode(salt).decode(),
                "verifier": base64.b64encode(vault.encrypt_data(b"BUNKER_VERIFIED", derived_key)).decode(),
                #"timeout_value": timeout_value,
                #"max_attempts": 3,
                #"settings": {"disable_ipv4": True},
                #"attempts": 0,
                "last_exit": str(datetime.datetime.now().timestamp()),
                "timestamp": str(time.time())
            }
            #temp tell untill we solve the encryption issue where 
            #we need the password to get to decrypt config but cant acess it without the login
            ui_config = {
                "attempts": 0,
                "max_attempts": 3,
                "disable_ipv4": True,
                "current_timeout": timeout_value
            }
            save_ui_config(ui_config)

            # Encrypt and save config
            encrypted_config = vault.encrypt_data(json.dumps(config).encode(), derived_key)
            with open("bunker.cfg", "wb") as f:
                f.write(encrypted_config)
            if os.name == 'posix':
                os.chmod("bunker.cfg", 0o600)

            # Initialize empty database separately
            empty_db = {}
            if not saveDatabase(empty_db, derived_key):
                raise ValueError("Failed to save initial database")

            # Display success
            clear_screen()
            print(title_art)
            print(subwm)
            print(divider)

            if timeout_value == 0:
                print(f"{RED}** WARNING: Auto-logout is disabled **{RESET}")
            else:
                print(f"{GREEN}Auto-logout timer set to: {timeout_value} seconds{RESET}")

            print(f"\n{GREEN}** SUCCESS: Vault setup complete! **{RESET}")
            input(f"{GOLD}Press ENTER to continue: {RESET}")

            time.sleep(0.5)
            return True

        except Exception as e:
            print(f"{RED}** ALERT: Setup failed: {str(e)} **{RESET}")
            vault.secure_delete_on_failure()
            return False
    except Exception as e:
        print(f"{RED}** ALERT: Setup failed: {str(e)} **{RESET}")
        vault.secure_delete_on_failure()
        return False
    finally:
        # Secure cleanup
        for var in ['password_provided', 'password_confirmation', 'derived_key', 'master_key']:
            if var in locals():
                del locals()[var]
        vault.secure_wipe()
             
def main():
    """Main entry point"""
    check_terminal_size()
    clear_screen()
    if not vaultSetup():
        print(nuke_art)
        print(nuke_text)
        print(divider)
        sys.exit(1)

if __name__ == "__main__":
    main()


def display_setup_guide():
    """Display a simplified user guide during setup phase"""
    clear_screen()
    print(title_art)
    print(subwm)
    print(divider)
    print(f"{CYAN}📘 SETUP GUIDE{RESET}")
    
    sections = {
        "1": {
            "title": "Introduction",
            "color": RESET,
            "content": f"\n{GOLD}----- Welcome to the Bunker Setup Guide -----{RESET}\n\n"
            f"{RESET}Our unique bunker-style approach guarantees that your saved data is automatically deleted if tampering is detected or any unauthorized changes are made. "
            f"Additionally, the application will self-destruct after three incorrect password attempts, providing unparalleled protection.{RESET}\n\n"
            f"{CYAN}All stored data is encrypted using industry-standard encryption algorithms and is kept on your own PC, ensuring your information is secure and private. {RESET}\n\n"
            + f"{GOLD}----- Security Features -----{RESET}\n\n"
            + "\n".join(
                [
                    f"{GOLD}• {CYAN}Self Destruct:{RESET} The application will self-destruct data after three incorrect password attempts.",
                    f"{GOLD}• {CYAN}Data Encryption:{RESET} All stored data is encrypted using industry-standard encryption algorithms.",
                    f"{GOLD}• {CYAN}Local Storage:{RESET} All data is stored locally on your PC, not in the cloud, ensuring maximum privacy.",
                    f"{GOLD}• {CYAN}Timeouts and Auto-Logout:{RESET} The application will automatically log out after a specified period of inactivity to prevent unauthorized access.\n\n",
                ]
            )
        },
        "2": {
            "title": "Setup Instructions",
            "color": CYAN,
            "content": f"\n{CYAN}----- Setup Process -----{RESET}\n\n"
            + "\n".join(
                [
                    f"{GOLD}1. {RESET}Choose whether to show your password during typing.",
                    f"{GOLD}2. {RESET}Create a strong master password (minimum 8 characters).",
                    f"{GOLD}3. {RESET}Confirm your password by typing it again.",
                    f"{GOLD}4. {RESET}Set an auto-logout timer (10-3600 seconds, or 0 to disable).",
                    f"{GOLD}5. {RESET}Your vault will be created and ready to use.",
                ]
            )
            + f"\n\n{CYAN}----- Password Tips -----{RESET}\n\n"
            + "\n".join(
                [
                    f"{GOLD}• {RESET}Use a mix of uppercase and lowercase letters, numbers, and special characters.",
                    f"{GOLD}• {RESET}Avoid using easily guessable information like birthdays or names.",
                    f"{GOLD}• {RESET}Consider using a passphrase that's easy for you to remember but hard for others to guess.",
                    f"{GOLD}• {RESET}Your master password cannot be recovered if lost, so make sure to remember it!",
                ]
            )
        },
        "3": {
            "title": "Important Notes",
            "color": LPURPLE,
            "content": f"\n{LPURPLE}----- Important Notes -----{RESET}\n\n"
            + "\n".join(
                [
                    f"{GOLD}• {RESET}You can cancel the setup at any time by typing {GOLD}.c{RESET} at password prompts.",
                    f"{GOLD}• {RESET}The auto-logout timer helps protect your data if you step away from your computer.",
                    f"{GOLD}• {RESET}After setup, you'll be able to store account information and secure notes.",
                    f"{GOLD}• {RESET}The application will self-destruct all data after three incorrect password attempts.",
                    f"{GOLD}• {RESET}All data is stored locally on your device with strong encryption.",
                ]
            )
        }
    }
    
    def print_section(section):
        print(f"{DBLUE}{'*' * 5} {section['color']}{section['title']} {DBLUE}{'*' * 5}{RESET}")
        print(section["content"])
        print("\n")
    
    def display_menu_setup():
        print(f"{GOLD}Table of Contents: {RESET}\n")
        for key, section in sections.items():
            print(f"{CYAN}p. {key} {GOLD}| {section['color']}{section['title']}{RESET}")
    
    # Display the guide
    display_menu_setup()
    
    while True:
        choice = input(f"\n{GOLD}Enter the index number of the section you want to explore (press 'enter' to display all, type '.c' to return): {RESET}")
        
        if choice == ".c":
            clear_screen()
            print(title_art)
            print(subwm)
            print(divider)
            print(
                f"{CYAN}\nBUNKER SETUP\n\nWelcome to Bunker!\n\n{RED}ALERT: Bunker.mmf was DESTROYED or not found in local directory... SETUP A NEW PASSWORD!{RESET}"
                )
            return
            
        if choice == "":
            clear_screen()
            print(f"{CYAN}📘 SETUP GUIDE{RESET}")
            for section in sections.values():
                print_section(section)
                
        elif choice in sections:
            clear_screen()
            print(f"{CYAN}📘 SETUP GUIDE{RESET}")
            print_section(sections[choice])
            
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")
            
        input(f"{GOLD}\nPress 'enter' to return to menu...{RESET}")
        clear_screen()
        print(title_art)
        print(subwm)
        print(divider)
        print(f"{CYAN}📘 SETUP GUIDE{RESET}")
        display_menu_setup()

def display_user_guide(hashed_pass, db):
    """Display comprehensive user guide with enhanced security"""
    sections = {
        "1": {
            "title": "Introduction",
            "color": RESET,
            "content": f"\n{GOLD}----- Welcome to the Bunker User Guide -----{RESET}\n\n"
            f"{RESET}Our unique bunker-style approach guarantees that your saved data is automatically deleted if tampering is detected or any unauthorized changes are made. "
            f"Additionally, the application will self-destruct after three incorrect password attempts, providing unparalleled protection.{RESET}\n\n"
            f"{CYAN}All stored data is encrypted using industry-standard encryption algorithms and is kept on your own PC, ensuring your information is secure and private. {RESET}\n\n"
            + f"{GOLD}----- Security Features -----{RESET}\n\n"
            + "\n".join(
                [
                    f"{GOLD}• {CYAN}Self Destruct:{RESET} The application will self-destruct data after three incorrect password attempts.",
                    f"{GOLD}• {CYAN}Data Encryption:{RESET} All stored data is encrypted using industry-standard encryption algorithms.",
                    f"{GOLD}• {CYAN}Local Storage:{RESET} All data is stored locally on your PC, not in the cloud, ensuring maximum privacy.",
                    f"{GOLD}• {CYAN}Timeouts and Auto-Logout:{RESET} The application will automatically log out after a specified period of inactivity to prevent unauthorized access.\n\n",
                ]
            )
            + f"{GOLD}----- Features: -----{RESET}\n\n"
            f"{GOLD}• {L_CYAN}Save Accounts:{RESET} Securely store your account information.{RESET}\n"
            f"{GOLD}• {L_CYAN}Save Notes:{RESET} Securely store your important notes.{RESET}\n"
            f"{GOLD}• {L_CYAN}Export/Import Data:{RESET} Easily manage and transfer your data.{RESET}\n"
            f"{GOLD}• {CYAN}Check IP:{RESET} Quickly check your IP address using the `api.ipify.org` service.{RESET}\n"
            f"{GOLD}• {CYAN}System Information:{RESET} Access detailed system information at a glance.{RESET}\n"
            f"{GOLD}• {CYAN}Generate Passwords:{RESET} Create secure, complex passwords.{RESET}\n"
            f"{GOLD}• {CYAN}Check Password Strength:{RESET} Evaluate the strength of your passwords to ensure they meet security standards.{RESET}\n"
            f"{GOLD}• {CYAN}Auto-Logout:{RESET} Automatically log out after a period of inactivity to ensure your data remains secure.{RESET}\n\n"
            f"{GOLD}----- My Vision For ZEROMARKSLLC: -----{RESET}\n\n"
            f"{RESET}My vision is to set a new standard in cybersecurity, prioritizing the user safety over profits. We aim to build a blueprint for future companies, "
            f"not like the current leading corporate entities, we focus on uncompromising integrity and innovation.{RESET}\n\n"
            f"{CYAN}Thank you for choosing ZEROMARKSLLC, where your security is our top priority. Innovation is our purpose.\n\n{RESET}"
            f"{DBLUE}\n\n                                            *** {RESET}PAGE 1{DBLUE} ***{RESET}",
        },
        "2": {
            "title": "Menu Information",
            "color": CYAN,
            "content": (
                f"\nMost of the inputs are designed to be easily accessible with your left hand on the keyboard, allowing for a more comfortable and efficient user experience.\n"
                f"{CYAN}\n----- 🏚️  Main Menu 🏚️  -----{RESET}\n"
                + f"{CYAN}\nWhen you launch the application, you'll be greeted with the main menu. Here's how to navigate:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}(a) {CYAN}👤 Manage Accounts:{RESET} Manage user profiles and account-related functionalities.",
                        f"{GOLD}(s) {CYAN}🗂️  Manage Notes:{RESET} Create, edit, and manage notes.",
                        f"{GOLD}(d) {CYAN}💻 Display IP:{RESET} Display IP addresses using an online API.",
                        f"{GOLD}(f) {CYAN}🪄 Generate Password{RESET}: Generate secure passwords for your accounts.",
                        f"{GOLD}(g) {CYAN}📘 User Guide:{RESET} Access this user guide for detailed instructions.",
                        f"{GOLD}(c) {CYAN}🔑 Change Login Password:{RESET} Change your login password.",
                        f"{GOLD}(r) {CYAN}🔍 Check Password Strength:{RESET} Check the strength of a password.",
                        f"{GOLD}(e) {CYAN}🖥️  System Info:{RESET} Display detailed system information.",
                        f"{GOLD}(t) {CYAN}⏲️  Change Auto-Logout Timer:{RESET} Adjust the auto-logout timer settings.",
                        f"{GOLD}(x) {PURPLE}🚪 Logout:{RESET} Logout from the application.",
                    ]
                )
                + "\n\n"
                + f"{L_CYAN}----- 👤 Account Manager -----{RESET}\n\n"
                + f"{L_CYAN}The Account Manager allows you to handle all user profiles within the application. Here are the options available:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}(a) {L_CYAN}✏️  Add Profile:{RESET} Create a new user profile with unique credentials.",
                        f"{GOLD}(s) {L_CYAN}⭐ Favorite Profiles:{RESET} Mark and manage profiles you use frequently.",
                        f"{GOLD}(d) {L_CYAN}🗑️  Delete Profile:{RESET} Remove an existing user profile from the system.",
                        f"{GOLD}(f) {L_CYAN}🔍 Find Profile:{RESET} Search for a specific user profile by name or other criteria.",
                        f"{GOLD}(c) {L_CYAN}⬆️  Import/Export Profiles:{RESET} Import/Export user profiles from external sources or backups.",
                        f"{GOLD}(r) {L_CYAN}📖 Read All Profiles:{RESET} View a list of all user profiles stored in the application.",
                        f"{GOLD}(e) {L_CYAN}🖍️  Edit Profile:{RESET} Modify details of an existing user profile.",
                        f"{GOLD}(t) {L_CYAN}🏷️  Tags Folder:{RESET} Organize notes using tags for easy retrieval.",
                        f"{GOLD}(x) {PURPLE}🔙 Back:{RESET} Return to the previous menu.",
                    ]
                )
                + "\n\n"
                + f"{L_CYAN}----- 🗂️  Note Manager -----{RESET}\n\n"
                + f"{L_CYAN}The Note Manager helps you organize and manage your notes securely. Here are the options available:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}(a) {L_CYAN}📝 Add Note:{RESET} Create a new note with title and content.",
                        f"{GOLD}(s) {L_CYAN}⭐ Favorite Notes:{RESET} Mark and manage notes you use frequently.",
                        f"{GOLD}(d) {L_CYAN}🗑️  Delete Note:{RESET} Remove an existing note from the system.",
                        f"{GOLD}(f) {L_CYAN}🔍 Find Note:{RESET} Search for a specific note by keywords or tags.",
                        f"{GOLD}(c) {L_CYAN}⬆️  Import/Export Profiles:{RESET} Import/Export user notes from external sources or backups.",
                        f"{GOLD}(r) {L_CYAN}📖 Read All Notes:{RESET} View a list of all notes stored in the application.",
                        f"{GOLD}(e) {L_CYAN}🖍️  Edit Note Data:{RESET} Modify the content of an existing note.",
                        f"{GOLD}(t) {L_CYAN}🏷️  Tags Folder:{RESET} Organize notes using tags for easy retrieval.",
                        f"{GOLD}(x) {PURPLE}🔙 Back:{RESET} Return to the previous menu.\n\n",
                    ]
                )
                + f"{DBLUE}\n\n                                            *** {CYAN}PAGE 2{DBLUE} ***{RESET}"
            ),
        },
        "3": {
            "title": "Privacy and Security",
            "color": LPURPLE,
            "content": (
                f"\n{RESET}Welcome to {CYAN}ZEROMARKSLLC{RESET}, where we prioritize your security and privacy with cutting-edge technologies and thoughtful features. Trust and security are woven into every line of code. We empower you with a robust platform to manage your sensitive information confidently and privately.\n\n{RESET}"
                + f"{LPURPLE}Fortified Encryption Protocols{RESET}: Your data is shielded by advanced encryption algorithms that meet industry standards, ensuring it remains confidential and unreadable to unauthorized access.\n"
                + f"\n{LPURPLE}Zero Exposure to Cloud Risks{RESET}: We champion your privacy by storing all sensitive information strictly on your local device. This approach eliminates vulnerabilities associated with cloud-based storage.\n"
                + f"\n{LPURPLE}Self-Defense Mechanisms{RESET}: Our application includes intelligent tamper detection. If any unauthorized attempt is detected, all stored data is instantly purged, safeguarding your information from breaches.\n"
                + f"\n{LPURPLE}Innovative Password Management{RESET}: Enjoy hassle-free security with features like an auto-logout timer that activates after periods of inactivity and a robust password generator that crafts strong, unique passwords tailored to each account.\n"
                + f"\n{LPURPLE}Secure Note Repository{RESET}: Store and manage important notes securely alongside passwords, ensuring easy access while maintaining the highest levels of data protection.\n"
                + f"\n{LPURPLE}Continuous Vigilance{RESET}: We are committed to staying ahead of threats. Our team constantly updates our security protocols and application features to shield you from evolving cyber risks.\n\n"
                f"{DBLUE}\n\n                                            *** {LPURPLE}PAGE 3{DBLUE} ***{RESET}"
            ),
        },
        "4": {
            "title": "Troubleshooting Tips",
            "color": VINTAGE,
            "content": (
                f"{RESET}\nEncountering an issue? We've got you covered. Follow these steps to troubleshoot common problems effectively:{RESET}\n\n"
                + f"{VINTAGE}Restart the Application{RESET}: Often, simply restarting the application can resolve minor issues. Close the app completely and reopen it to see if the problem persists.\n"
                + f"{VINTAGE}\nCheck for Updates{RESET}: Ensure you are using the latest version of the application. Updates often include bug fixes and performance improvements. Visit our website or app store to download the latest version.\n"
                + f"{VINTAGE}\nConsult the Documentation{RESET}: Our comprehensive online documentation covers a wide range of topics and common issues. Visit our support page to find step-by-step guides and FAQs that may address your problem.\n"
                + f"{VINTAGE}\nReview System Requirements{RESET}: Make sure your device meets the minimum system requirements for running the application. Incompatibilities can sometimes cause unexpected errors.\n"
                + f"{VINTAGE}\nClear Cache and Data{RESET}: If the application is still not functioning correctly, try clearing the cache and data. This can resolve issues related to corrupted files or settings.\n"
                + f"{VINTAGE}\nContact Support{RESET}: If none of the above steps resolve your issue, our support team is here to help. Reach out to us through our support page, and we'll assist you in diagnosing and fixing the problem.\n\n"
                + f"{VINTAGE}Remember, we’re committed to providing a seamless experience. Don't hesitate to reach out for assistance whenever needed. Your satisfaction is our priority.\n\n{RESET}"
                f"{DBLUE}\n\n                                            *** {VINTAGE}PAGE 4{DBLUE} ***{RESET}"
            ),
        },
        "5": {
            "title": "Support",
            "color": MUSTARD,
            "content": (
                f"{RESET}\nIf you encounter any issues or need further assistance, Here are the ways you can reach us:{RESET}\n\n"
                + f"{MUSTARD}----- 💬 Support and Contact Information -----{RESET}\n\n"
                + f"{MUSTARD}Email{RESET}: support@zeromarks.net\n"
                + f"{MUSTARD}Website{RESET}: [www.zeromarks.net/support](http://www.zeromarks.net/support)\n\n"
                + f"{RESET}For immediate assistance, please check our online resources:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{MUSTARD}FAQs{RESET}: Visit our [Frequently Asked Questions](http://www.zeromarksllc.com/faqs) page for quick answers.",
                        f"{MUSTARD}User Guide{RESET}: Explore our comprehensive [User Guide](http://www.zeromarksllc.com/user-guide) for detailed instructions.",
                        f"{MUSTARD}Community Forum{RESET}: Join our [Community Forum](http://www.zeromarksllc.com/forum) to ask questions and share tips.",
                    ]
                )
                + "\n\n"
                + f"{MUSTARD}We value your feedback! If you have suggestions or encounter any issues, please don't hesitate to let us know. Our support team is dedicated to providing the best possible experience for our users.{RESET}\n\n"
                + f"{MUSTARD}----- Follow Us on Social Media: -----{RESET}\n"
                + f"{RESET}\nStay updated and connect with us on social media:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}• {MUSTARD}\n**Other Media:** ",
                        f"{GOLD}• {MUSTARD}[Website] |{RESET} http://www.zeromarks.net ",
                        f"{GOLD}• {MUSTARD}[Youtube] |{RESET} https://www.youtube.com/@ZEROMARKSLLC",
                        f"{GOLD}• {MUSTARD}[Reddit] |{RESET} https://www.reddit.com/zeromarksllc",
                        f"{GOLD}• {MUSTARD}[Github] |{RESET} https://www.github.com/zeromarksllc",
                        f"{GOLD}• {MUSTARD}\n **Social Media:** ",
                        f"{GOLD}• {MUSTARD}[Twitter / X] |{RESET} https://x.com/ZEROMARKSLLC",
                        f"{GOLD}• {MUSTARD}[Instagram] |{RESET} https://www.instagram.com/zeromarksllc",
                        f"{GOLD}• {MUSTARD}[TikTok] |{RESET} https://www.tiktok.com/zeromarksllc",
                        f"{GOLD}• {MUSTARD}[LinkedIn] |{RESET} https://www.linkedin.com/in/zeromarksllc",
                    ]
                )
                + "\n\n"
                + f"{MUSTARD}We value your feedback! Please email suggestions or issues to support@zeromarks.net .\nOur support team is here to help with any questions, concerns or suggestions.{RESET}\n\n"
                + f"{DBLUE}\n\n                                            *** {MUSTARD}PAGE 5{DBLUE} ***{RESET}"
            ),
        },
        "6": {
            "title": "Shortcut & Additional Information*",
            "color": FORANGE,
            "content": (
                f"{RESET}\nEnhance your productivity by using these handy shortcut keys in the terminal{RESET}\n\n"
                + f"Staff favorites: ⭐\n\n"
                + f"{FORANGE}----- 🚀 Shortcut Keys -----{RESET}\n\n"
                + "\n".join(
                    [
                        f"{FORANGE}Terminal Window Shortcuts: ",
                        f"{FORANGE}Command + T{RESET}: ⭐ Open a new a new tab.",
                        f"{FORANGE}Command + W{RESET}: Close the current window or tab.",
                        f"{FORANGE}Command + N{RESET}: ⭐ Open a new terminal window.",
                        f"{FORANGE}Command + Q{RESET}: ⭐ Quit the application safely.",
                        f"{FORANGE}Command + D{RESET}: Duplicate a selected line or block of text.",
                        f"{FORANGE}Ctrl + C{RESET}: ⭐ CANCELS SCRIPT WITHOUT SAVING",
                        f"{FORANGE}Command + Option + Esc{RESET}: Force quit an application with task manager.",
                        f"{FORANGE}Command + SHIFT + 4{RESET}: ⭐ Screenshot(on mac)",
                        f"{FORANGE}Command + Tab{RESET}: Switch between open applications.(on mac)",
                        f"\n{FORANGE}Copy / Print Shortcuts:",
                        f"{FORANGE}Command + A{RESET}: Select all text.",
                        f"{FORANGE}Command + C{RESET}: ⭐ Copy selected / highlighted text to the clipboard.",
                        f"{FORANGE}Command + V{RESET}: ⭐ Paste text from the clipboard.",
                        f"{FORANGE}Command + P{RESET}: Print Page of current displayed text in the termianl",
                        f"{FORANGE}Command + S{RESET}: Create a new file of current displayed text in the terminal.",
                        f"\n{FORANGE}Input Bar Shortcuts:",
                        f"{FORANGE}Ctrl + S{RESET}: ⭐ Takes you to the current input.",
                        f"{FORANGE}Command + F{RESET}: ⭐ Open the search function to find a specific item or text.",
                        f"{FORANGE}Ctrl + U{RESET}: Delete / Clear ALL text from the input bar.",
                        f"{FORANGE}Ctrl + W{RESET}: ⭐ Delete the word before the cursor.",
                    ]
                )
                + "\n\n"
                + f"{FORANGE}----- 💡 General Tips -----{RESET}\n\n"
                + f"{RESET}Here are some essential tips to keep your data secure and improve your experience:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{FORANGE}Use Strong Passwords{RESET}: Ensure all your passwords are strong, unique, and regularly updated. Use a mix of letters, numbers, and special characters.",
                        f"{FORANGE}Keep Software Updated{RESET}: Regularly update the application to benefit from the latest features and security patches. Check for updates in the settings menu.",
                        f"{FORANGE}Backup Your Data{RESET}: Regularly backup your data to prevent data loss. Use both cloud storage and physical devices for redundancy.",
                        f"{FORANGE}Log Out Regularly{RESET}: Always log out of the application when not in use, especially on shared or public devices.",
                    ]
                )
                + "\n\n"
                + f"{FORANGE}----- Common Commands -----{RESET}\n\n"
                + f"{RESET}(x) Back{RESET}: Always takes you back to the previous menu.\n"
                + f"{FORANGE}Press 'enter' to return to the menu{RESET}: After viewing detailed information, press 'enter' to return to the main menu.\n\n"
                + f"{FORANGE}----- Icons -----{RESET}\n\n"
                + f"{RESET}Icons (e.g., 👤, 🗂️, 💻) help you quickly identify the purpose of each menu option, making navigation intuitive and efficient.{RESET}\n\n"
                + f"{FORANGE}----- Color Coding -----{RESET}\n\n"
                + f"{RESET}Different colors are used to distinguish between menu options and sections, enhancing readability and ease of use:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}• {CYAN}CYAN{RESET}: General information and tips.",
                        f"{GOLD}• {RED}RED{RESET}: Alerts and important notices.",
                        f"{GOLD}• {PURPLE}PURPLE{RESET}: Navigation and action options.",
                    ]
                )
                + "\n\n"
                + f"{FORANGE}Stay informed and vigilant to ensure your data remains secure and your experience smooth.{RESET}\n\n"
                + f"{DBLUE}\n\n                                            *** {FORANGE}PAGE 6{DBLUE} ***{RESET}"
            ),
        },
        "7": {
            "title": "Acknowledgements & Contributions*",
            "color": L_CYAN,
            "content": (
                f"\n\n"
                + f"{RESET}We think it’s important to do this because your feedback ensures that we’re creating products and services that truly resonate with our users. Together, we can make ZEROMARKSLLC not only a tool for anonymity and security but also a platform that enhances your digital life in ways we’ve only just begun to imagine.\n\nThank you for being part of the ZEROMARKSLLC journey. We can’t wait to hear your ideas and work together to make them a reality!\n\nStay secure, \nThe ZeroMarks Team{RESET}\n\n"
                + f"{L_CYAN}We extend our heartfelt thanks to the creators of the following libraries and resources that made this application possible:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}• {L_CYAN}[ipify](https://github.com/rdegges/ipify-api){RESET}: For providing a simple and efficient way to get the public IP address of our system.",
                    ]
                )
                + "\n\n"
                + f"{L_CYAN}We also acknowledge the support from our user community and contributors who continually inspire us to improve and innovate.{RESET}\n\n"
                + f"{L_CYAN}----- 🛠️  How You Can Contribute -----{RESET}\n\n"
                + f"{L_CYAN}We welcome contributions from the community. Here's how you can get involved:{RESET}\n\n"
                + "\n".join(
                    [
                        f"{GOLD}• {L_CYAN}Report Issues{RESET}: Found a bug? Report it on our [issue tracker](https://example.com/issues).",
                        f"{GOLD}• {L_CYAN}Feature Requests{RESET}: Have a suggestion for a new feature? Submit it through our [feature request form](https://example.com/feature-request).",
                        f"{GOLD}• {L_CYAN}Community Support{RESET}: Join our [community forum](https://example.com/forum) to help other users and share your ideas.",
                    ]
                )
                + "\n\n"
                + f"{DBLUE}\n\n                                            *** {L_CYAN}PAGE 7{DBLUE} ***{RESET}"
            ),
        },
    }

    def print_section(section):
        """Print a single section of the user guide"""

        print(
            f"{DBLUE}{'*' * 5} {section['color']}{section['title']} {DBLUE}{'*' * 5}{RESET}"
        )
        print(section["content"])
        print("\n")

    def display_menu():
        """Display the table of contents menu"""
        displayHeader(f"{CYAN}📘 USER GUIDE{RESET}")
        print(f"{GOLD}Full Screen is recommended {RESET}\n")
        print(f"{GOLD}Table of Contents: {RESET}\n")
        for key, section in sections.items():
            print(f"{CYAN}p. {key} {GOLD}| {section['color']}{section['title']}{RESET}")

    try:
        # Main user guide function with timeout handling
        timedOut = False
        while not timedOut:
            display_menu()
            choice = timeoutInput(
                f"\n{GOLD}Enter the index number of the section you want to explore (press 'enter' to display all, type '.c' to cancel): {RESET}"
            )
            
            # Handle timeout
            if choice == timeoutGlobalCode:
                return True
                
            # Handle cancel
            if choice == ".c":
                print(f"{RED}Operation canceled.{RESET}")
                return False
                
            # Display all sections
            if choice == "":
                clear_screen()
                displayHeader(f"{CYAN}📘 USER GUIDE{RESET}")
                for section in sections.values():
                    print_section(section)
                    
            # Display specific section
            elif choice in sections:
                clear_screen()
                displayHeader(f"{CYAN}📘 USER GUIDE{RESET}")
                print_section(sections[choice])
                
            # Handle invalid input
            else:
                print(f"{RED}Invalid choice. Please try again.{RESET}")

            # Ask user to continue or return
            userContinue = timeoutInput(
                f"{GOLD}\nPress 'enter' to return to menu or type 'r' to retry...{RESET}"
            )
            
            # Handle timeout
            if userContinue == timeoutGlobalCode:
                return True
                
            # Return to main menu
            if userContinue.lower() != "r":
                return False
                
            # Clear screen for next iteration
            clear_screen()
            
    except Exception as e:
        # Handle any unexpected errors
        print(f"{RED}** ALERT: Error displaying user guide **{RESET}")
        return False
    finally:
        # Clean up sensitive data
        if 'hashed_pass' in locals(): del hashed_pass
        
    return False

def changeMasterPassword(hashed_pass, db):
    """Change the master password with enhanced security"""
    try:
        # Get current config values
        config = vault.manage_config(hashed_pass )
        #temparily load UI config to get current timeout
        ui_config = load_ui_config()
        current_timeout = ui_config["current_timeout"]
        #current_timeout = config["timeout_value"]
        current_salt = base64.b64decode(config["salt"])
        clear_screen()
        displayHeader(f"{CYAN}🔑 CHANGE BUNKER ACCESS PASSWORD{RESET}")
        print(
            f"⚠️ {RESET} ** BEWARE: Once changed, you'll be logged out and will need to log in again to access the bunker. ** ⚠️{RESET}"
        )

        while True:
            show_password_choice = input(
                f"{GOLD}\nDo you want to show your password while you type? (y/n) or (.c) Back: {RESET}"
            ).lower()

            if show_password_choice == "y":
                clear_screen()
                displayHeader(f"{CYAN}🔑 CHANGE BUNKER ACCESS PASSWORD{RESET}")
                print(f"{RESET}⚠️  ** Your password will be shown as you type. ** ⚠️{RESET}")
                password_provided = timeoutInput(
                    f"\n{GOLD}Enter your new master password (minimum 8 characters, type and submit (.c) to cancel): {RESET}"
                )
            elif show_password_choice == "n":
                clear_screen()
                displayHeader(f"{CYAN}🔑 CHANGE BUNKER ACCESS PASSWORD{RESET}")
                print(f"{RESET}⚠️  ** Your password will be hidden as you type. ** ⚠️{RESET}")
                password_provided = timeout_getpass(
                    f"\n{GOLD}Enter your new master password (minimum 8 characters, type and submit (.c) to cancel): {RESET}",
                    current_timeout
                )
            elif show_password_choice == ".c":
                print(f"{GREEN}** SUCCESS: Cancelling successful... **{RESET}")
                return False
            else:
                print(f"{RED} ** ALERT: Invalid input. Please enter y, n, or .c. **{RESET}")
                continue

            if password_provided == ".c" or password_provided == timeoutGlobalCode:
                return False

            if len(password_provided) < 8:
                print(f"{RED} ** ALERT: Password must be at least 8 characters long. **{RESET}")
                continue

            if not password_provided.strip():
                print(f"{RED} ** ALERT: Invalid input. Please enter a valid password. **{RESET}")
                continue

            try:
                # Derive key and check if it matches existing password
                derived_key = vault.derive_key_hybrid(password_provided, current_salt)
                if derived_key == hashed_pass:
                    print(f"{RED}\n ** ALERT: New password cannot be the same as the current password. **{RESET}")
                    while True:
                        retry_choice = timeoutInput(
                            f"{GOLD}\nPress 'enter' to continue or type 'r' to retry... {RESET}"
                        ).lower()
                        if retry_choice == "r":
                            return changeMasterPassword(hashed_pass, db)
                        elif retry_choice == "":
                            return False
                        else:
                            print(f"{RED} ** ALERT: Invalid input. Please press 'enter' to continue or type 'r' to retry. **{RESET}")
                    continue
            except Exception as e:
                print(f"{RED} ** ALERT: Error checking password: {str(e)} **{RESET}")
                return False

            # Generate new salt and key
            try:
            # Generate new salt and key
                new_salt = os.urandom(SALT_SIZE)
                new_derived_key = vault.derive_key_hybrid(password_provided, new_salt, password_provided)
                #tempar
                #new_config = {
                #    "salt": base64.b64encode(new_salt).decode(),
                #    "verifier": base64.b64encode(vault.encrypt_data(b"BUNKER_VERIFIED", new_derived_key)).decode(),
                    #"timeout_value": current_timeout,
                    #"max_attempts": config["max_attempts"],
                    #"settings": config["settings"],
                    #"attempts": 0,
                #    "last_exit": str(datetime.datetime.now().timestamp()),
                #    "timestamp": str(time.time())
                #}
                config["salt"] = base64.b64encode(new_salt).decode()
                config["verifier"] = base64.b64encode(vault.encrypt_data(b"BUNKER_VERIFIED", new_derived_key)).decode()
                config["last_exit"] = str(datetime.datetime.now().timestamp())
                config["timestamp"] = str(time.time())

                
                # Save new salt
                save_salt(new_salt)

                # Encrypt and save config with new key
                encrypted_config = vault.encrypt_data(json.dumps(config).encode(), new_derived_key)
                with open("bunker.cfg", "wb") as f:
                    f.write(encrypted_config)

                # Update and save UI config
                ui_config = {
                    "attempts": 0,
                    "max_attempts": config.get("max_attempts", 3),
                    "disable_ipv4": config.get("settings", {}).get("disable_ipv4", True),
                    "current_timeout": config.get("timeout_value", 60)
                }
                save_ui_config(ui_config)

                # Save database with new key if needed
                saveDatabase(db, new_derived_key)

                print(f"{GREEN}\n ** SUCCESS: Master password changed successfully! Log in again to access the note manager. **{RESET}")
                timeoutInput(f"\n{GOLD}Press 'enter' to logout...{RESET}")
                clear_screen()
                sys.exit()

            except KeyError as ke:
                print(f"{RED} ** ALERT: Could not change master password (Error code: 01). KeyError: {ke} **{RESET}")
                return False
            except Exception as e:
                print(f"{RED} ** ALERT: Could not change master password (Error code: 03). Error: {e} **{RESET}")
                return False
            finally:
                if 'password_provided' in locals(): del password_provided
                if 'new_derived_key' in locals(): del new_derived_key
                if 'hashed_pass' in locals(): del hashed_pass
                vault.secure_wipe()

    except Exception as e:
        print(f"{RED} ** ALERT: An error occurred: {str(e)} **{RESET}")
        return False

    
def changeAutoLogoutTimer(hashed_pass, db):
    """Change auto-logout timer with enhanced security"""
    RECOMMENDED_TIMEOUT = 60
    min_timeout = 10
    max_timeout = 3600

    try:
        while True:
            clear_screen()
            displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")

            # Load current timeout value with enhanced security
            try:
                #temp
                #config = vault.manage_config(hashed_pass)
                #current_timeout = config.get("timeout_value", 60)
        
                # Load current timeout value from ui_config
                ui_config = load_ui_config()
                current_timeout = ui_config.get("current_timeout", 60)
            
                if current_timeout is None or current_timeout == 0:
                    current_timeout_display = f"{GOLD}0{RESET} seconds {GOLD}|{RESET} ⚠️  ** BEWARE: Auto-logout is currently {RED}OFF.{RESET} **  ⚠️"
                else:
                    current_timeout_display = f"{GOLD}{current_timeout}{RESET} seconds"

                print(
                    f"{LPURPLE}🕒 Current auto-logout timer value:{RESET} {current_timeout_display}"
                )
                print(f"{DBLUE}⏳ Minimum timeout value:{GOLD} {min_timeout} {RESET}seconds")
                print(f"{DBLUE}⌛ Maximum timeout value:{GOLD} {max_timeout} {RESET}seconds")
                print(f"{DBLUE}⌛ Recommended timeout value:{GOLD} {RECOMMENDED_TIMEOUT} {RESET}seconds")

                if current_timeout != 0:
                    print(
                        f"{GOLD}Enter '0' to turn off auto-logout but not recommended.{RESET}"
                    )

                # Get new timeout value with timeout protection
                new_timeout = timeoutInput(
                    f"\n{GOLD}What would you like your new auto-logout timer to be? Enter the amount of seconds (press enter for recommended {RECOMMENDED_TIMEOUT} seconds, type (.c) to cancel): {RESET}"
                )

                # Handle cancel and timeout
                if new_timeout == ".c":
                    print(f"{CYAN} ** ALERT: Operation canceled. **{RESET}")
                    return False
                    
                if new_timeout == timeoutGlobalCode:
                    return True
                    
                # Handle empty input (use recommended value)
                if new_timeout.strip() == "":
                    new_timeout_value = RECOMMENDED_TIMEOUT
                    print(f"{CYAN}Using recommended timeout value: {GOLD}{RECOMMENDED_TIMEOUT}{RESET} seconds{RESET}")
                else:
                    try:
                        new_timeout_value = int(new_timeout)
                    except ValueError:
                        clear_screen()
                        displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                        print(f"{RED} ** Invalid input. Please enter a valid number. **{RESET}")
                        
                        userContinue = timeoutInput(
                            f"{GOLD}\nPress 'enter' to return to menu or type 'r' to retry...{RESET}"
                        )
                        if userContinue == timeoutGlobalCode:
                            return True
                        if userContinue.lower() == "r":
                            continue
                        else:
                            return False

                # Validate new timeout value
                if new_timeout_value < 0:
                    clear_screen()
                    displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                    print(f"{RED} ** Timeout value cannot be negative. **{RESET}")
                    
                elif new_timeout_value == 0:
                    # Confirm disabling auto-logout
                    clear_screen()
                    displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                    confirm = input(f"{RED}** WARNING: Are you sure you want to disable auto-logout? (y/n): {RESET}").lower()
                    
                    if confirm == 'y':
                        # Save with enhanced security
                        ui_config["current_timeout"] = new_timeout_value
                        save_ui_config(ui_config)
                        #temp
                        #vault.manage_config(key=hashed_pass, timeout_value=new_timeout_value)
                        print(
                            f"{GREEN}** SUCCESS: Auto-logout turned off. Timeout value set to 0 and saved. **{RESET}"
                        )

                        userContinue = timeoutInput(
                            f"{GOLD}\nPress 'enter' to return to menu or type 'r' to retry...{RESET}"
                        )
                        if userContinue == timeoutGlobalCode:
                            return True
                        if userContinue.lower() == "r":
                            continue
                        else:
                            return False
                    else:
                        print(f"{CYAN} ** Operation canceled. **{RESET}")
                        continue
                        
                elif new_timeout_value < min_timeout:
                    clear_screen()
                    displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                    print(
                        f"{RED} ** Timeout value must be at least {min_timeout} seconds. **{RESET}"
                    )
                    
                elif new_timeout_value > max_timeout:
                    clear_screen()
                    displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                    print(
                        f"{RED} ** Maximum timeout value is {max_timeout} seconds. **{RESET}"
                    )
                    
                else:
                    # Valid timeout value - save with enhanced security
                    clear_screen()
                    displayHeader(f"{CYAN}⏲️ CHANGE AUTO-LOGOUT TIMER{RESET}")
                    ui_config["current_timeout"] = new_timeout_value
                    save_ui_config(ui_config)
                    #temp
                    #vault.manage_config(key=hashed_pass, timeout_value=new_timeout_value)
                    print(
                        f"{GREEN} ** SUCCESS: Auto-logout timer successfully set to {new_timeout_value} seconds. **{RESET}"
                    )

                    userContinue = timeoutInput(
                        f"{GOLD}\nPress 'enter' to return to menu or type 'r' to retry...{RESET}"
                    )
                    if userContinue == timeoutGlobalCode:
                        return True
                    if userContinue.lower() == "r":
                        continue
                    else:
                        return False

                # Ask user to continue or return
                userContinue = timeoutInput(
                    f"{GOLD}\nPress 'enter' to return to menu or type 'r' to retry...{RESET}"
                )
                if userContinue == timeoutGlobalCode:
                    return True
                if userContinue.lower() == "r":
                    continue
                else:
                    return False
                    
            except Exception as e:
                # Handle any errors with enhanced security
                print(f"{RED} ** ALERT: Error changing timeout value: {str(e)} **{RESET}")
                return False
    except Exception as e:
        print(f"{RED} ** ALERT: Failed to manage timeout settings: {str(e)} **{RESET}")
        return False
    finally:
        # Clean up sensitive data
        if 'hashed_pass' in locals(): del hashed_pass
        vault.secure_wipe()

#debug fuction not connected not needed but good to have to clean db with out restarting setup
def cleanupDatabase(hashed_pass, db):
    """
    Remove invalid entries from the database with enhanced security.
    Handles both profile entries and note entries.
    """
    invalid_entries = []
    cleaned = False
    profile_count = 0
    note_count = 0

    for entry_id, info in db.items():
        if not isinstance(info, dict):
            # Not a dictionary, definitely invalid
            invalid_entries.append(entry_id)
            cleaned = True
            continue
            
        # Check if this is a profile entry
        if "password" in info and "domain" in info:
            # This should be a profile entry
            if (not isinstance(info.get("domain"), (str, bytes)) or
                not isinstance(info.get("password"), (str, bytes)) or
                "content" in info or  # Profiles shouldn't have content
                "tags" in info):      # Profiles shouldn't have tags
                invalid_entries.append(entry_id)
                cleaned = True
                profile_count += 1
                
        # Check if this is a note entry
        elif "content" in info and "title" in info:
            # This should be a note entry
            if (not isinstance(info.get("title"), (str, bytes)) or
                not isinstance(info.get("content"), (str, bytes)) or
                "password" in info or  # Notes shouldn't have password
                "domain" in info):     # Notes shouldn't have domain
                invalid_entries.append(entry_id)
                cleaned = True
                note_count += 1
                
        else:
            # Neither a valid profile nor a valid note
            invalid_entries.append(entry_id)
            cleaned = True

    # Remove invalid entries
    for entry_id in invalid_entries:
        del db[entry_id]

    # Save cleaned database
    if cleaned:
        try:
            # Use enhanced security for encryption
            encrypted_db = vault.encrypt_data(json.dumps(db).encode(), hashed_pass)
            
            # Write directly as bytes to ensure consistent format
            with open("Bunker.mmf", "wb") as f:
                f.write(encrypted_db)
                
            print(f"\n{GREEN}** Database cleaned up: Removed {len(invalid_entries)} invalid entries **{RESET}")
            if profile_count > 0:
                print(f"{GREEN}** {profile_count} invalid profile entries removed **{RESET}")
            if note_count > 0:
                print(f"{GREEN}** {note_count} invalid note entries removed **{RESET}")
        except Exception as e:
            print(f"{RED} ** ALERT: Failed to update database. Error: {str(e)} **{RESET}")
            return None

    return db
