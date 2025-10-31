"""
Kernel Keyring Storage Implementation

Stores AES-128 session keys in the Linux kernel keyring.
Uses the session keyring (@s) by default for ephemeral storage.

Requirements:
- Linux kernel with keyring support (CONFIG_KEYS=y)
- keyctl utility (from keyutils package)
"""

import subprocess
import re
from typing import Optional

from .key_storage_interface import KeyStorageInterface
from .logger import Logger


class KeyringStorage(KeyStorageInterface):
    """
    Linux kernel keyring implementation for session key storage.
    
    Uses kernel keyring API via keyctl command-line tool.
    Keys are stored in the session keyring (@s) by default.
    """
    
    def __init__(self, keyring_type: str = "@s"):
        """
        Initialize keyring storage.
        
        Args:
            keyring_type: Keyring to use:
                - "@s" = session keyring (cleared on logout, default)
                - "@u" = user keyring (persistent per user)
                - "@us" = user session keyring
        """
        self.keyring_type = keyring_type
    
    def store_session_key(self, key: bytes, key_id: str = "mastr-session") -> bool:
        """
        Store session key in kernel keyring.
        
        Uses: keyctl padd user <key_id> <keyring>
        """
        self.validate_key(key)
        
        try:
            # Use keyctl padd to add key to keyring
            # Format: keyctl padd <type> <description> <keyring>
            # Input is read from stdin
            cmd = ['keyctl', 'padd', 'user', key_id, self.keyring_type]
            
            result = subprocess.run(
                cmd,
                input=key,
                capture_output=True,
                timeout=5.0
            )
            
            if result.returncode == 0:
                # keyctl padd outputs the key ID
                key_serial = result.stdout.decode().strip()
                Logger.success(f"Stored session key in kernel keyring (ID: {key_serial})")
                return True
            else:
                error = result.stderr.decode().strip()
                Logger.error(f"Failed to store in keyring: {error}")
                return False
                
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while storing key in keyring")
            return False
        except FileNotFoundError:
            Logger.error("keyctl command not found - install keyutils package")
            return False
        except Exception as e:
            Logger.error(f"Error storing key in keyring: {e}")
            return False
    
    def retrieve_session_key(self, key_id: str = "mastr-session") -> Optional[bytes]:
        """
        Retrieve session key from kernel keyring.
        
        Uses: keyctl search + keyctl pipe
        """
        try:
            # Step 1: Search for key by description
            search_cmd = ['keyctl', 'search', self.keyring_type, 'user', key_id]
            
            search_result = subprocess.run(
                search_cmd,
                capture_output=True,
                timeout=5.0
            )
            
            if search_result.returncode != 0:
                Logger.warning(f"Key '{key_id}' not found in keyring")
                return None
            
            # Get key serial number
            key_serial = search_result.stdout.decode().strip()
            
            # Step 2: Read key data using keyctl pipe
            pipe_cmd = ['keyctl', 'pipe', key_serial]
            
            pipe_result = subprocess.run(
                pipe_cmd,
                capture_output=True,
                timeout=5.0
            )
            
            if pipe_result.returncode != 0:
                error = pipe_result.stderr.decode().strip()
                Logger.error(f"Failed to read key from keyring: {error}")
                return None
            
            key_data = pipe_result.stdout
            
            # Validate key length
            if len(key_data) != 16:
                Logger.error(f"Retrieved key has invalid length: {len(key_data)} (expected 16)")
                return None
            
            Logger.success(f"Retrieved session key from kernel keyring (ID: {key_serial})")
            return key_data
            
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while retrieving key from keyring")
            return None
        except FileNotFoundError:
            Logger.error("keyctl command not found - install keyutils package")
            return None
        except Exception as e:
            Logger.error(f"Error retrieving key from keyring: {e}")
            return None
    
    def delete_session_key(self, key_id: str = "mastr-session") -> bool:
        """
        Delete session key from kernel keyring.
        
        Uses: keyctl revoke
        """
        try:
            # Search for key
            search_cmd = ['keyctl', 'search', self.keyring_type, 'user', key_id]
            
            search_result = subprocess.run(
                search_cmd,
                capture_output=True,
                timeout=5.0
            )
            
            if search_result.returncode != 0:
                Logger.warning(f"Key '{key_id}' not found in keyring (already deleted?)")
                return True
            
            key_serial = search_result.stdout.decode().strip()
            
            # Revoke the key
            revoke_cmd = ['keyctl', 'revoke', key_serial]
            
            revoke_result = subprocess.run(
                revoke_cmd,
                capture_output=True,
                timeout=5.0
            )
            
            if revoke_result.returncode == 0:
                Logger.success(f"Deleted session key from kernel keyring (ID: {key_serial})")
                return True
            else:
                error = revoke_result.stderr.decode().strip()
                Logger.error(f"Failed to delete key from keyring: {error}")
                return False
                
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while deleting key from keyring")
            return False
        except FileNotFoundError:
            Logger.error("keyctl command not found - install keyutils package")
            return False
        except Exception as e:
            Logger.error(f"Error deleting key from keyring: {e}")
            return False
    
    def is_available(self) -> bool:
        """
        Check if kernel keyring support is available.
        
        Tests by checking if keyctl command exists and keyring is accessible.
        """
        try:
            # Try to list the keyring
            cmd = ['keyctl', 'list', self.keyring_type]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=2.0
            )
            
            # If we can list the keyring, it's available
            return result.returncode == 0
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        except Exception:
            return False