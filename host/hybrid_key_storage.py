"""
Hybrid Key Storage Manager

Combines kernel keyring and TPM2 storage with automatic fallback.
Tries keyring first (fast), falls back to TPM2 if unavailable.
Stores in both for redundancy when possible.
"""

from typing import Optional

from .key_storage_interface import KeyStorageInterface
from .keyring_storage import KeyringStorage
from .tpm2_storage import TPM2Storage
from .logger import Logger


class HybridKeyStorage(KeyStorageInterface):
    """
    Hybrid key storage with automatic fallback.
    
    Strategy:
    1. Primary: Kernel keyring (fast, ephemeral)
    2. Fallback/Backup: TPM2 NVRAM (persistent, hardware-backed)
    
    Storage: Tries both if available for redundancy
    Retrieval: Tries keyring first, falls back to TPM2
    """
    
    def __init__(self):
        """Initialize both storage backends."""
        self.keyring = KeyringStorage()
        self.tpm2 = TPM2Storage()
        
        # Check availability at init
        self.keyring_available = self.keyring.is_available()
        self.tpm2_available = self.tpm2.is_available()
        
        if self.keyring_available:
            Logger.info("Kernel keyring storage available")
        else:
            Logger.warning("Kernel keyring storage not available")
        
        if self.tpm2_available:
            Logger.info("TPM2 NVRAM storage available")
        else:
            Logger.warning("TPM2 NVRAM storage not available")
        
        if not self.keyring_available and not self.tpm2_available:
            Logger.error("No key storage backends available!")
    
    def store_session_key(self, key: bytes, key_id: str = "mastr-session") -> bool:
        """
        Store session key in available backends.
        
        Tries to store in both keyring and TPM2 for redundancy.
        Returns True if at least one succeeds.
        """
        self.validate_key(key)
        
        success_keyring = False
        success_tpm2 = False
        
        # Try keyring first (primary)
        if self.keyring_available:
            Logger.substep("Storing in kernel keyring...")
            success_keyring = self.keyring.store_session_key(key, key_id)
        
        # Also try TPM2 for backup/persistence
        if self.tpm2_available:
            Logger.substep("Storing in TPM2 NVRAM (backup)...")
            success_tpm2 = self.tpm2.store_session_key(key, key_id)
        
        # Success if at least one backend worked
        if success_keyring or success_tpm2:
            if success_keyring and success_tpm2:
                Logger.success("Session key stored in both keyring and TPM2")
            elif success_keyring:
                Logger.success("Session key stored in kernel keyring")
            else:
                Logger.success("Session key stored in TPM2 NVRAM")
            return True
        else:
            Logger.error("Failed to store session key in any backend")
            return False
    
    def retrieve_session_key(self, key_id: str = "mastr-session") -> Optional[bytes]:
        """
        Retrieve session key with automatic fallback.
        
        Tries keyring first (faster), falls back to TPM2 if not found.
        """
        # Try keyring first (faster, primary)
        if self.keyring_available:
            Logger.substep("Trying kernel keyring...")
            key = self.keyring.retrieve_session_key(key_id)
            if key is not None:
                Logger.success("Retrieved session key from kernel keyring")
                return key
        
        # Fallback to TPM2
        if self.tpm2_available:
            Logger.substep("Trying TPM2 NVRAM...")
            key = self.tpm2.retrieve_session_key(key_id)
            if key is not None:
                Logger.success("Retrieved session key from TPM2 NVRAM (keyring unavailable)")
                return key
        
        # Failed to retrieve from any source
        Logger.error("Failed to retrieve session key from any backend")
        return None
    
    def delete_session_key(self, key_id: str = "mastr-session") -> bool:
        """
        Delete session key from all backends.
        
        Returns True if deleted from at least one backend.
        """
        success_keyring = False
        success_tpm2 = False
        
        # Delete from keyring
        if self.keyring_available:
            Logger.substep("Deleting from kernel keyring...")
            success_keyring = self.keyring.delete_session_key(key_id)
        
        # Delete from TPM2
        if self.tpm2_available:
            Logger.substep("Deleting from TPM2 NVRAM...")
            success_tpm2 = self.tpm2.delete_session_key(key_id)
        
        # Success if at least one deletion worked
        if success_keyring or success_tpm2:
            Logger.success("Session key deleted")
            return True
        else:
            Logger.warning("Session key not found in any backend (already deleted?)")
            return True  # Not an error if already deleted
    
    def is_available(self) -> bool:
        """
        Check if at least one backend is available.
        
        Returns True if either keyring or TPM2 is available.
        """
        return self.keyring_available or self.tpm2_available