"""
Key Storage Interface - Abstract base for session key storage

This defines the interface for storing and retrieving AES-128 session keys
between the initramfs phase and runtime phase.

Implementations:
- KeyringStorage: Linux kernel keyring (ephemeral, fast)
- TPM2Storage: TPM2 NVRAM (persistent, hardware-backed)
"""

from abc import ABC, abstractmethod
from typing import Optional


class KeyStorageInterface(ABC):
    """
    Abstract interface for secure session key storage.
    
    The session key must be stored during initramfs phase (after BOOT_OK)
    and retrieved during runtime phase (by heartbeat daemon).
    """
    
    @abstractmethod
    def store_session_key(self, key: bytes, key_id: str = "mastr-session") -> bool:
        """
        Store AES-128 session key securely.
        
        Args:
            key: 16-byte AES session key
            key_id: Identifier for the key
            
        Returns:
            True if stored successfully, False otherwise
            
        Raises:
            ValueError: If key is not exactly 16 bytes
        """
        pass
    
    @abstractmethod
    def retrieve_session_key(self, key_id: str = "mastr-session") -> Optional[bytes]:
        """
        Retrieve stored session key.
        
        Args:
            key_id: Identifier for the key
            
        Returns:
            16-byte session key or None if not found
        """
        pass
    
    @abstractmethod
    def delete_session_key(self, key_id: str = "mastr-session") -> bool:
        """
        Delete stored session key.
        
        Args:
            key_id: Identifier for the key
            
        Returns:
            True if deleted successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this storage backend is available on the system.
        
        Returns:
            True if backend can be used, False otherwise
        """
        pass
    
    def validate_key(self, key: bytes) -> None:
        """
        Validate that key is correct length.
        
        Args:
            key: Key to validate
            
        Raises:
            ValueError: If key is not exactly 16 bytes
        """
        if len(key) != 16:
            raise ValueError(f"Session key must be 16 bytes, got {len(key)}")