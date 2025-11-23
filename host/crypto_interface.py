"""
Crypto Interface - Abstract base for cryptographic implementations

This defines the interface that all crypto implementations must follow.
Allows swapping between different backends (naive file-based, TPM2, HSM, etc.)
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class CryptoInterface(ABC):
    """
    Abstract interface for cryptographic operations in MASTR protocol.
    
    Implementations must provide:
    - Key management (loading/generating permanent keys)
    - ECDH ephemeral key generation
    - ECDSA signing and verification
    - Session key derivation (HKDF)
    - AES-GCM encryption/decryption
    """
    

    def __init__(self) -> None:
        """Initialize crypto implementation"""
        self.session_key: Optional[bytes] = None
        self._should_encrypt: bool = False
    
    # ========================================================================
    # Key Management
    # ========================================================================
    
    @abstractmethod
    def load_permanent_keys(self) -> bool:
        """
        Load host's permanent private key and token's permanent public key.
        
        Returns:
            True if keys loaded successfully, False otherwise
        """
        pass
    
    @abstractmethod
    def generate_permanent_keypair(self) -> bool:
        """
        Generate and save new permanent keypair for host.
        
        Returns:
            True if generation successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_host_permanent_pubkey(self) -> Optional[bytes]:
        """
        Get host's permanent public key (raw 64-byte format).
        
        Returns:
            64-byte public key or None if not available
        """
        pass
    
    @abstractmethod
    def set_token_permanent_pubkey(self, pubkey: bytes) -> bool:
        """
        Store token's permanent public key.
        
        Args:
            pubkey: 64-byte raw public key
            
        Returns:
            True if stored successfully
        """
        pass
    
    # ========================================================================
    # ECDH Operations
    # ========================================================================
    
    @abstractmethod
    def generate_ephemeral_keypair(self) -> Tuple[bytes, object]:
        """
        Generate ephemeral P-256 keypair for ECDH.
        
        Returns:
            Tuple of (public_key_bytes, private_key_object)
            public_key_bytes: 64-byte raw public key (X||Y)
            private_key_object: Implementation-specific private key object
        """
        pass
    
    @abstractmethod
    def sign_with_permanent_key(self, message: bytes) -> Optional[bytes]:
        """
        Sign message with host's permanent private key.
        
        Args:
            message: Message to sign
            
        Returns:
            64-byte raw signature (R||S) or None on error
        """
        pass
    
    @abstractmethod
    def verify_signature(self, message: bytes, signature: bytes, pubkey: bytes) -> bool:
        """
        Verify ECDSA signature using provided public key.
        
        Args:
            message: Message that was signed
            signature: 64-byte raw signature (R||S)
            pubkey: 64-byte raw public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def compute_shared_secret(self, ephemeral_privkey: object, peer_pubkey: bytes) -> Optional[bytes]:
        """
        Compute ECDH shared secret.
        
        Args:
            ephemeral_privkey: Host's ephemeral private key object
            peer_pubkey: Peer's 64-byte raw public key
            
        Returns:
            32-byte shared secret or None on error
        """
        pass
    
    @abstractmethod
    def derive_session_key(self, shared_secret: bytes) -> Optional[bytes]:
        """
        Derive AES-128 session key from ECDH shared secret using HKDF-SHA256.
        
        Args:
            shared_secret: 32-byte ECDH shared secret
            
        Returns:
            16-byte AES session key or None on error
        """
        pass
    
    # ========================================================================
    # Session Key Management
    # ========================================================================
    
    def set_session_key(self, key: bytes) -> None:
        """
        Set the session key (from ECDH derivation).
        
        Args:
            key: 16-byte AES-128 session key
        """
        if len(key) != 16:
            raise ValueError(f"Session key must be 16 bytes, got {len(key)}")
        self.session_key = key
    
    def get_session_key(self) -> Optional[bytes]:
        """
        Get current session key.
        
        Returns:
            16-byte session key or None if not set
        """
        return self.session_key
    
    # ========================================================================
    # Protocol State
    # ========================================================================
    
    def set_encryption_enabled(self, enabled: bool) -> None:
        """
        Enable or disable encryption.
        Called by protocol layer when state changes.
        
        Args:
            enabled: True to enable encryption, False to disable
        """
        self._should_encrypt = enabled
    
    def should_encrypt(self) -> bool:
        """
        Determine if encryption should be used.
        
        Returns:
            True if encryption is enabled
        """
        return self._should_encrypt
    
    # ========================================================================
    # Encryption/Decryption
    # ========================================================================
    
    @abstractmethod
    def encrypt_payload(self, payload: bytes) -> bytes:
        """
        Encrypt payload using AES-128-GCM if required by protocol state.
        
        Args:
            payload: Plaintext data
            
        Returns:
            Encrypted data or original if encryption not needed
        """
        pass
    
    @abstractmethod
    def decrypt_payload(self, payload: bytes) -> bytes:
        """
        Decrypt payload using AES-128-GCM if required by protocol state.
        
        Args:
            payload: Encrypted data (or plaintext if state < 0x22)
            
        Returns:
            Decrypted data or original if decryption not needed
            
        Raises:
            ValueError: If decryption fails
        """
        pass
