"""
Cryptographic functions for MASTR protocol - AES-GCM encryption/decryption
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# AES-128 key size
AES_KEY_SIZE = 16

# GCM IV/Nonce size (12 bytes recommended for GCM)
GCM_IV_SIZE = 12

# GCM Authentication Tag size (16 bytes)
GCM_TAG_SIZE = 16

# Total encryption overhead
ENCRYPTION_OVERHEAD = GCM_IV_SIZE + GCM_TAG_SIZE


# ============================================================================
# POC Hardcoded Key - TEMPORARY FOR TESTING
# ============================================================================

# This MUST match the key in src/crypt.c
POC_AES_KEY = bytes([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
])


def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-128-GCM.
    
    Output format: [IV (12 bytes)][Ciphertext][Tag (16 bytes)]
    
    Args:
        plaintext: Data to encrypt
        key: 16-byte AES key
    
    Returns:
        Encrypted data with IV and tag
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    # Generate random IV
    iv = os.urandom(GCM_IV_SIZE)
    
    # Create cipher
    aesgcm = AESGCM(key)
    
    # Encrypt and authenticate
    # AESGCM.encrypt() returns ciphertext + tag concatenated
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, None)
    
    # Format: IV || ciphertext || tag
    return iv + ciphertext_and_tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-128-GCM.
    
    Input format: [IV (12 bytes)][Ciphertext][Tag (16 bytes)]
    
    Args:
        ciphertext: Encrypted data with IV and tag
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If authentication fails or input is malformed
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    
    if len(ciphertext) < ENCRYPTION_OVERHEAD:
        raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes (min {ENCRYPTION_OVERHEAD})")
    
    # Extract IV
    iv = ciphertext[:GCM_IV_SIZE]
    
    # Extract ciphertext + tag (everything after IV)
    ciphertext_and_tag = ciphertext[GCM_IV_SIZE:]
    
    # Create cipher
    aesgcm = AESGCM(key)
    
    # Decrypt and verify
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def derive_session_key_hkdf(shared_secret: bytes) -> bytes:
    """
    Derive a 16-byte AES session key from ECDH shared secret using HKDF-SHA256.
    
    Args:
        shared_secret: 32-byte ECDH shared secret
    
    Returns:
        16-byte AES-128 session key
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    salt = b"MASTR-Session-Key-v1"
    info = b""
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(shared_secret)


class CryptoHandler:
    """
    Manages encryption/decryption for the MASTR protocol.
    """
    
    def __init__(self, force_encryption: bool = True, poc_key: bytes = POC_AES_KEY):
        """
        Initialize crypto handler.
        
        Args:
            force_encryption: If True, always encrypt/decrypt (POC mode)
            poc_key: Hardcoded key for POC testing
        """
        self.force_encryption = force_encryption
        self.session_key = poc_key
        self.protocol_state = 0x00  # Current protocol state
    
    def set_session_key(self, key: bytes):
        """Set the session key (from ECDH)"""
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Session key must be {AES_KEY_SIZE} bytes")
        self.session_key = key
    
    def set_protocol_state(self, state: int):
        """Update protocol state"""
        self.protocol_state = state
    
    def should_encrypt(self) -> bool:
        """Determine if current state requires encryption"""
        if self.force_encryption:
            return True
        
        # Encrypt if state >= 0x22 (after channel verification)
        return self.protocol_state >= 0x22
    
    def encrypt_payload(self, payload: bytes) -> bytes:
        """
        Encrypt payload if needed.
        
        Returns:
            Encrypted payload or original if encryption not needed
        """
        if not self.should_encrypt():
            return payload
        
        return aes_gcm_encrypt(payload, self.session_key)
    
    def decrypt_payload(self, payload: bytes) -> bytes:
        """
        Decrypt payload if needed.
        
        Returns:
            Decrypted payload or original if decryption not needed
        
        Raises:
            ValueError: If decryption fails
        """
        if not self.should_encrypt():
            return payload
        
        return aes_gcm_decrypt(payload, self.session_key)
