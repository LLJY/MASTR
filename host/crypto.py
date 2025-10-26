"""
Naive File-Based Crypto Implementation

This is the default "naive" implementation that stores keys in files.
For production, use TPM2 or HSM-based implementations instead.
"""

from typing import Optional, Tuple
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .crypto_interface import CryptoInterface

# File paths for key storage
HOST_PRIVKEY_FILE = 'host_permanent_privkey.pem'
HOST_PUBKEY_FILE = 'host_permanent_pubkey.bin'
TOKEN_PUBKEY_FILE = 'token_permanent_pubkey.bin'

# Crypto constants
AES_KEY_SIZE = 16
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16
ENCRYPTION_OVERHEAD = GCM_IV_SIZE + GCM_TAG_SIZE


class NaiveCrypto(CryptoInterface):
    """
    File-based cryptographic implementation.
    
    WARNING: This stores private keys in PEM files on disk.
    For production use, implement TPM2-based crypto instead.
    """
    
    def __init__(self) -> None:
        """Initialize naive crypto with file-based key storage"""
        super().__init__()
        self.host_permanent_privkey = None
        self.host_permanent_pubkey_raw = None
        self.token_permanent_pubkey_raw = None
    
    # ========================================================================
    # Key Management
    # ========================================================================
    
    def load_permanent_keys(self) -> bool:
        """Load host private key and token public key from files"""
        try:
            # Load host permanent private key
            with open(HOST_PRIVKEY_FILE, 'rb') as f:
                self.host_permanent_privkey = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Load host public key (raw format)
            with open(HOST_PUBKEY_FILE, 'rb') as f:
                self.host_permanent_pubkey_raw = f.read()
                if len(self.host_permanent_pubkey_raw) != 64:
                    return False
            
            # Load token permanent public key
            with open(TOKEN_PUBKEY_FILE, 'rb') as f:
                self.token_permanent_pubkey_raw = f.read()
                if len(self.token_permanent_pubkey_raw) != 64:
                    return False
            
            return True
        
        except FileNotFoundError:
            return False
        except Exception:
            return False
    
    def generate_permanent_keypair(self) -> bool:
        """Generate new permanent keypair and save to files"""
        try:
            # Generate P-256 keypair
            privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
            pubkey = privkey.public_key()
            
            # Save private key as PEM
            pem = privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(HOST_PRIVKEY_FILE, 'wb') as f:
                f.write(pem)
            
            # Save public key as raw bytes (64 bytes: X||Y)
            pubkey_bytes = pubkey.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            pubkey_raw = pubkey_bytes[1:]  # Remove 0x04 prefix
            
            with open(HOST_PUBKEY_FILE, 'wb') as f:
                f.write(pubkey_raw)
            
            # Store in memory
            self.host_permanent_privkey = privkey
            self.host_permanent_pubkey_raw = pubkey_raw
            
            return True
        
        except Exception:
            return False
    
    def get_host_permanent_pubkey(self) -> Optional[bytes]:
        """Get host's permanent public key"""
        return self.host_permanent_pubkey_raw
    
    def set_token_permanent_pubkey(self, pubkey: bytes) -> bool:
        """Store token's permanent public key"""
        if len(pubkey) != 64:
            return False
        
        try:
            with open(TOKEN_PUBKEY_FILE, 'wb') as f:
                f.write(pubkey)
            self.token_permanent_pubkey_raw = pubkey
            return True
        except Exception:
            return False
    
    # ========================================================================
    # ECDH Operations
    # ========================================================================
    
    def generate_ephemeral_keypair(self) -> Tuple[bytes, object]:
        """Generate ephemeral P-256 keypair"""
        privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pubkey = privkey.public_key()
        
        # Extract raw public key bytes (64 bytes: X||Y)
        pubkey_bytes = pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        pubkey_raw = pubkey_bytes[1:]  # Remove 0x04 prefix
        
        return (pubkey_raw, privkey)
    
    def sign_with_permanent_key(self, message: bytes) -> Optional[bytes]:
        """Sign message with host's permanent private key"""
        if self.host_permanent_privkey is None:
            return None
        
        try:
            # Sign using ECDSA with SHA-256
            signature_der = self.host_permanent_privkey.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Convert DER signature to raw format (R||S, 64 bytes)
            r, s = decode_dss_signature(signature_der)
            signature_raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
            
            return signature_raw
        
        except Exception:
            return None
    
    def verify_signature(self, message: bytes, signature: bytes, pubkey: bytes) -> bool:
        """Verify ECDSA signature"""
        if len(signature) != 64 or len(pubkey) != 64:
            return False
        
        try:
            # Reconstruct public key from raw bytes
            pubkey_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                b'\x04' + pubkey
            )
            
            # Convert raw signature to DER format
            r = int.from_bytes(signature[:32], 'big')
            s = int.from_bytes(signature[32:], 'big')
            signature_der = encode_dss_signature(r, s)
            
            # Verify signature
            pubkey_obj.verify(
                signature_der,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
        
        except Exception:
            return False
    
    def compute_shared_secret(self, ephemeral_privkey: object, peer_pubkey: bytes) -> Optional[bytes]:
        """Compute ECDH shared secret"""
        if len(peer_pubkey) != 64:
            return None
        
        try:
            # Reconstruct peer's public key from raw bytes
            peer_pubkey_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                b'\x04' + peer_pubkey
            )
            
            # Compute shared secret using ECDH
            shared_secret = ephemeral_privkey.exchange(ec.ECDH(), peer_pubkey_obj)
            
            return shared_secret
        
        except Exception:
            return None
    
    def derive_session_key(self, shared_secret: bytes) -> Optional[bytes]:
        """Derive AES-128 session key from ECDH shared secret using HKDF-SHA256"""
        if len(shared_secret) != 32:
            return None
        
        try:
            # HKDF parameters (must match C implementation)
            salt = b"MASTR-Session-Key-v1"
            info = b""
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE,
                salt=salt,
                info=info,
                backend=default_backend()
            )
            
            session_key = hkdf.derive(shared_secret)
            return session_key
        
        except Exception:
            return None
    
    # ========================================================================
    # Encryption/Decryption
    # ========================================================================
    
    def encrypt_payload(self, payload: bytes) -> bytes:
        """Encrypt payload if required by protocol state"""
        if not self.should_encrypt():
            return payload
        
        if self.session_key is None:
            raise ValueError("Session key not set")
        
        # Generate random IV
        iv = os.urandom(GCM_IV_SIZE)
        
        # Create cipher and encrypt
        aesgcm = AESGCM(self.session_key)
        ciphertext_and_tag = aesgcm.encrypt(iv, payload, None)
        
        # Format: IV || ciphertext || tag
        return iv + ciphertext_and_tag
    
    def decrypt_payload(self, payload: bytes) -> bytes:
        """Decrypt payload if required by protocol state"""
        if not self.should_encrypt():
            return payload
        
        if self.session_key is None:
            raise ValueError("Session key not set")
        
        if len(payload) < ENCRYPTION_OVERHEAD:
            raise ValueError(f"Payload too short for decryption: {len(payload)} bytes")
        
        # Extract IV and ciphertext+tag
        iv = payload[:GCM_IV_SIZE]
        ciphertext_and_tag = payload[GCM_IV_SIZE:]
        
        # Decrypt and verify
        try:
            aesgcm = AESGCM(self.session_key)
            plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
