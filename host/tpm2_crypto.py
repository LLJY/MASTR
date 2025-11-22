"""
TPM2-based Crypto Implementation

This implementation uses a TPM 2.0 device for all critical cryptographic
operations, including storage of the host's permanent private key.
"""

from typing import Optional, Tuple
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from tpm2_pytss import (
    ESAPI, TPM2_SU, TPM2_ECC, TPM2_ALG, ESYS_TR,
    TPMT_SIG_SCHEME, TPMT_ECC_SCHEME, TPMT_PUBLIC, TPMS_ECC_PARMS,
    TPM2B_DIGEST, TPMT_TK_HASHCHECK, TPM2B_SENSITIVE_CREATE,
    TPMS_ECC_POINT, TPM2B_ECC_POINT, TPM2B_ECC_PARAMETER,
    TPMS_NV_PUBLIC, TPM2B_NV_PUBLIC, TPMA_NV, TPMA_OBJECT, TPM2B_PUBLIC,
    TPMS_SCHEME_HASH, TPM2B_AUTH
)
from tpm2_pytss.constants import TPM2_RH, TPM2_RC, TPM2_CAP
from tpm2_pytss import TSS2_Exception

from .crypto_interface import CryptoInterface

# Crypto constants
AES_KEY_SIZE = 16
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16
ENCRYPTION_OVERHEAD = GCM_IV_SIZE + GCM_TAG_SIZE


class TPM2Crypto(CryptoInterface):

    def __init__(self) -> None:
        """Initialize TPM2 crypto backend."""
        super().__init__()
        self.esapi = ESAPI()
        self.esapi.startup(TPM2_SU.CLEAR)
        print("TPM initialized successfully.")
        self.host_permanent_key_handle = None
        self.HOST_PERMANENT_KEY_HANDLE = 0x81000080
        self.TOKEN_PUBKEY_NV_HANDLE = 0x01C00002

    # ========================================================================
    # Key Management
    # ========================================================================

    def load_permanent_keys(self) -> bool:
        """Load host private key and token public key from TPM2"""
        try:
            # Load the persistent host key from the TPM
            self.host_permanent_key_handle = self.esapi.tr_from_tpmpublic(self.HOST_PERMANENT_KEY_HANDLE)

            # Read the public part of the key
            pub, _, _ = self.esapi.read_public(self.host_permanent_key_handle)
            pubkey_point = pub.publicArea.unique.ecc
            self.host_permanent_pubkey_raw = bytes(pubkey_point.x.buffer) + bytes(pubkey_point.y.buffer)

            # Load token permanent public key from NVRAM
            # Convert NV index to ESYS_TR handle
            nv_handle = self.esapi.tr_from_tpmpublic(self.TOKEN_PUBKEY_NV_HANDLE)
            try:
                nv_data = self.esapi.nv_read(
                    nv_handle, 64, offset=0, auth_handle=ESYS_TR.OWNER
                )
                self.token_permanent_pubkey_raw = bytes(nv_data)
            finally:
                self.esapi.tr_close(nv_handle)

            if len(self.token_permanent_pubkey_raw) != 64:
                return False

            return True

        except TSS2_Exception as e:
            print(f"TSS2 exception loading keys: {e}")
            import traceback
            traceback.print_exc()
            return False
        except Exception as e:
            print(f"Exception loading keys: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_permanent_keypair(self) -> bool:
        """Generate new permanent keypair and save to TPM2"""
        try:
            # Try to evict any existing key at the persistent handle
            try:
                loaded_handle = self.esapi.tr_from_tpmpublic(self.HOST_PERMANENT_KEY_HANDLE)
                self.esapi.evict_control(ESYS_TR.OWNER, loaded_handle, self.HOST_PERMANENT_KEY_HANDLE)
                self.esapi.flush_context(loaded_handle)
            except (TSS2_Exception, Exception):
                # Key doesn't exist yet, which is fine
                pass

            # Create an ECC primary key
            in_sensitive = TPM2B_SENSITIVE_CREATE()
            in_public = TPM2B_PUBLIC.parse(
                alg='ecc256:ecdsa',
                objectAttributes=(
                    TPMA_OBJECT.USERWITHAUTH |
                    TPMA_OBJECT.SIGN_ENCRYPT |
                    TPMA_OBJECT.FIXEDTPM |
                    TPMA_OBJECT.FIXEDPARENT |
                    TPMA_OBJECT.SENSITIVEDATAORIGIN
                )
            )
            
            key_handle, pub, _, _, _ = self.esapi.create_primary(
                in_sensitive, in_public, primary_handle=ESYS_TR.OWNER
            )

            # Make the key persistent
            self.esapi.evict_control(ESYS_TR.OWNER, key_handle, self.HOST_PERMANENT_KEY_HANDLE)

            # Store raw public key
            pubkey_point = pub.publicArea.unique.ecc
            self.host_permanent_pubkey_raw = bytes(pubkey_point.x.buffer) + bytes(pubkey_point.y.buffer)

            # Try to flush the transient handle (may fail if already evicted, which is fine)
            try:
                self.esapi.flush_context(key_handle)
            except (TSS2_Exception, Exception):
                pass

            return True

        except Exception as e:
            print(f"Exception during keypair generation: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_host_permanent_pubkey(self) -> Optional[bytes]:
        """Get host's permanent public key from the TPM2."""
        return self.host_permanent_pubkey_raw

    def _nv_index_exists(self, nv_index: int) -> bool:
        """
        Check if NV index is already defined.

        Args:
            nv_index: TPM2 NV index to check

        Returns:
            True if NV index exists, False otherwise
        """
        try:
            # Use get_capability to check for handle existence without triggering errors
            # We ask for 1 handle starting at our NV index
            more_data, cap_data = self.esapi.get_capability(
                TPM2_CAP.HANDLES,
                nv_index,
                property_count=1
            )

            # Check if we got any handles back
            if not cap_data.data.handles:
                return False

            # Check if the first returned handle matches our index
            return cap_data.data.handles[0] == nv_index

        except TSS2_Exception:
            return False

    def set_token_permanent_pubkey(self, pubkey: bytes) -> bool:
        """Store token's permanent public key in TPM NVRAM."""
        if len(pubkey) != 64:
            return False

        try:
            # Check if NV index already exists and undefine it if so
            if self._nv_index_exists(self.TOKEN_PUBKEY_NV_HANDLE):
                # Convert NV index to ESYS_TR handle for undefine
                nv_handle = self.esapi.tr_from_tpmpublic(self.TOKEN_PUBKEY_NV_HANDLE)
                try:
                    self.esapi.nv_undefine_space(nv_handle, auth_handle=ESYS_TR.OWNER)
                finally:
                    self.esapi.tr_close(nv_handle)

            # Define the NV space for the token's public key
            # Using TPM2B_NV_PUBLIC wrapper for TPMS_NV_PUBLIC
            nv_public = TPM2B_NV_PUBLIC(
                nvPublic=TPMS_NV_PUBLIC(
                    nvIndex=self.TOKEN_PUBKEY_NV_HANDLE,
                    nameAlg=TPM2_ALG.SHA256,
                    attributes=TPMA_NV.OWNERWRITE | TPMA_NV.OWNERREAD | TPMA_NV.AUTHREAD,
                    dataSize=64
                )
            )
            # Parameter order for system package v2.3.0: auth, public_info, auth_handle
            self.esapi.nv_define_space(TPM2B_AUTH(), nv_public, ESYS_TR.OWNER)

            # Write the key to the NV space
            # Convert NV index to ESYS_TR handle for writing
            nv_handle = self.esapi.tr_from_tpmpublic(self.TOKEN_PUBKEY_NV_HANDLE)
            try:
                self.esapi.nv_write(nv_handle, pubkey, offset=0, auth_handle=ESYS_TR.OWNER)
            finally:
                self.esapi.tr_close(nv_handle)

            self.token_permanent_pubkey_raw = pubkey
            return True
        except TSS2_Exception as e:
            print(f"Failed to set token permanent pubkey in NVRAM: {e}")
            return False

    # ========================================================================
    # ECDH Operations
    # ========================================================================

    def generate_ephemeral_keypair(self) -> Tuple[bytes, object]:
        """Generate ephemeral P-256 keypair"""
        try:
            # Create an ephemeral ECC key for ECDH
            in_sensitive = TPM2B_SENSITIVE_CREATE()
            in_public = TPM2B_PUBLIC.parse(
                alg='ecc256:ecdh',
                objectAttributes=(
                    TPMA_OBJECT.USERWITHAUTH |
                    TPMA_OBJECT.DECRYPT |
                    TPMA_OBJECT.FIXEDTPM |
                    TPMA_OBJECT.FIXEDPARENT |
                    TPMA_OBJECT.SENSITIVEDATAORIGIN
                )
            )
            
            # Create primary key for ECDH
            key_handle, pub, _, _, _ = self.esapi.create_primary(
                in_sensitive,
                in_public,
                primary_handle=ESYS_TR.OWNER
            )

            # Extract raw public key
            pubkey_point = pub.publicArea.unique.ecc
            pubkey_raw = bytes(pubkey_point.x.buffer) + bytes(pubkey_point.y.buffer)

            # Return both public key and handle (don't flush yet, needed for ECDH)
            return (pubkey_raw, key_handle)

        except Exception:
            return (None, None)

    def sign_with_permanent_key(self, message: bytes) -> Optional[bytes]:
        """Sign message with host's permanent private key"""
        if self.host_permanent_key_handle is None:
            return None

        try:
            # Hash with TPM to get validation ticket
            digest, validation = self.esapi.hash(
                message,
                TPM2_ALG.SHA256,
                ESYS_TR.RH_NULL
            )

            # Define the signing scheme
            scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
            scheme.details.ecdsa = TPMS_SCHEME_HASH(hashAlg=TPM2_ALG.SHA256)

            # Sign the digest
            signature = self.esapi.sign(
                self.host_permanent_key_handle,
                digest,
                scheme,
                validation
            )

            # Convert signature to raw format (R||S, 64 bytes)
            r = bytes(signature.signature.ecdsa.signatureR.buffer)
            s = bytes(signature.signature.ecdsa.signatureS.buffer)
            return r + s

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
            print(f"ERROR: peer_pubkey length is {len(peer_pubkey)}, expected 64")
            return None

        try:
            # Convert peer's raw public key to TPM2B_ECC_POINT (wrapper for TPMS_ECC_POINT)
            x = TPM2B_ECC_PARAMETER(peer_pubkey[:32])
            y = TPM2B_ECC_PARAMETER(peer_pubkey[32:])
            peer_point = TPM2B_ECC_POINT(point=TPMS_ECC_POINT(x=x, y=y))

            # Compute shared secret using ECDH
            z_point = self.esapi.ecdh_zgen(ephemeral_privkey, peer_point)

            # Clean up ephemeral key after use
            self.esapi.flush_context(ephemeral_privkey)

            # z_point is TPM2B_ECC_POINT wrapper - access via .point.x
            return bytes(z_point.point.x.buffer)

        except Exception as e:
            print(f"Exception in compute_shared_secret: {e}")
            import traceback
            traceback.print_exc()
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
