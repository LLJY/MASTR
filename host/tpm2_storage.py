"""
TPM2 NVRAM Storage Implementation

Stores AES-128 session keys in TPM2 Non-Volatile RAM.
Provides hardware-backed, persistent storage for session keys.

Requirements:
- TPM2 hardware or software emulator
- tpm2-pytss library
"""

from typing import Optional
from tpm2_pytss import ESAPI, TPM2_SU, ESYS_TR, TPMS_NV_PUBLIC, TPMA_NV, TPM2_ALG, TSS2_Exception, TPM2_RC, TPM2B_NV_PUBLIC, TPM2_CAP
from .key_storage_interface import KeyStorageInterface
from .logger import Logger


class TPM2Storage(KeyStorageInterface):
    """
    TPM2 NVRAM implementation for session key storage.
    
    Uses TPM2 NVRAM for hardware-backed persistent storage.
    Keys are stored at a specific NVRAM index.
    """
    
    def __init__(self, nv_index: int = 0x01800000):
        """
        Initialize TPM2 storage.
        
        Args:
            nv_index: TPM2 NVRAM index for key storage
                      Default: 0x01800000 (user-defined range)
        """
        self.nv_index = nv_index
        self.esapi: Optional[ESAPI] = None
        self._init_tpm()

    def _init_tpm(self) -> bool:
        """Initialize TPM connection."""
        try:
            if self.esapi is None:
                self.esapi = ESAPI()
                self.esapi.startup(TPM2_SU.CLEAR)
            return True
        except TSS2_Exception as e:
            # It's possible startup failed because it was already started, which is fine
            # But if we can't create ESAPI, that's a failure
            if not self.esapi:
                return False
            return True
        except Exception:
            return False

    def store_session_key(self, key: bytes, key_id: str = "mastr-session") -> bool:
        """
        Store session key in TPM2 NVRAM.
        """
        self.validate_key(key)
        
        if not self._init_tpm():
            Logger.error("TPM connection failed")
            return False

        try:
            # Step 1: Check if NV index already exists
            if self._nv_index_exists():
                Logger.info(f"TPM2 NVRAM index 0x{self.nv_index:08x} already exists, will overwrite")
            self._undefine_nv_index()
            
            # Step 2: Define NV space
            if not self._define_nv_index(len(key)):
                return False
            
            # Step 3: Write key to NVRAM
            # Get handle for the NV index
            nv_handle = self.esapi.tr_from_tpmpublic(self.nv_index)
            
            try:
                # We write to the NV index using Owner authorization (default empty auth)
                self.esapi.nv_write(
                    nv_handle,
                    key,
                    offset=0,
                    auth_handle=ESYS_TR.RH_OWNER
                )
            finally:
                # Always close the handle we opened
                self.esapi.tr_close(nv_handle)
            
            Logger.success(f"Stored session key in TPM2 NVRAM at 0x{self.nv_index:08x}")
            return True
                
        except TSS2_Exception as e:
            Logger.error(f"Failed to write to TPM2 NVRAM: {e}")
            return False
        except Exception as e:
            Logger.error(f"Error storing key in TPM2: {e}")
            return False
    
    def retrieve_session_key(self, key_id: str = "mastr-session") -> Optional[bytes]:
        """
        Retrieve session key from TPM2 NVRAM.
        """
        if not self._init_tpm():
            return None

        try:
            # Check if NV index exists
            if not self._nv_index_exists():
                Logger.warning(f"TPM2 NVRAM index 0x{self.nv_index:08x} not found")
                return None
            
            # Get handle for the NV index
            nv_handle = self.esapi.tr_from_tpmpublic(self.nv_index)
            
            try:
                # Read from NVRAM
                # We read 16 bytes (AES-128 key size)
                data = self.esapi.nv_read(
                    nv_handle,
                    size=16,
                    offset=0,
                    auth_handle=ESYS_TR.RH_OWNER
                )
            finally:
                self.esapi.tr_close(nv_handle)

            key_data = bytes(data)
            
            # Validate key length
            if len(key_data) != 16:
                Logger.error(f"Retrieved key has invalid length: {len(key_data)} (expected 16)")
                return None
            
            Logger.success(f"Retrieved session key from TPM2 NVRAM at 0x{self.nv_index:08x}")
            return key_data
            
        except TSS2_Exception as e:
            Logger.error(f"Failed to read from TPM2 NVRAM: {e}")
            return None
        except Exception as e:
            Logger.error(f"Error retrieving key from TPM2: {e}")
            return None
    
    def delete_session_key(self, key_id: str = "mastr-session") -> bool:
        """
        Delete session key from TPM2 NVRAM.
        """
        if not self._init_tpm():
            return False
        return self._undefine_nv_index()
    
    def is_available(self) -> bool:
        """
        Check if TPM2 is available.
        """
        return self._init_tpm()
    
    def _nv_index_exists(self) -> bool:
        """
        Check if NV index is already defined.
        """
        try:
            # Use get_capability to check for handle existence without triggering errors
            # We ask for 1 handle starting at our NV index
            more_data, cap_data = self.esapi.get_capability(
                TPM2_CAP.HANDLES,
                self.nv_index,
                property_count=1
            )
            
            # Check if we got any handles back
            if not cap_data.data.handles:
                return False
                
            # Check if the first returned handle matches our index
            return cap_data.data.handles[0] == self.nv_index
            
        except TSS2_Exception:
            return False
    
    def _define_nv_index(self, size: int) -> bool:
        """
        Define NV index for key storage.
        """
        try:
            # Define NV space attributes
            # Owner write/read, and policy read (standard for storage)
            attributes = (
                TPMA_NV.OWNERWRITE |
                TPMA_NV.OWNERREAD |
                TPMA_NV.AUTHREAD |
                TPMA_NV.NO_DA
            )

            nv_public = TPMS_NV_PUBLIC(
                nvIndex=self.nv_index,
                nameAlg=TPM2_ALG.SHA256,
                attributes=attributes,
                authPolicy=b'',
                dataSize=size
            )
            
            # Wrap in TPM2B structure
            nv_public_2b = TPM2B_NV_PUBLIC(nvPublic=nv_public)

            self.esapi.nv_define_space(
                b'',
                nv_public_2b,
                auth_handle=ESYS_TR.RH_OWNER
            )
            
            Logger.info(f"Defined TPM2 NVRAM index 0x{self.nv_index:08x}")
            return True
                
        except TSS2_Exception as e:
            Logger.error(f"Failed to define TPM2 NVRAM index: {e}")
            return False
    
    def _undefine_nv_index(self) -> bool:
        """
        Undefine (delete) NV index.
        """
        try:
            if not self._nv_index_exists():
                Logger.info(f"TPM2 NVRAM index 0x{self.nv_index:08x} does not exist (already deleted?)")
                return True
            
            # For undefine, we need the handle too
            nv_handle = self.esapi.tr_from_tpmpublic(self.nv_index)
            
            success = False
            try:
                self.esapi.nv_undefine_space(
                    nv_handle,
                    auth_handle=ESYS_TR.RH_OWNER
                )
                success = True
            finally:
                # If undefine succeeded, the handle is likely invalid/consumed.
                # Only try to close if we failed to undefine.
                if not success:
                    try:
                        self.esapi.tr_close(nv_handle)
                    except TSS2_Exception:
                        pass
            
            Logger.success(f"Deleted TPM2 NVRAM index 0x{self.nv_index:08x}")
            return True
                
        except TSS2_Exception as e:
            Logger.error(f"Failed to undefine TPM2 NVRAM index: {e}")
            return False