"""
TPM2 NVRAM Storage Implementation

Stores AES-128 session keys in TPM2 Non-Volatile RAM.
Provides hardware-backed, persistent storage for session keys.

Requirements:
- TPM2 hardware or software emulator
- tpm2-tools package (tpm2_nvdefine, tpm2_nvwrite, tpm2_nvread, etc.)
"""

import subprocess
from typing import Optional

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
        self.nv_index_hex = f"0x{nv_index:08x}"
    
    def store_session_key(self, key: bytes, key_id: str = "mastr-session") -> bool:
        """
        Store session key in TPM2 NVRAM.
        
        Uses: tpm2_nvdefine + tpm2_nvwrite
        """
        self.validate_key(key)
        
        try:
            # Step 1: Check if NV index already exists
            if self._nv_index_exists():
                Logger.info(f"TPM2 NVRAM index {self.nv_index_hex} already exists, will overwrite")
                # Try to undefine first
                self._undefine_nv_index()
            
            # Step 2: Define NV space
            if not self._define_nv_index():
                return False
            
            # Step 3: Write key to NVRAM
            write_cmd = [
                'tpm2_nvwrite',
                self.nv_index_hex,
                '-C', 'o',  # Use owner hierarchy
                '-i-'        # Read from stdin
            ]
            
            result = subprocess.run(
                write_cmd,
                input=key,
                capture_output=True,
                timeout=10.0
            )
            
            if result.returncode == 0:
                Logger.success(f"Stored session key in TPM2 NVRAM at {self.nv_index_hex}")
                return True
            else:
                error = result.stderr.decode().strip()
                Logger.error(f"Failed to write to TPM2 NVRAM: {error}")
                return False
                
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while writing to TPM2 NVRAM")
            return False
        except FileNotFoundError:
            Logger.error("tpm2_nvwrite command not found - install tpm2-tools package")
            return False
        except Exception as e:
            Logger.error(f"Error storing key in TPM2: {e}")
            return False
    
    def retrieve_session_key(self, key_id: str = "mastr-session") -> Optional[bytes]:
        """
        Retrieve session key from TPM2 NVRAM.
        
        Uses: tpm2_nvread
        """
        try:
            # Check if NV index exists
            if not self._nv_index_exists():
                Logger.warning(f"TPM2 NVRAM index {self.nv_index_hex} not found")
                return None
            
            # Read from NVRAM
            read_cmd = [
                'tpm2_nvread',
                self.nv_index_hex,
                '-C', 'o'  # Use owner hierarchy
            ]
            
            result = subprocess.run(
                read_cmd,
                capture_output=True,
                timeout=10.0
            )
            
            if result.returncode != 0:
                error = result.stderr.decode().strip()
                Logger.error(f"Failed to read from TPM2 NVRAM: {error}")
                return None
            
            key_data = result.stdout
            
            # Validate key length
            if len(key_data) != 16:
                Logger.error(f"Retrieved key has invalid length: {len(key_data)} (expected 16)")
                return None
            
            Logger.success(f"Retrieved session key from TPM2 NVRAM at {self.nv_index_hex}")
            return key_data
            
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while reading from TPM2 NVRAM")
            return None
        except FileNotFoundError:
            Logger.error("tpm2_nvread command not found - install tpm2-tools package")
            return None
        except Exception as e:
            Logger.error(f"Error retrieving key from TPM2: {e}")
            return None
    
    def delete_session_key(self, key_id: str = "mastr-session") -> bool:
        """
        Delete session key from TPM2 NVRAM.
        
        Uses: tpm2_nvundefine
        """
        return self._undefine_nv_index()
    
    def is_available(self) -> bool:
        """
        Check if TPM2 is available.
        
        Tests by checking if tpm2-tools commands exist and TPM is accessible.
        """
        try:
            # Try to read TPM capability
            cmd = ['tpm2_getcap', 'properties-fixed']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5.0
            )
            
            # If we can read TPM capabilities, it's available
            return result.returncode == 0
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        except Exception:
            return False
    
    def _nv_index_exists(self) -> bool:
        """
        Check if NV index is already defined.
        
        Uses: tpm2_nvreadpublic
        """
        try:
            cmd = ['tpm2_nvreadpublic', self.nv_index_hex]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5.0
            )
            
            # Index exists if command succeeds
            return result.returncode == 0
            
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False
    
    def _define_nv_index(self) -> bool:
        """
        Define NV index for key storage.
        
        Uses: tpm2_nvdefine
        """
        try:
            # Define NV space with appropriate attributes
            # Size: 16 bytes (AES-128 key)
            # Attributes: ownerwrite|ownerread|policyread
            define_cmd = [
                'tpm2_nvdefine',
                self.nv_index_hex,
                '-C', 'o',  # Use owner hierarchy
                '-s', '16',  # Size: 16 bytes
                '-a', 'ownerwrite|ownerread|policyread'
            ]
            
            result = subprocess.run(
                define_cmd,
                capture_output=True,
                timeout=10.0
            )
            
            if result.returncode == 0:
                Logger.info(f"Defined TPM2 NVRAM index {self.nv_index_hex}")
                return True
            else:
                error = result.stderr.decode().strip()
                Logger.error(f"Failed to define TPM2 NVRAM index: {error}")
                return False
                
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while defining TPM2 NVRAM index")
            return False
        except FileNotFoundError:
            Logger.error("tpm2_nvdefine command not found - install tpm2-tools package")
            return False
        except Exception as e:
            Logger.error(f"Error defining TPM2 NVRAM index: {e}")
            return False
    
    def _undefine_nv_index(self) -> bool:
        """
        Undefine (delete) NV index.
        
        Uses: tpm2_nvundefine
        """
        try:
            if not self._nv_index_exists():
                Logger.info(f"TPM2 NVRAM index {self.nv_index_hex} does not exist (already deleted?)")
                return True
            
            undefine_cmd = [
                'tpm2_nvundefine',
                self.nv_index_hex,
                '-C', 'o'  # Use owner hierarchy
            ]
            
            result = subprocess.run(
                undefine_cmd,
                capture_output=True,
                timeout=10.0
            )
            
            if result.returncode == 0:
                Logger.success(f"Deleted TPM2 NVRAM index {self.nv_index_hex}")
                return True
            else:
                error = result.stderr.decode().strip()
                Logger.error(f"Failed to undefine TPM2 NVRAM index: {error}")
                return False
                
        except subprocess.TimeoutExpired:
            Logger.error("Timeout while undefining TPM2 NVRAM index")
            return False
        except FileNotFoundError:
            Logger.error("tpm2_nvundefine command not found - install tpm2-tools package")
            return False
        except Exception as e:
            Logger.error(f"Error undefining TPM2 NVRAM index: {e}")
            return False