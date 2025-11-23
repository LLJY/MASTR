#!/usr/bin/env python3
"""
MASTR Bootstrap - Initramfs Integrity Gate

This script performs the initial handshake and integrity verification with the
MASTR hardware token. It is designed to run within the initramfs environment
before the main root filesystem is mounted.

Exit Codes:
  0: Success - Token verified, integrity confirmed. Boot may proceed.
  1: Failure - Token missing, invalid, or integrity check failed. Boot should halt.

Usage:
  python3 -m host.bootstrap --port /dev/ttyACM0 [--debug]
"""

import sys
import argparse
import logging
from typing import Optional

from .main import MASTRHost
from .crypto import NaiveCrypto
from .tpm2_crypto import TPM2Crypto
from .logger import Logger, Colors

class BootstrapPanic(Exception):
    """Raised when a security violation (like unexpected debug output) occurs."""
    pass

class BootstrapHost(MASTRHost):
    """
    Specialized MASTRHost for initramfs bootstrapping.
    
    Differences from main MASTRHost:
    1. Enforces "Panic on Debug" policy (unless --debug is set).
    2. Simplified execution flow (single pass, no watchdog).
    3. Minimal output (unless --debug is set).
    """
    
    def __init__(self, port: str, baudrate: int = 115200, crypto=None, debug_mode: bool = False):
        super().__init__(
            port=port,
            baudrate=baudrate,
            crypto=crypto,
            verbose=debug_mode,
            skip_key_storage=False
        )
        self.debug_mode = debug_mode

    def _handle_debug_message(self, payload: bytes) -> None:
        """
        Handle debug messages from token.
        
        Security Policy:
        - If debug_mode is False: PANIC. Debug messages in production are a security risk.
        - If debug_mode is True: Log it.
        """
        if not self.debug_mode:
            # Security Violation!
            try:
                msg = payload.decode('utf-8', errors='replace')
            except Exception:
                msg = payload.hex()
            
            raise BootstrapPanic(f"Security Violation: Token sent debug message in non-debug mode: {msg}")
        
        # Default behavior (log it)
        super()._handle_debug_message(payload)

    def bootstrap(self) -> int:
        """
        Perform single-pass integrity verification.
        
        Returns:
            0 on success
            1 on failure
        """
        try:
            Logger.header("MASTR Bootstrap - Integrity Gate")
            
            # 1. Connect
            if not self.handler.connect():
                Logger.error(f"Failed to connect to {self.port}")
                return 1
            
            self.handler.start()
            
            # 2. Load Keys
            if not self._load_or_generate_keys():
                Logger.error("Failed to load keys")
                return 1
            
            # 3. Phase 1: ECDH
            if not self._perform_ecdh_handshake():
                Logger.error("ECDH handshake failed")
                return 1
            
            # 4. Channel Verification
            if not self._perform_channel_verification():
                Logger.error("Channel verification failed")
                return 1
            
            # 5. Phase 2: Integrity Verification
            if not self._perform_integrity_verification():
                Logger.error("Integrity verification failed")
                return 1
            
            # 6. Store Session Key (for runtime handover)
            # We use the kernel keyring, which should persist into the main OS
            if not self._store_session_key_for_runtime():
                Logger.error("Failed to store session key")
                return 1
            
            Logger.success_header("Integrity Verified - Boot Allowed")
            return 0
            
        except BootstrapPanic as e:
            Logger.tagged("PANIC", Colors.RED, str(e))
            return 1
        except Exception as e:
            Logger.error(f"Bootstrap failed with unexpected error: {e}")
            if self.debug_mode:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.handler.stop()
            self.handler.disconnect()

def main():
    parser = argparse.ArgumentParser(description='MASTR Initramfs Bootstrap')
    parser.add_argument('--port', required=True, help='Serial port (e.g. /dev/ttyACM0)')
    parser.add_argument('--baudrate', type=int, default=115200, help='Baud rate')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (allows debug msgs)')
    parser.add_argument('--crypto', choices=['naive', 'tpm2'], default='tpm2', help='Crypto backend')
    
    args = parser.parse_args()
    
    # Select Crypto Backend
    if args.crypto == 'naive':
        crypto = NaiveCrypto()
    else:
        try:
            crypto = TPM2Crypto()
        except Exception as e:
            Logger.error(f"Failed to initialize TPM2: {e}")
            return 1
            
    host = BootstrapHost(
        port=args.port,
        baudrate=args.baudrate,
        crypto=crypto,
        debug_mode=args.debug
    )
    
    return host.bootstrap()

if __name__ == '__main__':
    sys.exit(main())
