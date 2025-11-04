"""
MASTR Host - Production Protocol Implementation

This is the main entry point for the MASTR protocol. It implements the complete
protocol state machine with pluggable cryptographic backends.

CRYPTO BACKENDS:
  - NaiveCrypto: File-based key storage (development/testing)
  - TPM2Crypto: TPM2-based secure storage (production) ✓ IMPLEMENTED

PROTOCOL PHASES:
  Phase 0: Key Provisioning
    - Load or generate permanent keypairs
    - Exchange public keys with token
  
  Phase 1: Mutual Authentication (ECDH) ✓ IMPLEMENTED
    - Generate ephemeral P-256 keypairs
    - Sign ephemeral keys with permanent keys
    - Verify signatures
    - Compute ECDH shared secret
    - Derive AES-128 session key via HKDF-SHA256
  
  Phase 1.5: Channel Verification ✓ IMPLEMENTED
    - Token sends encrypted "ping" challenge
    - Host responds with encrypted "pong"
    - Confirms session key is identical on both sides
  
  Phase 2: Integrity Verification [TODO]
    - Token challenges host firmware integrity
    - Host provides signed integrity attestation
    - Token validates before allowing operations
  
  Phase 3: Runtime Heartbeat [TODO]
    - Periodic keep-alive messages
    - Detect disconnection or tampering
    - Automatic session teardown on timeout

EXTENDING THE PROTOCOL:
  1. Add new message types to protocol.py (both Python and C)
  2. Add handler methods to MASTRHost class (e.g., _handle_new_message)
  3. Register handlers in on_frame_received()
  4. Implement corresponding C handlers in src/protocol.c
  5. Update protocol state machine as needed

SWITCHING CRYPTO BACKENDS:
  Simply pass a different CryptoInterface implementation to MASTRHost:
    host = MASTRHost(port, crypto=TPM2Crypto())
  
  All crypto implementations must implement CryptoInterface methods.
"""

import sys
import os
import argparse
import time
import threading
from typing import Optional

from .serial_handler import SerialHandler
from .protocol import Frame, MessageType, get_message_name
from .parser import FrameParserError, ChecksumError, ProtocolError
from .crypto import NaiveCrypto
from .tpm2_crypto import TPM2Crypto
from .crypto_interface import CryptoInterface
from .logger import Logger, Colors
from .hybrid_key_storage import HybridKeyStorage


class MASTRHost:
    """
    Production MASTR protocol implementation with full state machine.
    
    This class manages the complete protocol lifecycle:
      - Serial communication with token
      - Cryptographic operations (via pluggable backend)
      - Protocol state transitions
      - Frame encryption/decryption
    
    To use:
        crypto = NaiveCrypto()  # or TPM2Crypto()
        host = MASTRHost(port="/dev/ttyACM0", crypto=crypto)
        exit_code = host.run()
    """
    
    def __init__(self, port: str, baudrate: int = 115200, crypto: Optional[CryptoInterface] = None, verbose: bool = False, auto_provision: bool = False, skip_key_storage: bool = False, debug_handover: bool = False):
        """
        Initialize the MASTR host.
        
        Args:
            port: Serial port to connect to
            baudrate: Serial baud rate
            crypto: Crypto implementation (defaults to NaiveCrypto)
            verbose: Enable verbose output
            auto_provision: Automatically provision keys and golden hash if True
            skip_key_storage: Skip storing session key for runtime (testing only)
            debug_handover: Simulate initramfs->systemd handover for testing
        """
        self.port = port
        self.baudrate = baudrate
        self.verbose = verbose
        self.auto_provision = auto_provision
        self.skip_key_storage = skip_key_storage
        self.debug_handover = debug_handover
        self.frame_count = 0
        self.error_count = 0
        
        # Crypto implementation (pluggable)
        self.crypto = crypto if crypto else NaiveCrypto()
        
        # Protocol state
        self.protocol_state = 0x00
        
        # ECDH state
        self.host_ephemeral_privkey = None
        self.host_ephemeral_pubkey_raw = None
        self.token_ecdh_share_received = None
        self.channel_challenge_received = None
        
        # Synchronization
        self.ecdh_complete_event = threading.Event()
        self.challenge_event = threading.Event()
        self.buffered_challenge = None
        self.token_pubkey_received_event = threading.Event()
        self.received_token_pubkey = None
        self.golden_hash_set_event = threading.Event()
        self.golden_hash_ack_received = None
        
        # Phase 2: Integrity verification
        self.integrity_challenge_event = threading.Event()
        self.received_nonce = None
        self.boot_ok_event = threading.Event()
        
        # Session management for re-attestation
        self.session_timeout = 30  # seconds (configurable)
        self.session_start_time = None
        self.watchdog_thread = None
        self.watchdog_running = False
        self.in_reattestation = False
        
        self.handler = SerialHandler(
            port=port,
            baudrate=baudrate,
            on_frame=self.on_frame_received,
            on_error=self.on_error,
            on_raw_data=None,
            crypto_handler=self.crypto  # Serial layer handles encryption/decryption automatically
        )
    
    # ========================================================================
    # FRAME RECEIVING AND ROUTING
    # ========================================================================
    
    def on_frame_received(self, frame: Frame):
        """
        Main frame handler - routes frames to appropriate handlers.
        Frames are already decrypted by the serial layer.
        """
        self.frame_count += 1
        
        payload = frame.payload
        
        # Handle debug messages
        if frame.msg_type == MessageType.DEBUG_MSG:
            self._handle_debug_message(payload)
            return
        
        # Handle protocol messages
        if frame.msg_type == MessageType.T2H_ECDH_SHARE:
            self._handle_ecdh_share(payload)
        
        elif frame.msg_type == MessageType.T2H_CHANNEL_VERIFY_REQUEST:
            self._handle_channel_verify_request(payload)
        
        elif frame.msg_type == MessageType.T2H_DEBUG_GET_TOKEN_PUBKEY:
            self._handle_token_pubkey_response(payload)
        
        elif frame.msg_type == MessageType.H2T_DEBUG_SET_GOLDEN_HASH:
            self._handle_golden_hash_ack(payload)
        
        elif frame.msg_type == MessageType.T2H_INTEGRITY_CHALLENGE:
            self._handle_integrity_challenge(payload)
        
        elif frame.msg_type == MessageType.T2H_BOOT_OK:
            self._handle_boot_ok(payload)
        
        elif frame.msg_type == MessageType.T2H_ECDH_SHARE:
            # Receiving T2H_ECDH_SHARE during runtime means re-attestation needed
            # This is handled by the debug handover loop or ignored in normal mode
            if self.verbose:
                Logger.warning("Received T2H_ECDH_SHARE during runtime (re-attestation signal)")
        
        elif frame.msg_type == MessageType.T2H_ERROR:
            self._handle_error(payload)
        
        elif frame.msg_type == MessageType.T2H_NACK:
            self._handle_nack(payload)
        
        else:
            if self.verbose:
                msg_name = get_message_name(frame.msg_type)
                print(f"\n[RX] {msg_name} (0x{frame.msg_type:02X}), {len(payload)} bytes")
    
    # ========================================================================
    # MESSAGE HANDLERS
    # ========================================================================
    
    def _handle_debug_message(self, payload: bytes) -> None:
        """Handle debug messages from token"""
        try:
            debug_text = payload.decode('utf-8', errors='replace')
            Logger.debug("TOKEN DEBUG", debug_text.rstrip())
        except Exception:
            Logger.debug("TOKEN DEBUG", f"(decode error): {payload.hex()}")
    
    def _handle_ecdh_share(self, payload: bytes) -> None:
        """Handle T2H_ECDH_SHARE (token ephemeral pubkey + signature)"""
        if len(payload) != 128:
            Logger.error(f"Invalid ECDH share length: {len(payload)} (expected 128)")
            return
        
        self.token_ecdh_share_received = payload
        self.ecdh_complete_event.set()
    
    def _handle_channel_verify_request(self, payload: bytes) -> None:
        """Handle T2H_CHANNEL_VERIFY_REQUEST (encrypted ping - already decrypted by serial layer)"""
        # Note: Protocol state was already set to 0x22 after deriving session key
        # Payload is already decrypted by serial layer
        if len(payload) >= 4 and payload[:4] == b"ping":
            self.channel_challenge_received = payload
            self.challenge_event.set()
        else:
            Logger.error(f"Invalid challenge payload: {payload!r}")
    
    def _handle_token_pubkey_response(self, payload: bytes) -> None:
        """Handle T2H_DEBUG_GET_TOKEN_PUBKEY response"""
        if len(payload) == 64:
            self.received_token_pubkey = payload
            self.token_pubkey_received_event.set()
            Logger.success(f"Received token public key: {payload[:32].hex()}...")
        else:
            Logger.error(f"Invalid token pubkey length: {len(payload)} (expected 64)")
    
    def _handle_golden_hash_ack(self, payload: bytes) -> None:
        """Handle H2T_DEBUG_SET_GOLDEN_HASH acknowledgment"""
        if len(payload) == 32:
            self.golden_hash_ack_received = payload
            self.golden_hash_set_event.set()
            Logger.success(f"Golden hash set confirmed: {payload[:16].hex()}...")
        else:
            Logger.error(f"Invalid golden hash ack length: {len(payload)} (expected 32)")
    
    def _handle_boot_ok(self, payload: bytes) -> None:
        """Handle T2H_BOOT_OK from token"""
        Logger.success("Token sent BOOT_OK - integrity verification passed!")
        self.boot_ok_event.set()
    
    
    def _handle_error(self, payload: bytes) -> None:
        """Handle T2H_ERROR"""
        if len(payload) >= 1:
            error_code = payload[0]
            error_msg = payload[1:].decode('utf-8', errors='replace') if len(payload) > 1 else ""
            Logger.tagged("TOKEN ERROR", Colors.RED, f"Code: 0x{error_code:02X}, Message: {error_msg}")
    
    def _handle_integrity_challenge(self, payload: bytes) -> None:
        """Handle T2H_INTEGRITY_CHALLENGE (nonce from token)"""
        if len(payload) == 4:
            self.received_nonce = payload
            self.integrity_challenge_event.set()
            Logger.tagged("INTEGRITY", Colors.CYAN, f"Received challenge nonce: {payload.hex()}")
        else:
            Logger.error(f"Invalid nonce length: {len(payload)} (expected 4)")
    
    def _handle_nack(self, payload: bytes) -> None:
        """Handle T2H_NACK"""
        if len(payload) >= 1:
            rejected_type = payload[0]
            reason = payload[1:].decode('utf-8', errors='replace') if len(payload) > 1 else ""
            rejected_name = get_message_name(rejected_type)
            Logger.tagged("TOKEN NACK", Colors.YELLOW, f"Rejected: {rejected_name}, Reason: {reason}")
    
    # ========================================================================
    # ERROR HANDLING
    # ========================================================================
    
    def on_error(self, error: Exception) -> None:
        """Handle protocol errors"""
        self.error_count += 1
        
        if isinstance(error, ChecksumError):
            Logger.tagged("ERROR", Colors.RED, f"Checksum validation failed - {error}")
        elif isinstance(error, ProtocolError):
            Logger.tagged("ERROR", Colors.RED, f"Protocol violation - {error}")
        elif isinstance(error, FrameParserError):
            Logger.tagged("ERROR", Colors.RED, f"Frame parsing error - {error}")
        else:
            Logger.tagged("ERROR", Colors.RED, f"{type(error).__name__}: {error}")
    
    # ========================================================================
    # PHASE 0: KEY PROVISIONING
    # ========================================================================
    
    def _load_or_generate_keys(self) -> bool:
        """Load permanent keys or generate them if they don't exist"""
        # If auto-provision flag is set, always regenerate and re-provision
        if self.auto_provision:
            Logger.info("Provision mode: Regenerating keypair...")
            if self.crypto.generate_permanent_keypair():
                host_pubkey = self.crypto.get_host_permanent_pubkey()
                Logger.success("Generated new host keypair")
                if host_pubkey:
                    Logger.substep(f"Host pubkey: {host_pubkey.hex()}")
                # Auto-provision: exchange keys with token
                return self._auto_provision_token_key()
            else:
                Logger.error("Failed to generate keys")
                return False
        
        # Normal mode: try to load existing keys
        if self.crypto.load_permanent_keys():
            host_pubkey = self.crypto.get_host_permanent_pubkey()
            Logger.success("Loaded permanent keys")
            if self.verbose and host_pubkey:
                Logger.substep(f"Host pubkey: {host_pubkey[:32].hex()}...")
            return True
        else:
            Logger.warning("Permanent keys not found!")
            print(f"Please run with --provision flag to generate and provision keys:")
            print(f"  python -m host.main {self.port} --provision")
            return False
    
    def _auto_provision_token_key(self) -> bool:
        """Request token public key automatically"""
        Logger.section("Auto-Provisioning Token Key")
        
        # Step 1: Send host pubkey to token
        Logger.step(1, "Sending host public key to token...")
        host_pubkey = self.crypto.get_host_permanent_pubkey()
        if not self.handler.send_frame(MessageType.H2T_DEBUG_SET_HOST_PUBKEY.value, host_pubkey):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send host pubkey")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Sent host pubkey")
        time.sleep(0.2)  # Give token time to process
        
        # Step 2: Request token pubkey
        Logger.step(2, "Requesting token public key...")
        if not self.handler.send_frame(MessageType.T2H_DEBUG_GET_TOKEN_PUBKEY.value, b''):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send request")
            return False
        
        # Step 3: Wait for response
        Logger.step(3, "Waiting for token public key (timeout: 5s)...")
        if not self.token_pubkey_received_event.wait(timeout=5.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for token pubkey")
            return False
        
        # Step 4: Save to file
        Logger.step(4, "Saving token public key...")
        try:
            with open('token_permanent_pubkey.bin', 'wb') as f:
                f.write(self.received_token_pubkey)
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Saved to token_permanent_pubkey.bin")
            
            # Reload keys
            if self.crypto.load_permanent_keys():
                Logger.success("Keys provisioned successfully!")
                
                # Step 5: Provision default golden hash
                if not self._provision_golden_hash():
                    Logger.error("Failed to provision golden hash")
                    return False
                
                return True
            else:
                Logger.error("Failed to reload keys")
                return False
        except Exception as e:
            Logger.error(f"Failed to save token pubkey: {e}")
            return False
    
    def _provision_golden_hash(self) -> bool:
        """Compute and provision default golden hash to token"""
        import hashlib
        
        Logger.section("Provisioning Golden Hash")
        
        # Step 1: Compute golden hash from default test data
        Logger.step(1, "Computing golden hash from default test data (2 bytes: 'h' + null)...")
        test_data = b"h\0"  # 2 bytes: 0x68 0x00
        golden_hash = hashlib.sha256(test_data).digest()
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Test data: {test_data.hex()} ({len(test_data)} bytes)")
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Golden hash: {golden_hash.hex()}")
        
        # Save golden hash to disk for future testing
        try:
            with open('golden_hash.bin', 'wb') as f:
                f.write(golden_hash)
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Saved to golden_hash.bin")
        except Exception as e:
            Logger.substep(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Could not save golden hash: {e}")
        
        # Step 2: Send golden hash to token
        Logger.step(2, "Sending golden hash to token...")
        if not self.handler.send_frame(MessageType.H2T_DEBUG_SET_GOLDEN_HASH.value, golden_hash):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send golden hash")
            return False
        
        # Step 3: Wait for acknowledgment
        Logger.step(3, "Waiting for acknowledgment (timeout: 5s)...")
        if not self.golden_hash_set_event.wait(timeout=5.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for ack")
            return False
        
        # Step 4: Verify the ack matches what we sent
        if self.golden_hash_ack_received != golden_hash:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Golden hash mismatch!")
            Logger.substep(f"   Sent:     {golden_hash.hex()}")
            Logger.substep(f"   Received: {self.golden_hash_ack_received.hex()}")
            return False
        
        Logger.success("Golden hash provisioned successfully!")
        return True
    
    # ========================================================================
    # PHASE 1: MUTUAL AUTHENTICATION (ECDH)
    # ========================================================================
    
    def _perform_ecdh_handshake(self) -> bool:
        """
        Execute Phase 1: ECDH Mutual Authentication
        
        Returns:
            True if handshake successful, False otherwise
        """
        Logger.section("Phase 1: Mutual Authentication (ECDH)")
        
        # Step 1: Generate ephemeral keypair
        Logger.step(1, "Generating ephemeral keypair...")
        self.host_ephemeral_pubkey_raw, self.host_ephemeral_privkey = self.crypto.generate_ephemeral_keypair()
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Ephemeral pubkey: {self.host_ephemeral_pubkey_raw[:32].hex()}...")
        
        # Step 2: Sign ephemeral pubkey
        Logger.step(2, "Signing ephemeral pubkey with permanent key...")
        signature_raw = self.crypto.sign_with_permanent_key(self.host_ephemeral_pubkey_raw)
        if signature_raw is None:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to sign")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Signature: {signature_raw[:32].hex()}...")
        
        # Step 3: Send H2T_ECDH_SHARE
        Logger.step(3, "Sending H2T_ECDH_SHARE...")
        payload = self.host_ephemeral_pubkey_raw + signature_raw
        if not self.handler.send_frame(MessageType.H2T_ECDH_SHARE.value, payload):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Sent {len(payload)} bytes")
        self.protocol_state = 0x20
        
        # Step 4: Wait for T2H_ECDH_SHARE
        Logger.step(4, "Waiting for T2H_ECDH_SHARE (timeout: 10s)...")
        if not self.ecdh_complete_event.wait(timeout=10.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for token response")
            return False
        
        # Step 5: Verify token's signature
        Logger.step(5, "Verifying token's signature...")
        token_eph_pubkey = self.token_ecdh_share_received[:64]
        token_signature = self.token_ecdh_share_received[64:]
        
        if not self.crypto.verify_signature(token_eph_pubkey, token_signature,
                                           self.crypto.token_permanent_pubkey_raw):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Signature verification failed")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Token signature verified")
        
        # Step 6: Compute shared secret
        Logger.step(6, "Computing ECDH shared secret...")
        shared_secret = self.crypto.compute_shared_secret(self.host_ephemeral_privkey, token_eph_pubkey)
        if shared_secret is None:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to compute shared secret")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Shared secret: {shared_secret.hex()}")
        
        # Step 7: Derive session key
        Logger.step(7, "Deriving AES session key (HKDF-SHA256)...")
        session_key = self.crypto.derive_session_key(shared_secret)
        if session_key is None:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to derive session key")
            return False
        
        # Don't set session key yet - keep using old key for ECDH
        # Will switch to new key right before ping/pong
        self.derived_session_key = session_key  # Store for later
        self.protocol_state = 0x22
        
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Session key: {session_key.hex()}")
        
        return True
    
    # ========================================================================
    # PHASE 1.5: CHANNEL VERIFICATION
    # ========================================================================
    
    def _perform_channel_verification(self, step_offset: int = 0) -> bool:
        """
        Execute channel verification (encrypted ping/pong)
        
        Args:
            step_offset: Starting step number for logging
        
        Returns:
            True if verification successful, False otherwise
        """
        if step_offset == 0:
            Logger.section("Channel Verification")
        
        # CRITICAL: Switch to new session key RIGHT BEFORE ping/pong
        # (ECDH messages were encrypted with old key, ping/pong uses new key)
        if hasattr(self, 'derived_session_key'):
            Logger.info(f"Switching to new session key: {self.derived_session_key.hex()}")
            self.crypto.set_session_key(self.derived_session_key)
            self.crypto.set_encryption_enabled(True)
            delattr(self, 'derived_session_key')  # Clean up
        
        step_num = 8 + step_offset
        
        # Wait for encrypted ping challenge
        Logger.step(step_num, "Waiting for encrypted ping challenge (timeout: 5s)...")
        if not self.challenge_event.wait(timeout=5.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for challenge")
            return False
        
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Received challenge: {self.channel_challenge_received!r}")
        
        # Send pong response (will be encrypted automatically by serial layer)
        Logger.step(9, "Sending pong response (will be encrypted automatically)...")
        pong_payload = b"pong"
        
        if not self.handler.send_frame(MessageType.H2T_CHANNEL_VERIFY_RESPONSE.value, pong_payload):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send response")
            return False
        
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Pong sent")
        
        # Update state to "established" (encryption remains enabled)
        self.protocol_state = 0x24
        
        return True
    # ========================================================================
    # PHASE 2: INTEGRITY VERIFICATION
    # ========================================================================
    
    def _perform_integrity_verification(self) -> bool:
        """
        Execute Phase 2: Integrity Verification
        
        Returns:
            True if verification successful, False otherwise
        """
        import hashlib
        
        Logger.section("Phase 2: Integrity Verification")
        
        # Wait for integrity challenge from token
        Logger.step(10, "Waiting for integrity challenge (timeout: 10s)...")
        if not self.integrity_challenge_event.wait(timeout=10.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for challenge")
            return False
        
        nonce = self.received_nonce
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Received nonce: {nonce.hex()}")
        
        # Load the golden hash we provisioned
        Logger.step(11, "Loading golden hash...")
        try:
            with open('golden_hash.bin', 'rb') as f:
                golden_hash = f.read()
            if len(golden_hash) != 32:
                Logger.substep(f"{Colors.RED}✗{Colors.RESET} Invalid golden hash length: {len(golden_hash)}")
                return False
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Golden hash: {golden_hash[:16].hex()}...")
        except FileNotFoundError:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Golden hash file not found. Run with --provision first.")
            return False
        except Exception as e:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Error loading golden hash: {e}")
            return False
        
        # Combine hash + nonce for signing
        Logger.step(12, "Preparing integrity response...")
        message_to_sign = golden_hash + nonce
        Logger.substep(f"Message to sign: hash + nonce ({len(message_to_sign)} bytes)")
        
        # Sign with permanent private key
        Logger.step(13, "Signing with permanent key...")
        signature = self.crypto.sign_with_permanent_key(message_to_sign)
        if signature is None:
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to sign")
            return False
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Signature: {signature[:32].hex()}...")
        
        # Send H2T_INTEGRITY_RESPONSE
        Logger.step(14, "Sending integrity response (will be encrypted automatically)...")
        payload = golden_hash + signature
        
        if not self.handler.send_frame(MessageType.H2T_INTEGRITY_RESPONSE.value, payload):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send response")
            return False
        
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Sent {len(payload)} bytes (hash + signature)")
        
        # Update state to waiting for BOOT_OK
        self.protocol_state = 0x31
        
        # Wait for BOOT_OK from token
        Logger.step(15, "Waiting for BOOT_OK from token (timeout: 10s)...")
        if not self.boot_ok_event.wait(timeout=10.0):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Timeout waiting for BOOT_OK")
            return False
        
        # Send acknowledgment
        Logger.step(16, "Sending BOOT_OK acknowledgment...")
        if not self.handler.send_frame(MessageType.H2T_BOOT_OK_ACK.value, b''):
            Logger.substep(f"{Colors.RED}✗{Colors.RESET} Failed to send ACK")
            return False
        
        Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} BOOT_OK ACK sent")
        
        # Update state to complete
        self.protocol_state = 0x34
        
        return True
    
    # ========================================================================
    # SESSION KEY STORAGE FOR RUNTIME
    # ========================================================================
    
    def _store_session_key_for_runtime(self) -> bool:
        """
        Store session key in kernel keyring for runtime phase.
        
        The runtime heartbeat daemon will retrieve this key to maintain
        encrypted communication after initramfs exits and system boots.
        
        Uses kernel keyring only (TPM2 removed per requirements).
        
        Returns:
            True if stored successfully, False otherwise
        """
        Logger.section("Storing Session Key for Runtime")
        
        session_key = self.crypto.get_session_key()
        if not session_key:
            Logger.error("No session key available")
            return False
        
        if len(session_key) != 16:
            Logger.error(f"Invalid session key length: {len(session_key)} bytes")
            return False
        
        Logger.info(f"Session key to store: {session_key.hex()}")
        
        # Use kernel keyring only
        from .keyring_storage import KeyringStorage
        storage = KeyringStorage()
        
        if not storage.is_available():
            Logger.error("Kernel keyring not available")
            Logger.error("Cannot store session key for runtime phase!")
            return False
        
        if storage.store_session_key(session_key):
            Logger.success("Session key stored in kernel keyring")
            Logger.info("Runtime heartbeat daemon will retrieve this key")
            return True
    
    # ========================================================================
    # SESSION WATCHDOG & RE-ATTESTATION
    # ========================================================================
    
    def _start_session_watchdog(self) -> None:
        """
        Start background watchdog thread for session timeout monitoring.
        Watchdog checks every second if session has timed out.
        """
        Logger.info("Starting session watchdog thread")
        self.watchdog_running = True
        self.watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            daemon=True,
            name="SessionWatchdog"
        )
        self.watchdog_thread.start()
    
    def _stop_session_watchdog(self) -> None:
        """Stop the session watchdog thread"""
        if self.watchdog_running:
            Logger.info("Stopping session watchdog")
            self.watchdog_running = False
            if self.watchdog_thread:
                self.watchdog_thread.join(timeout=2.0)
    
    def _watchdog_loop(self) -> None:
        """
        Background watchdog loop - monitors session timeout.
        Runs every second checking if session has expired.
        """
        while self.watchdog_running:
            time.sleep(1)  # Check every second
            
            # Skip if no active session
            if self.session_start_time is None:
                continue
            
            # Skip if already in re-attestation
            if self.in_reattestation:
                continue
                
            # Check if session has timed out
            elapsed = time.time() - self.session_start_time
            
            if elapsed >= self.session_timeout:
                Logger.warning(
                    f"Session timeout ({self.session_timeout}s elapsed) - "
                    f"triggering re-attestation"
                )
                self._trigger_reattestation()
    
    def _trigger_reattestation(self) -> None:
        """
        Trigger re-attestation cycle.
        Invalidates current session and performs full ECDH + integrity verification.
        """
        if self.in_reattestation:
            Logger.warning("Re-attestation already in progress")
            return
        
        self.in_reattestation = True
        
        try:
            Logger.section("Re-Attestation Cycle")
            
            # Step 1: Invalidate current session
            Logger.step(1, "Invalidating current session")
            self.session_start_time = None
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Session invalidated")
            
            # Note: Keep is_encrypted = True to maintain encryption during re-attestation
            # The token will also keep encryption enabled with old key until new one derived
            
            # Step 2: Perform new ECDH handshake
            Logger.step(2, "Performing ECDH handshake")
            if not self._perform_ecdh_handshake():
                Logger.error("Re-attestation ECDH failed")
                self.in_reattestation = False
                return
            
            # Step 3: Perform channel verification
            Logger.step(3, "Verifying encrypted channel")
            if not self._perform_channel_verification():
                Logger.error("Re-attestation channel verification failed")
                self.in_reattestation = False
                return
            
            # Step 4: Perform integrity verification
            Logger.step(4, "Verifying host integrity")
            if not self._perform_integrity_verification():
                Logger.error("Re-attestation integrity check failed")
                self.in_reattestation = False
                return
            
            # Step 5: Restart session timer
            self.session_start_time = time.time()
            Logger.success(f"Re-attestation complete - new session established (timeout: {self.session_timeout}s)")
            
        finally:
            self.in_reattestation = False
    
    def _debug_handover_loop(self) -> int:
        """
        Debug handover to runtime_heartbeat service.
        
        Simulates systemd handing off from attestation to runtime service.
        """
        Logger.section("Debug Handover to Runtime")
        Logger.info("Simulating initramfs->systemd handover")
        Logger.info("Waiting 3 seconds...")
        time.sleep(3)
        
        # Stop watchdog and disconnect our handler
        self._stop_session_watchdog()
        self.handler.stop()
        self.handler.disconnect()
        
        # Launch runtime heartbeat as subprocess (like systemd would)
        Logger.info("Launching runtime heartbeat service...")
        Logger.info("Command: python -m host.runtime_heartbeat /dev/ttyACM0 --debug-no-shutdown")
        
        import subprocess
        result = subprocess.run(
            [sys.executable, '-m', 'host.runtime_heartbeat', self.port,
             '--interval', '5',
             '--timeout', '3',
             '--no-lkrg',
             '--debug-no-shutdown']
        )
        
        Logger.info(f"Runtime heartbeat exited with code {result.returncode}")
        return result.returncode
    
    # ========================================================================
    # MAIN PROTOCOL EXECUTION
    # ========================================================================
    
    def run(self) -> int:
        """
        Run the MASTR host protocol.
        
        Returns:
            Exit code (0 = success)
        """
        Logger.header("MASTR Host - Production Protocol Implementation")
        print(f"Port: {self.port}")
        print(f"Crypto: {type(self.crypto).__name__}")
        
        # Connect to serial port first
        Logger.section("Connecting to Token")
        if not self.handler.connect():
            Logger.tagged("ERROR", Colors.RED, f"Failed to connect to {self.port}")
            return 1
        
        Logger.success(f"Connected to {self.port}")
        self.handler.start()
        
        # Give token time to boot
        time.sleep(0.5)
        
        # Step 0: Load permanent keys
        Logger.section("Phase 0: Key Loading")
        keys_loaded = self._load_or_generate_keys()
        if not keys_loaded:
            self.handler.stop()
            self.handler.disconnect()
            return 1
        
        try:
            # Phase 1: ECDH Mutual Authentication
            if not self._perform_ecdh_handshake():
                print(f"\n{Colors.RED}✗ ECDH handshake failed{Colors.RESET}")
                return 1
            
            # Channel Verification
            if not self._perform_channel_verification():
                print(f"\n{Colors.RED}✗ Channel verification failed{Colors.RESET}")
                return 1
            
            # Channel established!
            Logger.success_header("✅ Secure channel established!")
            print(f"Protocol state: 0x{self.protocol_state:02X}")
            print(f"Session key: {self.crypto.get_session_key().hex()}")
            
            # Phase 2: Integrity Verification
            if not self._perform_integrity_verification():
                print(f"\n{Colors.RED}✗ Integrity verification failed{Colors.RESET}")
                return 1
            
            # Success!
            Logger.success_header("✅ Integrity verification complete!")
            
            # Start session timer and watchdog
            self.session_start_time = time.time()
            self._start_session_watchdog()
            Logger.info(f"Session established with {self.session_timeout}s timeout")
            
            # Store session key for runtime phase (unless skipped for testing)
            if not self.skip_key_storage:
                if not self._store_session_key_for_runtime():
                    Logger.error("Failed to store session key for runtime")
                    return 1
                
                # Check if debug handover mode is enabled
                if self.debug_handover:
                    Logger.section("Debug Handover Simulation")
                    Logger.info("Simulating initramfs->systemd handover")
                    
                    # Run re-attestation loop to simulate systemd restart behavior
                    return self._debug_handover_loop()
                else:
                    # Normal mode: Exit cleanly - initramfs will continue boot
                    Logger.info("Protocol phases complete - exiting for boot continuation")
                    Logger.info("Runtime heartbeat will be started by systemd")
            else:
                Logger.warning("Skipping key storage (testing mode)")
                Logger.info("Keeping connection open for testing...")
                Logger.info("Press Ctrl+C to exit")
                
                # Keep connection open for testing
                while self.handler.is_connected and self.handler._running:
                    time.sleep(0.1)
            
            return 0
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
        
        finally:
            self._stop_session_watchdog()
            self.handler.stop()
            self.handler.disconnect()
            
            Logger.tagged("Statistics", Colors.CYAN, "")
            print(f"  Frames received: {self.frame_count}")
            print(f"  Errors: {self.error_count}")
        
        return 0


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """
    Main entry point for the MASTR host application.
    
    Usage:
        python -m host.main /dev/ttyACM0                    # Use existing keys
        python -m host.main /dev/ttyACM0 --provision        # Auto-provision keys
        python -m host.main /dev/ttyACM0 --crypto=tpm2      # Use TPM2 backend
        python -m host.main /dev/ttyACM0 -v                 # Verbose mode
    """
    
    parser = argparse.ArgumentParser(
        description='MASTR Host - Full protocol implementation with pluggable crypto'
    )
    parser.add_argument(
        'port',
        help='Serial port to connect to (e.g., /dev/ttyACM0, COM3)'
    )
    parser.add_argument(
        '-b', '--baudrate',
        type=int,
        default=115200,
        help='Serial baud rate (default: 115200)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--crypto',
        choices=['naive', 'tpm2'],
        default='naive',
        help='Crypto implementation (default: naive)'
    )
    parser.add_argument(
        '--provision',
        action='store_true',
        help='Automatically provision token keys and golden hash'
    )
    parser.add_argument(
        '--skip-key-storage',
        action='store_true',
        help='Skip storing session key for runtime (testing only)'
    )
    parser.add_argument(
        '--debug-handover',
        action='store_true',
        help='Simulate initramfs->systemd handover (testing only)'
    )
    
    args = parser.parse_args()
    
    # ========================================================================
    # Select Crypto Backend
    # ========================================================================
    # This is where you choose which cryptographic implementation to use.
    # Simply instantiate the desired backend class that implements CryptoInterface.
    #
    # Available backends:
    #   - NaiveCrypto: File-based key storage (development/testing)
    #   - TPM2Crypto: TPM2-based secure storage (production) ✓ IMPLEMENTED
    #
    # To add a new backend:
    #   1. Create a new class implementing CryptoInterface
    #   2. Add it to the choices list above
    #   3. Add instantiation code below
    # ========================================================================
    
    if args.crypto == 'naive':
        crypto = NaiveCrypto()
    elif args.crypto == 'tpm2':
        try:
            crypto = TPM2Crypto()
        except Exception as e:
            Logger.error(f"Failed to initialize TPM2 crypto: {e}")
            return 1
    else:
        Logger.error(f"Unknown crypto implementation: {args.crypto}")
        return 1
    
    host = MASTRHost(
        port=args.port,
        baudrate=args.baudrate,
        crypto=crypto,
        verbose=args.verbose,
        auto_provision=args.provision,
        skip_key_storage=args.skip_key_storage,
        debug_handover=args.debug_handover
    )
    
    return host.run()


if __name__ == '__main__':
    sys.exit(main())
