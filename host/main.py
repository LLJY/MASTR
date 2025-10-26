"""
MASTR Host - Production Protocol Implementation

This is the main entry point for the MASTR protocol. It implements the complete
protocol state machine with pluggable cryptographic backends.

CRYPTO BACKENDS:
  - NaiveCrypto: File-based key storage (development/testing)
  - TPM2Crypto: TPM2-based secure storage (production) [TODO]

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
import argparse
import time
import threading
from typing import Optional

from .serial_handler import SerialHandler
from .protocol import Frame, MessageType, get_message_name
from .parser import FrameParserError, ChecksumError, ProtocolError
from .crypto import NaiveCrypto
from .crypto_interface import CryptoInterface


# ANSI Color Codes
class Colors:
    """ANSI escape codes for terminal colors"""
    RESET = '\033[0m'
    ORANGE = '\033[38;5;214m'
    GREEN = '\033[38;5;46m'
    RED = '\033[38;5;196m'
    YELLOW = '\033[38;5;208m'
    CYAN = '\033[38;5;51m'
    MAGENTA = '\033[38;5;201m'


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
    
    def __init__(self, port: str, baudrate: int = 115200, crypto: Optional[CryptoInterface] = None, verbose: bool = False, auto_provision: bool = False):
        """
        Initialize the MASTR host.
        
        Args:
            port: Serial port to connect to
            baudrate: Serial baud rate
            crypto: Crypto implementation (defaults to NaiveCrypto)
            verbose: Enable verbose output
            auto_provision: Automatically provision keys and golden hash if True
        """
        self.port = port
        self.baudrate = baudrate
        self.verbose = verbose
        self.auto_provision = auto_provision
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
    
    def _handle_debug_message(self, payload: bytes):
        """Handle debug messages from token"""
        try:
            debug_text = payload.decode('utf-8', errors='replace')
            print(f"{Colors.ORANGE}[TOKEN DEBUG]{Colors.RESET} {debug_text}", end='')
        except Exception:
            print(f"{Colors.ORANGE}[TOKEN DEBUG]{Colors.RESET} (decode error): {payload.hex()}")
    
    def _handle_ecdh_share(self, payload: bytes):
        """Handle T2H_ECDH_SHARE (token ephemeral pubkey + signature)"""
        if len(payload) != 128:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid ECDH share length: {len(payload)} (expected 128)")
            return
        
        self.token_ecdh_share_received = payload
        self.ecdh_complete_event.set()
    
    def _handle_channel_verify_request(self, payload: bytes):
        """Handle T2H_CHANNEL_VERIFY_REQUEST (encrypted ping - already decrypted by serial layer)"""
        # Note: Protocol state was already set to 0x22 after deriving session key
        # Payload is already decrypted by serial layer
        if len(payload) >= 4 and payload[:4] == b"ping":
            self.channel_challenge_received = payload
            self.challenge_event.set()
        else:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid challenge payload: {payload!r}")
    
    def _handle_token_pubkey_response(self, payload: bytes):
        """Handle T2H_DEBUG_GET_TOKEN_PUBKEY response"""
        if len(payload) == 64:
            self.received_token_pubkey = payload
            self.token_pubkey_received_event.set()
            print(f"{Colors.GREEN}✓{Colors.RESET} Received token public key: {payload[:32].hex()}...")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid token pubkey length: {len(payload)} (expected 64)")
    
    def _handle_golden_hash_ack(self, payload: bytes):
        """Handle H2T_DEBUG_SET_GOLDEN_HASH acknowledgment"""
        if len(payload) == 32:
            self.golden_hash_ack_received = payload
            self.golden_hash_set_event.set()
            print(f"{Colors.GREEN}✓{Colors.RESET} Golden hash set confirmed: {payload[:16].hex()}...")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid golden hash ack length: {len(payload)} (expected 32)")
    def _handle_boot_ok(self, payload: bytes):
        """Handle T2H_BOOT_OK from token"""
        print(f"{Colors.GREEN}✓{Colors.RESET} Token sent BOOT_OK - integrity verification passed!")
        self.boot_ok_event.set()
    
    
    def _handle_error(self, payload: bytes):
        """Handle T2H_ERROR"""
        if len(payload) >= 1:
            error_code = payload[0]
            error_msg = payload[1:].decode('utf-8', errors='replace') if len(payload) > 1 else ""
            print(f"{Colors.RED}[TOKEN ERROR]{Colors.RESET} Code: 0x{error_code:02X}, Message: {error_msg}")
    
    def _handle_integrity_challenge(self, payload: bytes):
        """Handle T2H_INTEGRITY_CHALLENGE (nonce from token)"""
        if len(payload) == 4:
            self.received_nonce = payload
            self.integrity_challenge_event.set()
            print(f"{Colors.CYAN}[INTEGRITY]{Colors.RESET} Received challenge nonce: {payload.hex()}")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid nonce length: {len(payload)} (expected 4)")
    
    def _handle_nack(self, payload: bytes):
        """Handle T2H_NACK"""
        if len(payload) >= 1:
            rejected_type = payload[0]
            reason = payload[1:].decode('utf-8', errors='replace') if len(payload) > 1 else ""
            rejected_name = get_message_name(rejected_type)
            print(f"{Colors.YELLOW}[TOKEN NACK]{Colors.RESET} Rejected: {rejected_name}, Reason: {reason}")
    
    # ========================================================================
    # ERROR HANDLING
    # ========================================================================
    
    def on_error(self, error: Exception):
        """Handle protocol errors"""
        self.error_count += 1
        
        if isinstance(error, ChecksumError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Checksum validation failed - {error}", file=sys.stderr)
        elif isinstance(error, ProtocolError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Protocol violation - {error}", file=sys.stderr)
        elif isinstance(error, FrameParserError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Frame parsing error - {error}", file=sys.stderr)
        else:
            print(f"{Colors.RED}ERROR:{Colors.RESET} {type(error).__name__}: {error}", file=sys.stderr)
    
    # ========================================================================
    # PHASE 0: KEY PROVISIONING
    # ========================================================================
    
    def _load_or_generate_keys(self) -> bool:
        """Load permanent keys or generate them if they don't exist"""
        # If auto-provision flag is set, always regenerate and re-provision
        if self.auto_provision:
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Provision mode: Regenerating keypair...")
            if self.crypto.generate_permanent_keypair():
                host_pubkey = self.crypto.get_host_permanent_pubkey()
                print(f"{Colors.GREEN}✓{Colors.RESET} Generated new host keypair")
                if host_pubkey:
                    print(f"  Host pubkey: {host_pubkey.hex()}")
                # Auto-provision: exchange keys with token
                return self._auto_provision_token_key()
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to generate keys")
                return False
        
        # Normal mode: try to load existing keys
        if self.crypto.load_permanent_keys():
            host_pubkey = self.crypto.get_host_permanent_pubkey()
            print(f"{Colors.GREEN}✓{Colors.RESET} Loaded permanent keys")
            if self.verbose and host_pubkey:
                print(f"  Host pubkey: {host_pubkey[:32].hex()}...")
            return True
        else:
            print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Permanent keys not found!")
            print(f"Please run with --provision flag to generate and provision keys:")
            print(f"  python -m host.main {self.port} --provision")
            return False
    
    def _auto_provision_token_key(self) -> bool:
        """Request token public key automatically"""
        print(f"\n{Colors.CYAN}=== Auto-Provisioning Token Key ==={Colors.RESET}")
        
        # Step 1: Send host pubkey to token
        print(f"1. Sending host public key to token...")
        host_pubkey = self.crypto.get_host_permanent_pubkey()
        if not self.handler.send_frame(MessageType.H2T_DEBUG_SET_HOST_PUBKEY.value, host_pubkey):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send host pubkey")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Sent host pubkey")
        time.sleep(0.2)  # Give token time to process
        
        # Step 2: Request token pubkey (send T2H_DEBUG_GET_TOKEN_PUBKEY with empty payload as request)
        print(f"2. Requesting token public key...")
        if not self.handler.send_frame(MessageType.T2H_DEBUG_GET_TOKEN_PUBKEY.value, b''):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send request")
            return False
        
        # Step 3: Wait for response
        print(f"3. Waiting for token public key (timeout: 5s)...")
        if not self.token_pubkey_received_event.wait(timeout=5.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for token pubkey")
            return False
        
        # Step 4: Save to file
        print(f"4. Saving token public key...")
        try:
            with open('token_permanent_pubkey.bin', 'wb') as f:
                f.write(self.received_token_pubkey)
            print(f"   {Colors.GREEN}✓{Colors.RESET} Saved to token_permanent_pubkey.bin")
            
            # Reload keys
            if self.crypto.load_permanent_keys():
                print(f"{Colors.GREEN}✓{Colors.RESET} Keys provisioned successfully!")
                
                # Step 5: Provision default golden hash
                if not self._provision_golden_hash():
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to provision golden hash")
                    return False
                
                return True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to reload keys")
                return False
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to save token pubkey: {e}")
            return False
    
    def _provision_golden_hash(self) -> bool:
        """Compute and provision default golden hash to token"""
        import hashlib
        
        print(f"\n{Colors.CYAN}=== Provisioning Golden Hash ==={Colors.RESET}")
        
        # Step 1: Compute golden hash from default test data: 2 bytes = 'h' + null terminator
        print(f"1. Computing golden hash from default test data (2 bytes: 'h' + null)...")
        test_data = b"h\0"  # 2 bytes: 0x68 0x00
        golden_hash = hashlib.sha256(test_data).digest()
        print(f"   {Colors.GREEN}✓{Colors.RESET} Test data: {test_data.hex()} ({len(test_data)} bytes)")
        print(f"   {Colors.GREEN}✓{Colors.RESET} Golden hash: {golden_hash.hex()}")
        
        # Save golden hash to disk for future testing
        try:
            with open('golden_hash.bin', 'wb') as f:
                f.write(golden_hash)
            print(f"   {Colors.GREEN}✓{Colors.RESET} Saved to golden_hash.bin")
        except Exception as e:
            print(f"   {Colors.YELLOW}[WARNING]{Colors.RESET} Could not save golden hash: {e}")
        
        # Step 2: Send golden hash to token
        print(f"2. Sending golden hash to token...")
        if not self.handler.send_frame(MessageType.H2T_DEBUG_SET_GOLDEN_HASH.value, golden_hash):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send golden hash")
            return False
        
        # Step 3: Wait for acknowledgment
        print(f"3. Waiting for acknowledgment (timeout: 5s)...")
        if not self.golden_hash_set_event.wait(timeout=5.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for ack")
            return False
        
        # Step 4: Verify the ack matches what we sent
        if self.golden_hash_ack_received != golden_hash:
            print(f"   {Colors.RED}✗{Colors.RESET} Golden hash mismatch!")
            print(f"      Sent:     {golden_hash.hex()}")
            print(f"      Received: {self.golden_hash_ack_received.hex()}")
            return False
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Golden hash provisioned successfully!")
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
        print(f"\n{Colors.CYAN}=== Phase 1: Mutual Authentication (ECDH) ==={Colors.RESET}")
        
        # Step 1: Generate ephemeral keypair
        print(f"\n1. Generating ephemeral keypair...")
        self.host_ephemeral_pubkey_raw, self.host_ephemeral_privkey = self.crypto.generate_ephemeral_keypair()
        print(f"   {Colors.GREEN}✓{Colors.RESET} Ephemeral pubkey: {self.host_ephemeral_pubkey_raw[:32].hex()}...")
        
        # Step 2: Sign ephemeral pubkey
        print(f"\n2. Signing ephemeral pubkey with permanent key...")
        signature_raw = self.crypto.sign_with_permanent_key(self.host_ephemeral_pubkey_raw)
        if signature_raw is None:
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to sign")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Signature: {signature_raw[:32].hex()}...")
        
        # Step 3: Send H2T_ECDH_SHARE
        print(f"\n3. Sending H2T_ECDH_SHARE...")
        payload = self.host_ephemeral_pubkey_raw + signature_raw
        if not self.handler.send_frame(MessageType.H2T_ECDH_SHARE.value, payload):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Sent {len(payload)} bytes")
        self.protocol_state = 0x20
        
        # Step 4: Wait for T2H_ECDH_SHARE
        print(f"\n4. Waiting for T2H_ECDH_SHARE (timeout: 10s)...")
        if not self.ecdh_complete_event.wait(timeout=10.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for token response")
            return False
        
        # Step 5: Verify token's signature
        print(f"\n5. Verifying token's signature...")
        token_eph_pubkey = self.token_ecdh_share_received[:64]
        token_signature = self.token_ecdh_share_received[64:]
        
        if not self.crypto.verify_signature(token_eph_pubkey, token_signature, 
                                           self.crypto.token_permanent_pubkey_raw):
            print(f"   {Colors.RED}✗{Colors.RESET} Signature verification failed")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Token signature verified")
        
        # Step 6: Compute shared secret
        print(f"\n6. Computing ECDH shared secret...")
        shared_secret = self.crypto.compute_shared_secret(self.host_ephemeral_privkey, token_eph_pubkey)
        if shared_secret is None:
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to compute shared secret")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Shared secret: {shared_secret.hex()}")
        
        # Step 7: Derive session key
        print(f"\n7. Deriving AES session key (HKDF-SHA256)...")
        session_key = self.crypto.derive_session_key(shared_secret)
        if session_key is None:
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to derive session key")
            return False
        
        self.crypto.set_session_key(session_key)
        
        # Enable encryption now that we have a session key
        self.crypto.set_encryption_enabled(True)
        self.protocol_state = 0x22
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} Session key: {session_key.hex()}")
        
        return True
    
    # ========================================================================
    # PHASE 1.5: CHANNEL VERIFICATION
    # ========================================================================
    
    def _perform_channel_verification(self) -> bool:
        """
        Execute channel verification (encrypted ping/pong)
        
        Returns:
            True if verification successful, False otherwise
        """
        print(f"\n{Colors.CYAN}=== Channel Verification ==={Colors.RESET}")
        
        # Wait for encrypted ping challenge
        print(f"\n8. Waiting for encrypted ping challenge (timeout: 5s)...")
        if not self.challenge_event.wait(timeout=5.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for challenge")
            return False
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} Received challenge: {self.channel_challenge_received!r}")
        
        # Send pong response (will be encrypted automatically by serial layer)
        print(f"\n9. Sending pong response (will be encrypted automatically)...")
        pong_payload = b"pong"
        
        if not self.handler.send_frame(MessageType.H2T_CHANNEL_VERIFY_RESPONSE.value, pong_payload):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send response")
            return False
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} Pong sent")
        
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
        
        print(f"\n{Colors.CYAN}=== Phase 2: Integrity Verification ==={Colors.RESET}")
        
        # Wait for integrity challenge from token
        print(f"\n10. Waiting for integrity challenge (timeout: 10s)...")
        if not self.integrity_challenge_event.wait(timeout=10.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for challenge")
            return False
        
        nonce = self.received_nonce
        print(f"   {Colors.GREEN}✓{Colors.RESET} Received nonce: {nonce.hex()}")
        
        # Load the golden hash we provisioned
        print(f"\n11. Loading golden hash...")
        try:
            with open('golden_hash.bin', 'rb') as f:
                golden_hash = f.read()
            if len(golden_hash) != 32:
                print(f"   {Colors.RED}✗{Colors.RESET} Invalid golden hash length: {len(golden_hash)}")
                return False
            print(f"   {Colors.GREEN}✓{Colors.RESET} Golden hash: {golden_hash[:16].hex()}...")
        except FileNotFoundError:
            print(f"   {Colors.RED}✗{Colors.RESET} Golden hash file not found. Run with --provision first.")
            return False
        except Exception as e:
            print(f"   {Colors.RED}✗{Colors.RESET} Error loading golden hash: {e}")
            return False
        
        # Combine hash + nonce for signing
        print(f"\n12. Preparing integrity response...")
        message_to_sign = golden_hash + nonce
        print(f"   Message to sign: hash + nonce ({len(message_to_sign)} bytes)")
        
        # Sign with permanent private key
        print(f"\n13. Signing with permanent key...")
        signature = self.crypto.sign_with_permanent_key(message_to_sign)
        if signature is None:
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to sign")
            return False
        print(f"   {Colors.GREEN}✓{Colors.RESET} Signature: {signature[:32].hex()}...")
        
        # Send H2T_INTEGRITY_RESPONSE: hash (32) + signature (64) = 96 bytes
        # Serial layer will encrypt automatically since protocol state >= 0x22
        print(f"\n14. Sending integrity response (will be encrypted automatically)...")
        payload = golden_hash + signature
        
        if not self.handler.send_frame(MessageType.H2T_INTEGRITY_RESPONSE.value, payload):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send response")
            return False
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} Sent {len(payload)} bytes (hash + signature)")
        
        # Update state to waiting for BOOT_OK
        self.protocol_state = 0x31
        
        # Wait for BOOT_OK from token
        print(f"\n15. Waiting for BOOT_OK from token (timeout: 10s)...")
        if not self.boot_ok_event.wait(timeout=10.0):
            print(f"   {Colors.RED}✗{Colors.RESET} Timeout waiting for BOOT_OK")
            return False
        
        # Send acknowledgment (will be encrypted automatically by serial layer)
        print(f"\n16. Sending BOOT_OK acknowledgment...")
        if not self.handler.send_frame(MessageType.H2T_BOOT_OK_ACK.value, b''):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send ACK")
            return False
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} BOOT_OK ACK sent")
        
        # Update state to complete
        self.protocol_state = 0x34
        
        return True
    
    
    # ========================================================================
    # MAIN PROTOCOL EXECUTION
    # ========================================================================
    
    def run(self):
        """
        Run the MASTR host protocol.
        
        Returns:
            Exit code (0 = success)
        """
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}MASTR Host - Production Protocol Implementation{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Port: {self.port}")
        print(f"Crypto: {type(self.crypto).__name__}")
        
        # Connect to serial port first
        print(f"\n{Colors.CYAN}=== Connecting to Token ==={Colors.RESET}")
        if not self.handler.connect():
            print(f"{Colors.RED}ERROR:{Colors.RESET} Failed to connect to {self.port}")
            return 1
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Connected to {self.port}")
        self.handler.start()
        
        # Give token time to boot
        time.sleep(0.5)
        
        # Step 0: Load permanent keys (now that we're connected)
        print(f"\n{Colors.CYAN}=== Phase 0: Key Loading ==={Colors.RESET}")
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
            print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Secure channel established!{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"Protocol state: 0x{self.protocol_state:02X}")
            print(f"Session key: {self.crypto.get_session_key().hex()}")
            
            # Phase 2: Integrity Verification
            if not self._perform_integrity_verification():
                print(f"\n{Colors.RED}✗ Integrity verification failed{Colors.RESET}")
                return 1
            
            # Success!
            print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Integrity verification complete!{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            
            # ================================================================
            # TODO: Phase 3 - Runtime Heartbeat
            # ================================================================
            # When implementing Phase 3, add:
            #   1. _handle_heartbeat_ack() handler
            #   2. _send_heartbeat() method called periodically
            #   3. Add case for T2H_HEARTBEAT_ACK in on_frame_received()
            #   4. Watchdog timer to detect missed heartbeats
            #
            # heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
            # heartbeat_thread.start()
            
            print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Keeping connection open...")
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Press Ctrl+C to exit")
            
            # Keep connection open
            while self.handler.is_connected and self.handler._running:
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
        
        finally:
            self.handler.stop()
            self.handler.disconnect()
            
            print(f"\n{Colors.CYAN}Statistics:{Colors.RESET}")
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
    
    args = parser.parse_args()
    
    # ========================================================================
    # Select Crypto Backend
    # ========================================================================
    # This is where you choose which cryptographic implementation to use.
    # Simply instantiate the desired backend class that implements CryptoInterface.
    #
    # Available backends:
    #   - NaiveCrypto: File-based key storage (development/testing)
    #   - TPM2Crypto: TPM2-based secure storage (production) [not yet implemented]
    #
    # To add a new backend:
    #   1. Create a new class implementing CryptoInterface
    #   2. Add it to the choices list above
    #   3. Add instantiation code below
    # ========================================================================
    
    if args.crypto == 'naive':
        crypto = NaiveCrypto()
    elif args.crypto == 'tpm2':
        # TODO: Implement TPM2Crypto backend
        print("ERROR: TPM2 crypto not yet implemented")
        print("Use --crypto=naive for now")
        return 1
    else:
        print(f"ERROR: Unknown crypto implementation: {args.crypto}")
        return 1
    
    host = MASTRHost(
        port=args.port,
        baudrate=args.baudrate,
        crypto=crypto,
        verbose=args.verbose,
        auto_provision=args.provision
    )
    
    return host.run()


if __name__ == '__main__':
    sys.exit(main())
