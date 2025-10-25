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
            auto_provision: Automatically provision keys if missing
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
        
        self.handler = SerialHandler(
            port=port,
            baudrate=baudrate,
            on_frame=self.on_frame_received,
            on_error=self.on_error,
            on_raw_data=None,
            crypto_handler=None  # We'll manage crypto ourselves
        )
    
    # ========================================================================
    # FRAME RECEIVING AND ROUTING
    # ========================================================================
    
    def on_frame_received(self, frame: Frame):
        """
        Main frame handler - routes frames to appropriate handlers.
        
        All frames are decrypted here if protocol state >= 0x22.
        This includes debug messages, which are encrypted after channel establishment.
        """
        self.frame_count += 1
        
        # Decrypt if needed (applies to ALL messages including debug)
        payload = frame.payload
        if self.crypto.should_encrypt():
            try:
                payload = self.crypto.decrypt_payload(frame.payload)
                if self.verbose:
                    print(f"{Colors.YELLOW}[DECRYPTED]{Colors.RESET} {len(frame.payload)} -> {len(payload)} bytes")
            except Exception as e:
                print(f"{Colors.RED}[DECRYPT ERROR]{Colors.RESET} {e}")
                return
        
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
        """Handle debug messages from token (already decrypted if needed)"""
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
        """Handle T2H_CHANNEL_VERIFY_REQUEST (encrypted ping)"""
        # Update state to enable encryption
        self.crypto.set_protocol_state(0x22)
        self.protocol_state = 0x22
        
        # Decrypt the challenge
        if self.crypto.should_encrypt():
            try:
                decrypted = self.crypto.decrypt_payload(payload)
                if decrypted and len(decrypted) >= 4 and decrypted[:4] == b"ping":
                    self.channel_challenge_received = decrypted
                    self.challenge_event.set()
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid challenge payload: {decrypted!r}")
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to decrypt challenge: {e}")
        else:
            # Buffer for later if crypto not ready
            self.buffered_challenge = payload
    
    def _handle_token_pubkey_response(self, payload: bytes):
        """Handle T2H_DEBUG_GET_TOKEN_PUBKEY response"""
        if len(payload) == 64:
            self.received_token_pubkey = payload
            self.token_pubkey_received_event.set()
            print(f"{Colors.GREEN}✓{Colors.RESET} Received token public key: {payload[:32].hex()}...")
        else:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid token pubkey length: {len(payload)} (expected 64)")
    
    def _handle_error(self, payload: bytes):
        """Handle T2H_ERROR"""
        if len(payload) >= 1:
            error_code = payload[0]
            error_msg = payload[1:].decode('utf-8', errors='replace') if len(payload) > 1 else ""
            print(f"{Colors.RED}[TOKEN ERROR]{Colors.RESET} Code: 0x{error_code:02X}, Message: {error_msg}")
    
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
        if self.crypto.load_permanent_keys():
            host_pubkey = self.crypto.get_host_permanent_pubkey()
            print(f"{Colors.GREEN}✓{Colors.RESET} Loaded permanent keys")
            if self.verbose and host_pubkey:
                print(f"  Host pubkey: {host_pubkey[:32].hex()}...")
            return True
        else:
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Permanent keys not found, generating new keypair...")
            if self.crypto.generate_permanent_keypair():
                host_pubkey = self.crypto.get_host_permanent_pubkey()
                print(f"{Colors.GREEN}✓{Colors.RESET} Generated new host keypair")
                if host_pubkey:
                    print(f"  Host pubkey: {host_pubkey.hex()}")
                
                # Check if token pubkey exists
                if not self.auto_provision:
                    print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} Token public key not found!")
                    print(f"Please provision the token first:")
                    print(f"  python -m host.demos.debug {self.port}")
                    print(f"  Then type: provision")
                    print(f"Or run with --provision flag to auto-provision")
                    return False
                else:
                    # Auto-provision: request token pubkey
                    return self._auto_provision_token_key()
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to generate keys")
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
                return True
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to reload keys")
                return False
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to save token pubkey: {e}")
            return False
    
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
        self.crypto.set_protocol_state(0x21)  # ECDH complete, waiting for channel verify
        self.protocol_state = 0x21
        
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
        
        # Send encrypted pong response
        print(f"\n9. Sending encrypted pong response...")
        pong_payload = b"pong"
        
        # Encrypt the pong response (state is 0x22, encryption required)
        encrypted_pong = self.crypto.encrypt_payload(pong_payload)
        if encrypted_pong is None:
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to encrypt pong")
            return False
        
        if not self.handler.send_frame(MessageType.H2T_CHANNEL_VERIFY_RESPONSE.value, encrypted_pong):
            print(f"   {Colors.RED}✗{Colors.RESET} Failed to send response")
            return False
        
        print(f"   {Colors.GREEN}✓{Colors.RESET} Pong sent")
        
        # Update state to "established"
        self.crypto.set_protocol_state(0x24)
        self.protocol_state = 0x24
        
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
            
            # Success!
            print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}✅ Secure channel established!{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"Protocol state: 0x{self.protocol_state:02X}")
            print(f"Session key: {self.crypto.get_session_key().hex()}")
            
            # ================================================================
            # TODO: Phase 2 - Integrity Verification
            # ================================================================
            # When implementing Phase 2, add:
            #   1. _handle_integrity_challenge() handler
            #   2. _perform_integrity_verification() method
            #   3. Add case for T2H_INTEGRITY_CHALLENGE in on_frame_received()
            #   4. Implement firmware measurement/attestation logic
            #
            # if not self._perform_integrity_verification():
            #     print(f"\n{Colors.RED}✗ Integrity verification failed{Colors.RESET}")
            #     return 1
            
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
        help='Automatically provision token keys if missing'
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
