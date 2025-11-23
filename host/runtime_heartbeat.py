#!/usr/bin/env python3
"""
MASTR Runtime Heartbeat Daemon

Runs in the main Linux system after successful boot from initramfs.
Maintains encrypted heartbeat communication with MASTR token.
Integrates with LKRG for runtime integrity monitoring.

Usage:
    python -m host.runtime_heartbeat /dev/ttyACM0 [options]
    
Systemd:
    systemctl start mastr-heartbeat.service
"""

import sys
import time
import signal
import threading
from typing import Optional
import argparse

from host.crypto import NaiveCrypto

from .serial_handler import SerialHandler
from .protocol import MessageType, Frame
from .logger import Logger, Colors
from .tpm2_crypto import TPM2Crypto
from .config import GOLDEN_HASH_FILE


class HeartbeatDaemon:
    """
    Runtime heartbeat daemon for MASTR protocol Phase 3.
    
    Responsibilities:
    - Retrieve session key from storage (keyring or TPM2)
    - Establish encrypted serial connection
    - Send periodic heartbeat messages
    - Monitor for acknowledgments
    - Integrate with LKRG integrity monitoring
    - Trigger emergency shutdown on failures
    """
    
    def __init__(
        self,
        port: str,
        crypto,
        interval: int = 5,
        timeout_threshold: int = 3,
        check_lkrg: bool = True,
        debug_no_shutdown: bool = False,
    ):
        """
        Initialize heartbeat daemon.

        Args:
            port: Serial port (/dev/ttyACM0)
            crypto: Crypto backend (NaiveCrypto or TPM2Crypto)
            interval: Heartbeat interval in seconds
            timeout_threshold: Max consecutive timeouts before emergency shutdown
            check_lkrg: Enable LKRG integrity monitoring
            debug_no_shutdown: DEBUG MODE - prevent actual system shutdown
        """
        self.port = port
        self.interval = interval
        self.timeout_threshold = timeout_threshold
        self.check_lkrg = check_lkrg
        self.debug_no_shutdown = debug_no_shutdown

        self.running = False
        self.consecutive_timeouts = 0
        self.session_key: Optional[bytes] = None

        # Re-attestation support
        self.token_ecdh_share: Optional[bytes] = None
        self.reattestation_requested = threading.Event()
        self.boot_ok_received = threading.Event()  # Signal re-attestation complete
        self.reattestation_in_progress = False     # Flag to pause heartbeats during re-attestation

        # Threading synchronization
        self.ack_event = threading.Event()
        self.handler: Optional[SerialHandler] = None

        # Crypto handler for encryption (NaiveCrypto or TPM2Crypto)
        self.crypto = crypto
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def start(self) -> int:
        """
        Start the heartbeat daemon.
        
        Returns:
            Exit code (0 = success, 1 = failure)
        """
        Logger.header("MASTR Runtime Heartbeat Daemon")
        
        # BIG WARNING if in debug mode
        if self.debug_no_shutdown:
            print("\n" + "=" * 70)
            print(f"{Colors.RED}{'RUNNING IN DEBUG MODE - NO SHUTDOWN':^70}{Colors.RESET}")
            print(f"{Colors.RED}{'EMERGENCY SHUTDOWN DISABLED FOR TESTING':^70}{Colors.RESET}")
            print(f"{Colors.RED}{'DO NOT USE IN PRODUCTION!':^70}{Colors.RESET}")
            print("=" * 70 + "\n")
        
        Logger.info(f"Port: {self.port}")
        Logger.info(f"Crypto backend: {type(self.crypto).__name__}")
        Logger.info(f"Interval: {self.interval}s")
        Logger.info(f"Timeout threshold: {self.timeout_threshold}")
        Logger.info(f"LKRG monitoring: {'enabled' if self.check_lkrg else 'disabled'}")
        Logger.info(f"Debug mode (no shutdown): {'YES' if self.debug_no_shutdown else 'NO'}")
        
        # Step 1: Load permanent keys (needed for signature verification during re-attestation)
        Logger.section("Loading Permanent Keys")
        if not self.crypto.load_permanent_keys():
            Logger.error("Failed to load permanent keys")
            return 1
        Logger.success("Permanent keys loaded")
        
        # Step 2: Retrieve session key from storage
        if not self._retrieve_session_key():
            Logger.error("Failed to retrieve session key")
            return 1
        
        # Step 3: Connect to serial port
        if not self._connect_serial():
            Logger.error("Failed to connect to serial port")
            return 1
        
        # Step 4: Start heartbeat loop
        Logger.section("Starting Heartbeat Loop")
        self.running = True
        
        try:
            self._heartbeat_loop()
        except KeyboardInterrupt:
            Logger.info("Received interrupt signal")
        except Exception as e:
            Logger.error(f"Heartbeat loop crashed: {e}")
            return 1
        finally:
            self._cleanup()
        
        return 0
    
    def _retrieve_session_key(self) -> bool:
        """
        Retrieve session key from kernel keyring only.
        
        Returns:
            True if key retrieved successfully
        """
        Logger.section("Retrieving Session Key")
        
        from .keyring_storage import KeyringStorage
        storage = KeyringStorage()
        
        if not storage.is_available():
            Logger.error("Kernel keyring not available")
            return False
        
        self.session_key = storage.retrieve_session_key()
        
        if self.session_key is None:
            Logger.error("Failed to retrieve session key from keyring")
            return False
        
        if len(self.session_key) != 16:
            Logger.error(f"Invalid session key length: {len(self.session_key)} (expected 16)")
            return False
        
        Logger.success(f"Session key retrieved from keyring ({len(self.session_key)} bytes)")
        if Logger.verbose:
            Logger.substep(f"Key: {self.session_key.hex()}")
        
        return True
    
    def _connect_serial(self) -> bool:
        """
        Connect to serial port and configure encryption.
        
        Returns:
            True if connected successfully
        """
        Logger.section("Connecting to Token")
        
        # Initialize serial handler
        self.handler = SerialHandler(
            port=self.port,
            baudrate=115200,
            on_frame=self._on_frame_received,
            on_error=self._on_error,
            crypto_handler=self.crypto
        )
        
        # Connect to serial port
        if not self.handler.connect():
            Logger.error(f"Failed to connect to {self.port}")
            return False
        
        # Configure encryption with retrieved session key
        self.crypto.set_session_key(self.session_key)
        self.crypto.set_encryption_enabled(True)
        
        # Start serial handler background thread
        self.handler.start()
        
        Logger.success(f"Connected to {self.port}")
        Logger.substep("Encryption enabled")
        
        return True
    
    def _heartbeat_loop(self):
        """
        Main heartbeat loop.
        
        Sends periodic heartbeat messages and monitors for acknowledgments.
        Triggers emergency shutdown if too many consecutive timeouts.
        """
        heartbeat_count = 0
        
        while self.running:
            # Skip heartbeats during re-attestation
            if self.reattestation_in_progress:
                time.sleep(0.5)
                continue
            
            heartbeat_count += 1
            
            # Clear previous ACK
            self.ack_event.clear()
            
            # Send heartbeat
            Logger.info(f"Sending heartbeat #{heartbeat_count}...")
            
            if not self.handler.send_frame(MessageType.H2T_HEARTBEAT.value, b''):
                Logger.error("Failed to send heartbeat")
                self.consecutive_timeouts += 1
            else:
                # Wait for ACK with timeout
                if self.ack_event.wait(timeout=2.0):
                    Logger.success(f"Heartbeat ACK received")
                    self.consecutive_timeouts = 0
                else:
                    self.consecutive_timeouts += 1
                    Logger.warning(
                        f"Heartbeat timeout "
                        f"({self.consecutive_timeouts}/{self.timeout_threshold})"
                    )
            
            # Check timeout threshold
            if self.consecutive_timeouts >= self.timeout_threshold:
                Logger.error(
                    f"Too many consecutive timeouts ({self.consecutive_timeouts}) "
                    f"- EMERGENCY SHUTDOWN!"
                )
                self._emergency_shutdown()
                break
            
            # Check LKRG integrity status
            if self.check_lkrg:
                self._check_lkrg_status()
            
            # Sleep until next heartbeat
            if self.running:
                time.sleep(self.interval)
    
    def _on_frame_received(self, frame: Frame) -> None:
        """
        Handle received frames including re-attestation requests.
        
        Args:
            frame: Received frame (already decrypted)
        """
        if frame.msg_type == MessageType.T2H_HEARTBEAT_ACK:
            # Heartbeat ACK received
            self.ack_event.set()
        
        elif frame.msg_type == MessageType.T2H_ECDH_SHARE:
            # Token requesting re-attestation by sending new ephemeral key
            Logger.warning("=" * 60)
            Logger.warning("TOKEN INITIATED RE-ATTESTATION")
            Logger.warning("Received T2H_ECDH_SHARE - session timeout detected")
            Logger.warning("Token sent new ephemeral key - need to re-establish trust")
            Logger.warning("=" * 60)
            
            # Save the token's ECDH share
            self.token_ecdh_share = frame.payload
            self.reattestation_requested.set()
            
            # Pause heartbeats and perform re-attestation
            Logger.info("Performing re-attestation (heartbeat paused)...")
            self.reattestation_in_progress = True
            
            if self._perform_reattestation():
                # Don't resume yet - wait for BOOT_OK
                Logger.success("Re-attestation ECDH complete - waiting for BOOT_OK...")
            else:
                Logger.error("Re-attestation failed - emergency shutdown!")
                self.reattestation_in_progress = False
                self._emergency_shutdown()
            
        elif frame.msg_type == MessageType.T2H_CHANNEL_VERIFY_REQUEST:
            # Encrypted ping challenge during re-attestation
            try:
                ping_challenge = frame.payload.decode('utf-8', errors='replace')
                Logger.info(f"Received ping challenge: {ping_challenge!r}")
                
                # Send pong response (encrypted with new session key already set)
                if self.handler.send_frame(MessageType.H2T_CHANNEL_VERIFY_RESPONSE.value, b"pong"):
                    Logger.success("Pong response sent")
                else:
                    Logger.error("Failed to send pong")
            except Exception as e:
                Logger.error(f"Failed to handle ping: {e}")
        
        elif frame.msg_type == MessageType.T2H_INTEGRITY_CHALLENGE:
            # Integrity challenge (nonce)
            if len(frame.payload) == 4:
                nonce = frame.payload
                Logger.info(f"Received integrity nonce: {nonce.hex()}")

                # Compute golden hash from configured file
                import hashlib
                try:
                    with open(GOLDEN_HASH_FILE, 'rb') as f:
                        file_data = f.read()
                    golden_hash = hashlib.sha256(file_data).digest()
                    Logger.info(f"Computed golden hash from {GOLDEN_HASH_FILE} ({len(file_data)} bytes)")
                except FileNotFoundError:
                    Logger.error(f"Golden hash file not found: {GOLDEN_HASH_FILE}")
                    self._emergency_shutdown()
                    return
                except Exception as e:
                    Logger.error(f"Error computing golden hash: {e}")
                    self._emergency_shutdown()
                    return

                # Respond with golden hash + signature
                message_to_sign = golden_hash + nonce
                # Sign the message directly (golden_hash + nonce), don't hash again!
                signature = self.crypto.sign_with_permanent_key(message_to_sign)

                response = golden_hash + signature
                if self.handler.send_frame(MessageType.H2T_INTEGRITY_RESPONSE.value, response):
                    Logger.success("Integrity response sent")
                else:
                    Logger.error("Failed to send integrity response")
        
        elif frame.msg_type == MessageType.T2H_BOOT_OK:
            # Boot OK after successful re-attestation
            Logger.success("BOOT_OK received - re-attestation phase complete")
            
            # Send ACK
            if self.handler.send_frame(MessageType.H2T_BOOT_OK_ACK.value, b''):
                Logger.success("BOOT_OK ACK sent - re-attestation complete!")
                # Un-pause heartbeats
                self.reattestation_in_progress = False
                self.consecutive_timeouts = 0
                Logger.success("Resuming heartbeats with new session key")
            else:
                Logger.error("Failed to send BOOT_OK ACK")
        
        elif frame.msg_type == MessageType.T2H_INTEGRITY_FAIL_HALT:
            # Token entered permanent halt state - integrity failure detected
            Logger.error("=" * 60)
            Logger.error("TOKEN IN PERMANENT HALT STATE")
            Logger.error("INTEGRITY FAILURE DETECTED - NO RECOVERY POSSIBLE")
            Logger.error("=" * 60)
            self._emergency_shutdown()
        
        elif frame.msg_type == MessageType.DEBUG_MSG:
            # Debug message from token
            Logger.debug("TOKEN", frame.debug_text.rstrip())
        
        elif frame.msg_type == MessageType.T2H_ERROR:
            # Error from token
            if len(frame.payload) >= 1:
                error_code = frame.payload[0]
                error_msg = frame.payload[1:].decode('utf-8', errors='replace') if len(frame.payload) > 1 else ""
                Logger.error(f"Token error: code=0x{error_code:02X}, msg={error_msg}")
        
        else:
            # Unexpected frame type
            Logger.warning(f"Unexpected frame: {frame.msg_type.name if hasattr(frame.msg_type, 'name') else frame.msg_type}")
    
    def _on_error(self, error: Exception) -> None:
        """
        Handle protocol errors.
        
        Args:
            error: Exception that occurred
        """
        Logger.error(f"Protocol error: {error}")
    
    def _check_lkrg_status(self) -> None:
        """
        Check LKRG (Linux Kernel Runtime Guard) integrity status.
        
        If LKRG detects integrity violation, log it and potentially
        notify the token.
        """
        try:
            with open('/proc/lkrg', 'r') as f:
                status = f.read()
                
                # Check for integrity violations
                if 'INTEGRITY VIOLATION' in status.upper():
                    Logger.error("LKRG INTEGRITY VIOLATION DETECTED!")
                    Logger.error("System integrity compromised - alerting token")
 
        except FileNotFoundError:
            pass
        except PermissionError:
            Logger.warning("No permission to read /proc/lkrg")
        except Exception as e:
            Logger.warning(f"Failed to check LKRG status: {e}")
    
    def _perform_reattestation(self) -> bool:
        """
        Perform full re-attestation cycle (ECDH + ping/pong + integrity).
        Called when token triggers re-attestation.
        
        Returns:
            True if re-attestation successful, False otherwise
        """
        try:
            Logger.section("Re-Attestation Cycle")
            
            # We already have token's ECDH share in self.token_ecdh_share
            token_eph_pubkey = self.token_ecdh_share[:64]
            token_signature = self.token_ecdh_share[64:]
            
            # Step 1: Verify token's signature
            Logger.step(1, "Verifying token's signature...")
            if not self.crypto.verify_signature(token_eph_pubkey, token_signature,
                                               self.crypto.token_permanent_pubkey_raw):
                Logger.error("Token signature verification failed")
                return False
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Token signature verified")
            
            # Step 2: Generate our ephemeral keypair
            Logger.step(2, "Generating ephemeral keypair...")
            host_eph_pubkey, host_eph_privkey = self.crypto.generate_ephemeral_keypair()
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Ephemeral key generated")
            
            # Step 3: Sign and send our ECDH share
            Logger.step(3, "Signing and sending H2T_ECDH_SHARE...")
            signature = self.crypto.sign_with_permanent_key(host_eph_pubkey)
            payload = host_eph_pubkey + signature
            if not self.handler.send_frame(MessageType.H2T_ECDH_SHARE.value, payload):
                Logger.error("Failed to send H2T_ECDH_SHARE")
                return False
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} ECDH share sent")
            
            # Step 4: Derive shared secret and new session key
            Logger.step(4, "Deriving new session key...")
            shared_secret = self.crypto.compute_shared_secret(host_eph_privkey, token_eph_pubkey)
            if shared_secret is None:
                Logger.error("Failed to compute shared secret")
                return False
            
            new_session_key = self.crypto.derive_session_key(shared_secret)
            if new_session_key is None:
                Logger.error("Failed to derive session key")
                return False
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Session key derived: {new_session_key.hex()}")
            
            # Step 5: Switch to new key IMMEDIATELY (not on ping)
            Logger.step(5, "Switching to new session key...")
            self.crypto.set_session_key(new_session_key)
            self.crypto.set_encryption_enabled(True)
            self.session_key = new_session_key
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Session key switched: {new_session_key.hex()}")
            
            # Steps 6-7: Ping/pong and integrity handled by message callbacks
            # Don't wait here - we're IN the callback thread!
            # Return immediately so callbacks can process ping/pong/integrity/BOOT_OK
            Logger.step(6, "ECDH complete - returning to message loop...")
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Ping/pong and integrity will be handled by callbacks")
            
            # Update session key in keyring NOW
            Logger.step(7, "Updating session key in keyring...")
            from .keyring_storage import KeyringStorage
            storage = KeyringStorage()
            if storage.store_session_key(new_session_key):
                Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Keyring updated")
            else:
                Logger.warning("Failed to update keyring (non-fatal)")
            
            Logger.success("Re-attestation ECDH done - protocol continues via callbacks!")
            return True
            
        except Exception as e:
            Logger.error(f"Re-attestation exception: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _emergency_shutdown(self) -> None:
        """
        Trigger emergency system shutdown.
        
        Called when heartbeat failures exceed threshold.
        This is a security measure to prevent operation with disconnected token.
        """
        Logger.error("=" * 60)
        Logger.error("EMERGENCY SHUTDOWN TRIGGERED")
        Logger.error("Token heartbeat lost - system halting for security")
        Logger.error("=" * 60)
        
        if self.debug_no_shutdown:
            print("\n" + "=" * 70)
            print(f"{Colors.RED}{'DEBUG MODE: SHUTDOWN PREVENTED':^70}{Colors.RESET}")
            print(f"{Colors.YELLOW}{'In production, system would shutdown now!':^70}{Colors.RESET}")
            print("=" * 70 + "\n")
            Logger.warning("Continuing operation (debug mode only)")
            # Stop the heartbeat loop gracefully instead of shutting down
            self.running = False
            return
        
        import subprocess
        
        try:
            # Trigger immediate shutdown
            subprocess.run(
                ['/sbin/shutdown', '-h', 'now', 'MASTR token heartbeat lost'],
                check=False,
                timeout=5.0
            )
        except Exception as e:
            Logger.error(f"Failed to trigger shutdown: {e}")
            Logger.error("CRITICAL: Manual intervention required!")
    
    def _signal_handler(self, signum: int, frame) -> None:
        """
        Handle shutdown signals (SIGTERM, SIGINT).
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        Logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def _cleanup(self) -> None:
        """
        Cleanup resources before exit.
        """
        Logger.section("Shutting Down")
        
        if self.handler:
            self.handler.stop()
            self.handler.disconnect()
        
        Logger.info("Daemon stopped")


def main() -> int:
    """
    Main entry point for runtime heartbeat daemon.
    
    Returns:
        Exit code (0 = success)
    """
    parser = argparse.ArgumentParser(
        description='MASTR Runtime Heartbeat Daemon - Phase 3 Protocol Implementation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic usage
  python -m host.runtime_heartbeat /dev/ttyACM0
  
  # Custom interval and timeout
  python -m host.runtime_heartbeat /dev/ttyACM0 -i 10 -t 5
  
  # Disable LKRG monitoring
  python -m host.runtime_heartbeat /dev/ttyACM0 --no-lkrg
        '''
    )
    
    parser.add_argument(
        'port',
        help='Serial port (e.g., /dev/ttyACM0, COM3)'
    )
    
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Heartbeat interval in seconds (default: 5)'
    )
    
    parser.add_argument(
        '-t', '--timeout-threshold',
        type=int,
        default=3,
        help='Max consecutive timeouts before emergency shutdown (default: 3)'
    )
    
    parser.add_argument(
        '--no-lkrg',
        action='store_true',
        help='Disable LKRG integrity monitoring'
    )
    
    parser.add_argument(
        '--debug-no-shutdown',
        action='store_true',
        help='DEBUG MODE: Prevent actual system shutdown (testing only)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()

    # Set verbose mode in logger
    Logger.verbose = args.verbose

    # Initialize crypto backend (default to TPM2 for production)
    crypto_backend_name = None
    try:
        crypto = TPM2Crypto()
        crypto_backend_name = "TPM2Crypto"
        Logger.info("✓ Using TPM2Crypto backend")
    except Exception as e:
        Logger.warning(f"Failed to initialize TPM2Crypto: {e}")
        Logger.warning("Falling back to NaiveCrypto (file-based)")
        crypto = NaiveCrypto()
        crypto_backend_name = "NaiveCrypto"

    # Create and start daemon
    daemon = HeartbeatDaemon(
        port=args.port,
        crypto=crypto,
        interval=args.interval,
        timeout_threshold=args.timeout_threshold,
        check_lkrg=not args.no_lkrg,
        debug_no_shutdown=args.debug_no_shutdown
    )

    return daemon.start()


if __name__ == '__main__':
    sys.exit(main())