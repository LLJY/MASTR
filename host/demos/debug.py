"""
Debug and testing tool for the MASTR protocol.
Provides interactive commands to test all protocol message types.
"""

import sys
import argparse
import time
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from host.serial_handler import SerialHandler
from host.protocol import Frame, MessageType, get_message_name
from host.parser import FrameParserError, ChecksumError, ProtocolError


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


class ProtocolDebugger:
    """
    Interactive debugger for testing all MASTR protocol commands.
    """
    
    def __init__(self, port: str, baudrate: int = 115200, verbose: bool = False):
        """
        Initialize the protocol debugger.
        
        Args:
            port: Serial port to connect to
            baudrate: Serial baud rate
            verbose: Enable verbose output
        """
        self.port = port
        self.baudrate = baudrate
        self.verbose = verbose
        self.frame_count = 0
        self.error_count = 0
        self.byte_count = 0
        
        # Key storage
        self.host_pubkey_raw = None
        self.token_pubkey_raw = None
        
        self.handler = SerialHandler(
            port=port,
            baudrate=baudrate,
            on_frame=self.on_frame_received,
            on_error=self.on_error,
            on_raw_data=None
        )
    
    def on_frame_received(self, frame: Frame):
        """
        Handle a received frame.
        
        Args:
            frame: The received frame
        """
        self.frame_count += 1
        
        # ===== DEBUG MESSAGE =====
        if frame.is_debug:
            print(f"{Colors.ORANGE}[DEBUG FROM PICO]{Colors.RESET} {frame.debug_text}", end='')
            return
        
        # ===== REGULAR MESSAGE =====
        msg_name = get_message_name(frame.msg_type)
        print(f"\n{Colors.CYAN}[Frame #{self.frame_count}]{Colors.RESET}")
        print(f"  Type: {Colors.MAGENTA}{msg_name}{Colors.RESET} (0x{frame.msg_type:02X})")
        print(f"  Payload Length: {len(frame.payload)} bytes")
        
        # ===== MESSAGE TYPE SPECIFIC HANDLING =====
        self._handle_message_type(frame)
        
        # ===== PAYLOAD DISPLAY =====
        if len(frame.payload) > 0:
            self._display_payload(frame.payload)
        
        # ===== VERBOSE INFO =====
        if self.verbose:
            print(f"  Timestamp: {self._get_timestamp()}")
    
    def _handle_message_type(self, frame: Frame):
        """Handle specific message types with appropriate formatting"""
        
        # T2H_TEST_RANDOM_RESPONSE - Random number verification
        if frame.msg_type == MessageType.T2H_TEST_RANDOM_RESPONSE and len(frame.payload) == 32:
            hex_str = ' '.join(f'{b:02X}' for b in frame.payload)
            print(f"  {Colors.ORANGE}[VERIFICATION]{Colors.RESET} Random data (for comparison):")
            print(f"    {hex_str}")
        
        # T2H_BOOT_OK - Boot authorization success
        elif frame.msg_type == MessageType.T2H_BOOT_OK:
            print(f"  {Colors.GREEN}[SUCCESS]{Colors.RESET} Boot authorized by Token")
        
        # T2H_INTEGRITY_FAIL_HALT - Critical integrity failure
        elif frame.msg_type == MessageType.T2H_INTEGRITY_FAIL_HALT:
            print(f"  {Colors.RED}[CRITICAL]{Colors.RESET} Integrity check failed - HALT")
        
        # T2H_ERROR - Error message from token
        elif frame.msg_type == MessageType.T2H_ERROR:
            if len(frame.payload) >= 1:
                error_code = frame.payload[0]
                error_msg = frame.payload[1:].decode('utf-8', errors='replace') if len(frame.payload) > 1 else ""
                print(f"  {Colors.RED}[ERROR]{Colors.RESET} Code: 0x{error_code:02X}, Message: {error_msg}")
        
        # T2H_NACK - Negative acknowledgment
        elif frame.msg_type == MessageType.T2H_NACK:
            if len(frame.payload) >= 1:
                rejected_type = frame.payload[0]
                reason = frame.payload[1:].decode('utf-8', errors='replace') if len(frame.payload) > 1 else ""
                rejected_name = get_message_name(rejected_type)
                print(f"  {Colors.YELLOW}[NACK]{Colors.RESET} Rejected message: {rejected_name}, Reason: {reason}")
        
        # T2H_ECDH_SHARE - ECDH public key from token
        elif frame.msg_type == MessageType.T2H_ECDH_SHARE:
            print(f"  {Colors.GREEN}[ECDH]{Colors.RESET} Token ephemeral public key received")
        
        # T2H_CHANNEL_VERIFY_RESPONSE - Encrypted pong
        elif frame.msg_type == MessageType.T2H_CHANNEL_VERIFY_RESPONSE:
            print(f"  {Colors.GREEN}[CHANNEL]{Colors.RESET} Channel verification response received")
        
        # T2H_INTEGRITY_CHALLENGE - Integrity challenge with nonce
        elif frame.msg_type == MessageType.T2H_INTEGRITY_CHALLENGE:
            print(f"  {Colors.YELLOW}[CHALLENGE]{Colors.RESET} Integrity challenge received")
        
        # T2H_HEARTBEAT_ACK - Heartbeat acknowledgment
        elif frame.msg_type == MessageType.T2H_HEARTBEAT_ACK:
            print(f"  {Colors.GREEN}[HEARTBEAT]{Colors.RESET} Heartbeat acknowledged")
        
        # T2H_DEBUG_GET_TOKEN_PUBKEY - Token's permanent public key
        elif frame.msg_type == MessageType.T2H_DEBUG_GET_TOKEN_PUBKEY:
            if len(frame.payload) == 64:
                self.token_pubkey_raw = frame.payload
                print(f"  {Colors.GREEN}[KEY]{Colors.RESET} Token permanent pubkey received")
                print(f"    X: {frame.payload[:32].hex()}")
                print(f"    Y: {frame.payload[32:].hex()}")
                try:
                    with open('token_permanent_pubkey.bin', 'wb') as f:
                        f.write(frame.payload)
                    print(f"  {Colors.GREEN}[SAVED]{Colors.RESET} Written to token_permanent_pubkey.bin")
                except Exception as e:
                    print(f"  {Colors.RED}[ERROR]{Colors.RESET} Failed to save: {e}")
    
    def _display_payload(self, payload: bytes):
        """Display payload data in hex dump format"""
        print(f"  Payload (hex):")
        self._print_hex_dump(payload, indent=4)
    
    def on_error(self, error: Exception):
        """
        Handle an error.
        
        Args:
            error: The exception that occurred
        """
        self.error_count += 1
        
        if isinstance(error, ChecksumError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Checksum validation failed - {error}", file=sys.stderr)
        elif isinstance(error, ProtocolError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Protocol violation - {error}", file=sys.stderr)
        elif isinstance(error, FrameParserError):
            print(f"{Colors.RED}ERROR:{Colors.RESET} Frame parsing error - {error}", file=sys.stderr)
        else:
            print(f"{Colors.RED}ERROR:{Colors.RESET} {type(error).__name__}: {error}", file=sys.stderr)
    
    def run(self):
        """
        Run the debugger application.
        """
        self._print_banner()
        self._print_help()
        
        try:
            # ===== MAIN CONNECTION LOOP =====
            while True:
                if self.handler.connect(retries=1, retry_delay=0):
                    print(f"{Colors.GREEN}Connected{Colors.RESET} to {self.port} at {self.baudrate} baud!")
                    print(f"Listening for frames...\n")
                    
                    self.handler.start()
                    
                    # ===== COMMAND PROCESSING LOOP =====
                    import select
                    
                    while self.handler.is_connected and self.handler._running:
                        if sys.platform != 'win32':
                            if select.select([sys.stdin], [], [], 0.1)[0]:
                                cmd = sys.stdin.readline().strip().lower()
                                self._handle_command(cmd)
                        else:
                            time.sleep(0.1)
                    
                    # ===== DEVICE DISCONNECTED =====
                    print(f"\n{Colors.YELLOW}Device disconnected.{Colors.RESET} Waiting for reconnection...")
                    self.handler.stop()
                    self.handler.disconnect()
                    time.sleep(0.5)
                else:
                    time.sleep(0.5)
        
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        
        finally:
            # ===== CLEANUP AND STATISTICS =====
            self.handler.stop()
            self.handler.disconnect()
            
            print(f"\n{Colors.CYAN}Statistics:{Colors.RESET}")
            print(f"  Frames received: {self.frame_count}")
            print(f"  Errors: {self.error_count}")
        
        return 0
    
    def _print_banner(self):
        """Print application banner"""
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}MASTR Protocol Debugger & Unit Test Tool{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"Port: {self.port} @ {self.baudrate} baud")
        print(f"Waiting for device (will retry indefinitely)...\n")
    
    def _print_help(self):
        """Print available commands"""
        print(f"{Colors.YELLOW}Available Commands:{Colors.RESET}")
        print(f"  {Colors.GREEN}Key Provisioning & Setup{Colors.RESET}")
        print(f"    genkeys       - Generate new host permanent keypair and save to files")
        print(f"    gettoken      - Request token's permanent pubkey (T2H_DEBUG_GET_TOKEN_PUBKEY)")
        print(f"    sethost       - Send host's permanent pubkey to token (H2T_DEBUG_SET_HOST_PUBKEY)")
        print(f"    provision     - Auto-provision: genkeys + gettoken + sethost")
        print(f"")
        print(f"  {Colors.GREEN}Mutual Authentication Demo{Colors.RESET}")
        print(f"    ecdh_demo     - Run full ECDH mutual authentication demo")
        print(f"")
        print(f"  {Colors.GREEN}Phase 1: ECDH & Channel Setup{Colors.RESET}")
        print(f"    ecdh          - Send H2T_ECDH_SHARE (ephemeral public key)")
        print(f"    verify        - Send H2T_CHANNEL_VERIFY_REQUEST (encrypted ping)")
        print(f"")
        print(f"  {Colors.GREEN}Phase 2: Integrity & Boot{Colors.RESET}")
        print(f"    integrity     - Send H2T_INTEGRITY_RESPONSE (mock hash+signature)")
        print(f"    boot_ack      - Send H2T_BOOT_OK_ACK (acknowledge boot authorization)")
        print(f"    halt          - Send H2T_INTEGRITY_FAIL_HALT (signal halt)")
        print(f"    halt_ack      - Send INTEGRITY_FAIL_ACK (acknowledge halt)")
        print(f"")
        print(f"  {Colors.GREEN}Runtime: Heartbeat{Colors.RESET}")
        print(f"    hb            - Send H2T_HEARTBEAT (periodic ping)")
        print(f"")
        print(f"  {Colors.GREEN}Testing & Debug{Colors.RESET}")
        print(f"    random        - Send H2T_TEST_RANDOM_REQUEST (request ATECC608 random)")
        print(f"")
        print(f"  {Colors.GREEN}Utility{Colors.RESET}")
        print(f"    help          - Show this help message")
        print(f"    stats         - Show statistics")
        print(f"    clear         - Clear screen")
        print(f"    q / quit      - Exit debugger")
        print(f"")
    
    def _handle_command(self, cmd: str):
        """Handle user commands"""
        
        # ===== UTILITY COMMANDS =====
        if cmd == 'help' or cmd == 'h':
            self._print_help()
            return
        
        elif cmd == 'stats':
            print(f"\n{Colors.CYAN}Statistics:{Colors.RESET}")
            print(f"  Frames received: {self.frame_count}")
            print(f"  Errors: {self.error_count}")
            return
        
        elif cmd == 'clear':
            print('\033[2J\033[H', end='')
            self._print_banner()
            return
        
        elif cmd in ['q', 'quit', 'exit']:
            raise KeyboardInterrupt()
        
        # ===== KEY PROVISIONING & SETUP =====
        elif cmd == 'genkeys':
            self._generate_host_keys()
        
        elif cmd == 'gettoken':
            self._send_command(
                MessageType.H2T_DEBUG_SET_HOST_PUBKEY,
                b'\x00' * 64,  # Dummy payload - token ignores and sends its pubkey
                "Request token pubkey (H2T_DEBUG_SET_HOST_PUBKEY with dummy data)"
            )
        
        elif cmd == 'sethost':
            self._send_host_pubkey()
        
        elif cmd == 'provision':
            self._auto_provision()
        
        # ===== MUTUAL AUTHENTICATION DEMO =====
        elif cmd == 'ecdh_demo':
            self._run_ecdh_demo()
        
        # ===== PHASE 1: ECDH & CHANNEL =====
        elif cmd == 'ecdh':
            self._send_command(
                MessageType.H2T_ECDH_SHARE,
                b'\x00' * 64,  # Mock 64-byte public key
                "H2T_ECDH_SHARE (mock public key)"
            )
        
        elif cmd == 'verify':
            self._send_command(
                MessageType.H2T_CHANNEL_VERIFY_REQUEST,
                b'\x00' * 16,  # Mock 16-byte encrypted ping
                "H2T_CHANNEL_VERIFY_REQUEST (mock encrypted ping)"
            )
        
        # ===== PHASE 2: INTEGRITY & BOOT =====
        elif cmd == 'integrity':
            self._send_command(
                MessageType.H2T_INTEGRITY_RESPONSE,
                b'\x00' * 32,  # Mock 32-byte hash (signature would follow)
                "H2T_INTEGRITY_RESPONSE (mock hash)"
            )
        
        elif cmd == 'boot_ack':
            self._send_command(
                MessageType.H2T_BOOT_OK_ACK,
                b'',
                "H2T_BOOT_OK_ACK"
            )
        
        elif cmd == 'halt':
            self._send_command(
                MessageType.H2T_INTEGRITY_FAIL_HALT,
                b'',
                "H2T_INTEGRITY_FAIL_HALT"
            )
        
        elif cmd == 'halt_ack':
            self._send_command(
                MessageType.INTEGRITY_FAIL_ACK,
                b'',
                "INTEGRITY_FAIL_ACK"
            )
        
        # ===== RUNTIME: HEARTBEAT =====
        elif cmd in ['hb', 'heartbeat']:
            self._send_command(
                MessageType.H2T_HEARTBEAT,
                b'',
                "H2T_HEARTBEAT"
            )
        
        # ===== TESTING & DEBUG =====
        elif cmd in ['r', 'random']:
            self._send_command(
                MessageType.H2T_TEST_RANDOM_REQUEST,
                b'',
                "H2T_TEST_RANDOM_REQUEST"
            )
        
        # ===== UNKNOWN COMMAND =====
        elif cmd:
            print(f"{Colors.RED}Unknown command:{Colors.RESET} {cmd}")
            print(f"Type 'help' for available commands")
    
    def _send_command(self, msg_type: MessageType, payload: bytes, description: str):
        """Send a command to the device"""
        print(f"\n{Colors.YELLOW}[Sending]{Colors.RESET} {description}")
        if self.handler.send_frame(msg_type, payload):
            print(f"{Colors.GREEN}[Sent]{Colors.RESET} Successfully sent")
        else:
            print(f"{Colors.RED}[Error]{Colors.RESET} Failed to send")
    
    @staticmethod
    def _print_hex_dump(data: bytes, width: int = 16, indent: int = 0):
        """
        Print a hex dump of binary data.
        
        Args:
            data: Data to dump
            width: Number of bytes per line
            indent: Number of spaces to indent each line
        """
        prefix = ' ' * indent
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"{prefix}{i:04X}: {hex_part:<{width*3}} {ascii_part}")
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp as string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    def _generate_host_keys(self):
        """Generate new host permanent keypair and save to files"""
        print(f"\n{Colors.YELLOW}[Generating]{Colors.RESET} New host permanent keypair...")
        
        # Generate P-256 keypair
        privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pubkey = privkey.public_key()
        
        # Save private key as PEM
        try:
            pem = privkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('host_permanent_privkey.pem', 'wb') as f:
                f.write(pem)
            print(f"  {Colors.GREEN}[SAVED]{Colors.RESET} Private key: host_permanent_privkey.pem")
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.RESET} Failed to save private key: {e}")
            return
        
        # Extract and save public key as raw bytes
        pubkey_bytes = pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        self.host_pubkey_raw = pubkey_bytes[1:]
        
        try:
            with open('host_permanent_pubkey.bin', 'wb') as f:
                f.write(self.host_pubkey_raw)
            print(f"  {Colors.GREEN}[SAVED]{Colors.RESET} Public key: host_permanent_pubkey.bin")
        except Exception as e:
            print(f"  {Colors.RED}[ERROR]{Colors.RESET} Failed to save public key: {e}")
            return
        
        print(f"  {Colors.CYAN}[INFO]{Colors.RESET} Public key (64 bytes):")
        print(f"    X: {self.host_pubkey_raw[:32].hex()}")
        print(f"    Y: {self.host_pubkey_raw[32:].hex()}")
        print(f"\n  {Colors.GREEN}✓{Colors.RESET} Keypair generated successfully!")
    
    def _send_host_pubkey(self):
        """Send host's permanent public key to token"""
        if self.host_pubkey_raw is None:
            try:
                with open('host_permanent_pubkey.bin', 'rb') as f:
                    self.host_pubkey_raw = f.read()
                if len(self.host_pubkey_raw) != 64:
                    print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid pubkey file (expected 64 bytes, got {len(self.host_pubkey_raw)})")
                    return
                print(f"  {Colors.CYAN}[INFO]{Colors.RESET} Loaded host pubkey from file")
            except FileNotFoundError:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} No host pubkey available. Run 'genkeys' first.")
                return
        
        print(f"\n{Colors.YELLOW}[Sending]{Colors.RESET} Host permanent pubkey to token...")
        print(f"  X: {self.host_pubkey_raw[:32].hex()}")
        print(f"  Y: {self.host_pubkey_raw[32:].hex()}")
        
        self._send_command(
            MessageType.H2T_DEBUG_SET_HOST_PUBKEY,
            self.host_pubkey_raw,
            "H2T_DEBUG_SET_HOST_PUBKEY"
        )
    
    def _auto_provision(self):
        """Auto-provision: generate keys, get token key, send host key"""
        print(f"\n{Colors.CYAN}=== Auto-Provisioning ==={Colors.RESET}")
        
        # Step 1: Generate host keys
        self._generate_host_keys()
        time.sleep(0.5)
        
        # Step 2: Request token pubkey
        print(f"\n{Colors.YELLOW}[Requesting]{Colors.RESET} Token permanent pubkey...")
        self._send_command(
            MessageType.H2T_DEBUG_SET_HOST_PUBKEY,
            b'\x00' * 64,  # Dummy payload
            "Request token pubkey"
        )
        time.sleep(1.0)
        
        # Step 3: Send host pubkey
        if self.host_pubkey_raw:
            print(f"\n{Colors.YELLOW}[Sending]{Colors.RESET} Host pubkey to token...")
            self._send_host_pubkey()
        
        print(f"\n{Colors.GREEN}✓ Provisioning complete!{Colors.RESET}")
        if self.token_pubkey_raw:
            print(f"  Token pubkey saved to: token_permanent_pubkey.bin")
        print(f"  Host private key: host_permanent_privkey.pem")
        print(f"  Host public key: host_permanent_pubkey.bin")
    
    def _run_ecdh_demo(self):
        """Run the full ECDH mutual authentication demo"""
        print(f"\n{Colors.CYAN}=== Starting ECDH Mutual Authentication Demo ==={Colors.RESET}")
        print(f"This will run the full key exchange protocol.")
        print(f"Make sure keys are provisioned first (run 'provision' if needed).")
        print(f"")
        
        # Import and run the demo
        try:
            from .mutual_auth_demo import run_demo
            
            # Stop current handler
            print(f"{Colors.YELLOW}[INFO]{Colors.RESET} Stopping debug session...")
            self.handler.stop()
            self.handler.disconnect()
            time.sleep(0.5)
            
            # Run demo
            result = run_demo(port=self.port, baudrate=self.baudrate)
            
            # Reconnect after demo
            print(f"\n{Colors.YELLOW}[INFO]{Colors.RESET} Returning to debug mode...")
            time.sleep(0.5)
            if self.handler.connect(retries=1):
                self.handler.start()
                print(f"{Colors.GREEN}[INFO]{Colors.RESET} Debug session resumed")
            
            if result == 0:
                print(f"\n{Colors.GREEN}✓ Demo completed successfully!{Colors.RESET}")
            else:
                print(f"\n{Colors.RED}✗ Demo failed{Colors.RESET}")
        
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to run demo: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Main entry point"""
    
    # ===== ARGUMENT PARSING =====
    parser = argparse.ArgumentParser(
        description='MASTR Protocol Debugger - Interactive testing tool for all protocol commands'
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
        help='Enable verbose output with timestamps'
    )
    
    args = parser.parse_args()
    
    # ===== CREATE AND RUN DEBUGGER =====
    debugger = ProtocolDebugger(
        port=args.port,
        baudrate=args.baudrate,
        verbose=args.verbose
    )
    
    return debugger.run()


if __name__ == '__main__':
    sys.exit(main())
