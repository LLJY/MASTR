"""
Main entry point for the MASTR host receiver test application.
"""
# AI use delcaration: ONLY the skeleton code and documentation here is ai assisted.
import sys
import argparse
from typing import Optional
from .serial_handler import SerialHandler
from .protocol import Frame, MessageType, get_message_name
from .parser import FrameParserError, ChecksumError, ProtocolError


# ANSI Color Codes
class Colors:
    """ANSI escape codes for terminal colors"""
    RESET = '\033[0m'
    ORANGE = '\033[38;5;214m'
    GREEN = '\033[38;5;46m'
    RED = '\033[38;5;196m'
    YELLOW = '\033[38;5;208m'


class HostReceiver:
    """
    Main application class for receiving and displaying messages from the token.
    """
    
    def __init__(self, port: str, baudrate: int = 115200, verbose: bool = False, debug_bytes: bool = False):
        """
        Initialize the host receiver.
        
        Args:
            port: Serial port to connect to
            baudrate: Serial baud rate
            verbose: Enable verbose output
            debug_bytes: Enable raw byte debugging
        """
        self.port = port
        self.baudrate = baudrate
        self.verbose = verbose
        self.debug_bytes = debug_bytes
        self.frame_count = 0
        self.error_count = 0
        self.byte_count = 0
        
        self.handler = SerialHandler(
            port=port,
            baudrate=baudrate,
            on_frame=self.on_frame_received,
            on_error=self.on_error,
            on_raw_data=self.on_raw_data if debug_bytes else None
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
            # Debug messages are automatically colored
            print(f"{Colors.ORANGE}[DEBUG FROM PICO]{Colors.RESET} {frame.debug_text}", end='')
            return
        
        # ===== REGULAR MESSAGE =====
        msg_name = get_message_name(frame.msg_type)
        print(f"\n[Frame #{self.frame_count}]")
        print(f"  Type: {msg_name} (0x{frame.msg_type:02X})")
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
    
    def _display_payload(self, payload: bytes):
        """Display payload data in hex dump and ASCII format"""
        # Print payload as hex dump
        print(f"  Payload (hex):")
        self._print_hex_dump(payload, indent=4)
        
        # Try to print as ASCII if printable
        if all(32 <= b < 127 or b in (9, 10, 13) for b in payload):
            try:
                text = payload.decode('ascii')
                print(f"  Payload (ASCII): {repr(text)}")
            except UnicodeDecodeError:
                pass
    
    def on_raw_data(self, data: bytes):
        """
        Handle raw received data (for debugging).
        
        Args:
            data: Raw bytes received
        """
        self.byte_count += len(data)
        if self.debug_bytes:
            # Print raw bytes in hex
            hex_str = ' '.join(f'{b:02X}' for b in data)
            print(f"[RAW] {len(data)} bytes: {hex_str}")
    
    def on_error(self, error: Exception):
        """
        Handle an error.
        
        Args:
            error: The exception that occurred
        """
        self.error_count += 1
        
        if isinstance(error, ChecksumError):
            print(f"ERROR: Checksum validation failed - {error}", file=sys.stderr)
        elif isinstance(error, ProtocolError):
            print(f"ERROR: Protocol violation - {error}", file=sys.stderr)
        elif isinstance(error, FrameParserError):
            print(f"ERROR: Frame parsing error - {error}", file=sys.stderr)
        else:
            print(f"ERROR: {type(error).__name__}: {error}", file=sys.stderr)
    
    def run(self):
        """
        Run the receiver application.
        """
        import time
        
        print(f"MASTR Host Receiver Test")
        print(f"Waiting for device at {self.port} (will retry indefinitely)...")
        print(f"Commands: 'r' = request random number, 'q' = quit\n")
        
        try:
            # ===== MAIN CONNECTION LOOP =====
            # Retry connection indefinitely until device appears
            while True:
                if self.handler.connect(retries=1, retry_delay=0):
                    print(f"Connected to {self.port} at {self.baudrate} baud!")
                    print(f"Listening for frames...\n")
                    
                    self.handler.start()
                    
                    # ===== MESSAGE PROCESSING LOOP =====
                    # Keep reading and handle user input
                    import sys
                    import select
                    
                    while self.handler.is_connected and self.handler._running:
                        # Check for user input (non-blocking on Unix)
                        if sys.platform != 'win32':
                            if select.select([sys.stdin], [], [], 0.1)[0]:
                                cmd = sys.stdin.readline().strip().lower()
                                self._handle_command(cmd)
                        else:
                            time.sleep(0.1)
                    
                    # ===== DEVICE DISCONNECTED =====
                    # Clean up and retry
                    print(f"\nDevice disconnected. Waiting for reconnection...")
                    self.handler.stop()
                    self.handler.disconnect()
                    time.sleep(0.5)
                else:
                    # Device not available, wait a bit before retrying
                    time.sleep(0.5)
        
        except KeyboardInterrupt:
            print("\n\nShutting down...")
        
        finally:
            # ===== CLEANUP AND STATISTICS =====
            self.handler.stop()
            self.handler.disconnect()
            
            print(f"\nStatistics:")
            print(f"  Bytes received: {self.byte_count}")
            print(f"  Frames received: {self.frame_count}")
            print(f"  Errors: {self.error_count}")
        
        return 0
    
    def _handle_command(self, cmd: str):
        """Handle user commands"""
        if cmd == 'r':
            print("\n[Sending] H2T_TEST_RANDOM_REQUEST")
            if self.handler.send_frame(MessageType.H2T_TEST_RANDOM_REQUEST.value):
                print("[Sent] Random number request sent successfully")
            else:
                print("[Error] Failed to send request")
        elif cmd == 'q':
            raise KeyboardInterrupt()
        elif cmd:
            print(f"Unknown command: {cmd}")

    
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


def main():
    """Main entry point"""
    
    # ===== ARGUMENT PARSING =====
    parser = argparse.ArgumentParser(
        description='MASTR Host Receiver - Test application for receiving token messages'
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
        '-d', '--debug-bytes',
        action='store_true',
        help='Enable raw byte debugging (shows all received bytes)'
    )
    
    args = parser.parse_args()
    
    # ===== CREATE AND RUN RECEIVER =====
    receiver = HostReceiver(
        port=args.port,
        baudrate=args.baudrate,
        verbose=args.verbose,
        debug_bytes=args.debug_bytes
    )
    
    return receiver.run()


if __name__ == '__main__':
    sys.exit(main())
