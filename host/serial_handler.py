"""
Serial communication handler for the Host-Token protocol.
"""

import serial
import threading
from typing import Optional, Callable
from .parser import FrameParser, FrameParserError
from .protocol import Frame


class SerialHandler:
    """
    Manages serial communication with the token device.
    Runs a background thread to continuously read from the serial port.
    """
    
    def __init__(
        self,
        port: str,
        baudrate: int = 115200,
        on_frame: Optional[Callable[[Frame], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_raw_data: Optional[Callable[[bytes], None]] = None
    ):
        """
        Initialize the serial handler.
        
        Args:
            port: Serial port name (e.g., '/dev/ttyACM0', 'COM3')
            baudrate: Baud rate for serial communication
            on_frame: Callback called when a frame is received
            on_error: Callback called when an error occurs
            on_raw_data: Callback called with raw received bytes (for debugging)
        """
        self.port = port
        self.baudrate = baudrate
        self.on_frame = on_frame
        self.on_error = on_error
        self.on_raw_data = on_raw_data
        
        self._serial: Optional[serial.Serial] = None
        self._parser = FrameParser(on_frame=self._handle_frame)
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def connect(self, retries: int = 5, retry_delay: float = 1.0) -> bool:
        """
        Connect to the serial port with retry logic.
        
        Args:
            retries: Number of connection attempts (0 = infinite)
            retry_delay: Delay between retries in seconds
            
        Returns:
            True if connection successful, False otherwise
        """
        import time
        
        attempt = 0
        while retries == 0 or attempt < retries:
            try:
                self._serial = serial.Serial(
                    port=self.port,
                    baudrate=self.baudrate,
                    timeout=0.1,  # Short timeout to avoid blocking too long
                    write_timeout=1.0
                )
                # Reset parser state on new connection
                self._parser = FrameParser(on_frame=self._handle_frame)
                return True
            except (serial.SerialException, OSError) as e:
                if retry_delay > 0:
                    time.sleep(retry_delay)
                attempt += 1
        
        return False
    
    def disconnect(self):
        """Disconnect from the serial port"""
        self.stop()
        if self._serial and self._serial.is_open:
            self._serial.close()
        self._serial = None
    
    def start(self):
        """Start the background reading thread"""
        if self._running:
            return
        
        if not self._serial or not self._serial.is_open:
            raise RuntimeError("Serial port not connected")
        
        self._running = True
        self._thread = threading.Thread(target=self._read_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the background reading thread"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
    
    def _read_loop(self):
        """Background thread that continuously reads from serial port"""
        import time
        
        while self._running:
            try:
                # Check if serial port is still valid
                if not self._serial or not self._serial.is_open:
                    # Port closed, exit quietly (main loop will handle reconnection)
                    break
                
                # Read available data - always try to read up to 256 bytes
                # The timeout will handle blocking
                bytes_to_read = max(256, self._serial.in_waiting)
                data = self._serial.read(bytes_to_read)
                
                if len(data) > 0:
                    # Call raw data callback for debugging
                    if self.on_raw_data:
                        self.on_raw_data(data)
                    
                    # Feed to parser
                    try:
                        self._parser.feed(data)
                    except FrameParserError as e:
                        if self.on_error:
                            self.on_error(e)
            
            except (serial.SerialException, OSError) as e:
                # Serial port error - device probably disconnected, exit quietly
                break
            except Exception as e:
                if self.on_error:
                    self.on_error(e)
                break
    
    def _handle_frame(self, frame: Frame):
        """Internal frame handler that calls user callback"""
        if self.on_frame:
            self.on_frame(frame)
    
    def send_frame(self, msg_type: int, payload: bytes = b'') -> bool:
        """
        Send a frame to the token with proper byte stuffing.
        
        Args:
            msg_type: Message type byte
            payload: Payload bytes
            
        Returns:
            True if sent successfully
        """
        if not self._serial or not self._serial.is_open:
            return False
        
        from .protocol import SOF_BYTE, EOF_BYTE, ESC_BYTE, ESC_SUB_SOF, ESC_SUB_EOF, ESC_SUB_ESC
        
        try:
            # Build frame: Type(1) + Length(2) + Payload(N) + Checksum(1)
            payload_len = len(payload)
            frame_data = bytearray()
            frame_data.append(msg_type)
            frame_data.append((payload_len >> 8) & 0xFF)  # Length MSB
            frame_data.append(payload_len & 0xFF)         # Length LSB
            frame_data.extend(payload)
            
            # Calculate checksum
            checksum = sum(frame_data) & 0xFF
            frame_data.append(checksum)
            
            # Helper to send byte-stuffed data
            def send_stuffed(byte_val):
                if byte_val == SOF_BYTE:
                    self._serial.write(bytes([ESC_BYTE, ESC_SUB_SOF]))
                elif byte_val == EOF_BYTE:
                    self._serial.write(bytes([ESC_BYTE, ESC_SUB_EOF]))
                elif byte_val == ESC_BYTE:
                    self._serial.write(bytes([ESC_BYTE, ESC_SUB_ESC]))
                else:
                    self._serial.write(bytes([byte_val]))
            
            # Send SOF
            self._serial.write(bytes([SOF_BYTE]))
            
            # Send stuffed frame data
            for byte in frame_data:
                send_stuffed(byte)
            
            # Send EOF
            self._serial.write(bytes([EOF_BYTE]))
            
            # Flush
            self._serial.flush()
            return True
            
        except Exception as e:
            if self.on_error:
                self.on_error(e)
            return False
    
    @property
    def is_connected(self) -> bool:
        """Check if serial port is connected"""
        return self._serial is not None and self._serial.is_open
    
    @property
    def is_running(self) -> bool:
        """Check if background thread is running"""
        return self._running
