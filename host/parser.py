"""
Frame parser for the Host-Token protocol.
Handles byte stuffing, frame detection, and checksum verification.
"""
# AI use delcaration: ONLY the skeleton code and documentation here is ai assisted.
from typing import Optional, Callable
from .protocol import (
    Frame, MessageType, get_message_name,
    SOF_BYTE, EOF_BYTE, ESC_BYTE,
    ESC_SUB_SOF, ESC_SUB_EOF, ESC_SUB_ESC,
    MAX_PAYLOAD_SIZE
)


class FrameParserError(Exception):
    """Base exception for frame parsing errors"""
    pass


class ChecksumError(FrameParserError):
    """Raised when frame checksum validation fails"""
    pass


class ProtocolError(FrameParserError):
    """Raised when protocol violation is detected"""
    pass


class FrameParser:
    """
    Stateful parser for protocol frames.
    Handles byte-stuffing and frame boundaries.
    """
    
    def __init__(self, on_frame: Optional[Callable[[Frame], None]] = None):
        """
        Initialize the frame parser.
        
        Args:
            on_frame: Optional callback called when a complete frame is received
        """
        self.on_frame = on_frame
        self._reset()
    
    def _reset(self):
        """Reset parser state"""
        self._in_frame = False
        self._in_escape = False
        self._frame_buffer = bytearray()
    
    def feed_byte(self, byte: int) -> Optional[Frame]:
        """
        Feed a single byte to the parser.
        
        Args:
            byte: Byte value (0-255)
            
        Returns:
            Frame if a complete frame was parsed, None otherwise
            
        Raises:
            ProtocolError: If an invalid escape sequence is encountered
        """
        # Handle escape sequences
        if self._in_escape:
            self._in_escape = False
            
            if byte == ESC_SUB_SOF:
                unstuffed_byte = SOF_BYTE
            elif byte == ESC_SUB_EOF:
                unstuffed_byte = EOF_BYTE
            elif byte == ESC_SUB_ESC:
                unstuffed_byte = ESC_BYTE
            else:
                # Invalid escape sequence
                self._reset()
                raise ProtocolError(f"Invalid escape sequence: 0x{byte:02X}")
            
            if self._in_frame and len(self._frame_buffer) < (MAX_PAYLOAD_SIZE + 4):
                self._frame_buffer.append(unstuffed_byte)
            return None
        
        # Handle special bytes
        if byte == SOF_BYTE:
            # Start of frame - reset state
            self._in_frame = True
            self._in_escape = False
            self._frame_buffer.clear()
            return None
        
        elif byte == EOF_BYTE:
            # End of frame - process if we were in a frame
            if self._in_frame:
                self._in_frame = False
                try:
                    frame = self._process_frame()
                    if self.on_frame and frame:
                        self.on_frame(frame)
                    return frame
                except FrameParserError:
                    raise
                finally:
                    self._reset()
            return None
        
        elif byte == ESC_BYTE:
            # Start of escape sequence
            self._in_escape = True
            return None
        
        else:
            # Normal data byte
            if self._in_frame and len(self._frame_buffer) < (MAX_PAYLOAD_SIZE + 4):
                self._frame_buffer.append(byte)
            return None
    
    def feed(self, data: bytes) -> list[Frame]:
        """
        Feed multiple bytes to the parser.
        
        Args:
            data: Bytes to parse
            
        Returns:
            List of complete frames parsed from the data
        """
        frames = []
        for byte in data:
            frame = self.feed_byte(byte)
            if frame:
                frames.append(frame)
        return frames
    
    def _process_frame(self) -> Optional[Frame]:
        """
        Process a complete frame buffer.
        
        Returns:
            Parsed Frame object
            
        Raises:
            FrameParserError: If frame is invalid
        """
        # Frame must have at least 4 bytes: Type(1), Length(2), Checksum(1)
        if len(self._frame_buffer) < 4:
            raise FrameParserError(f"Frame too short ({len(self._frame_buffer)} bytes)")
        
        # Extract message type
        msg_type_byte = self._frame_buffer[0]
        
        # Extract payload length (big-endian)
        payload_len = (self._frame_buffer[1] << 8) | self._frame_buffer[2]
        
        # Extract checksum (last byte)
        received_checksum = self._frame_buffer[-1]
        
        # Verify length consistency
        actual_payload_len = len(self._frame_buffer) - 4
        if payload_len != actual_payload_len:
            raise FrameParserError(
                f"Length mismatch: header says {payload_len}, actual is {actual_payload_len}"
            )
        
        # Verify checksum
        calculated_checksum = sum(self._frame_buffer[:-1]) & 0xFF
        if calculated_checksum != received_checksum:
            raise ChecksumError(
                f"Checksum mismatch: expected {calculated_checksum}, got {received_checksum}"
            )
        
        # Extract payload
        payload = bytes(self._frame_buffer[3:-1])
        
        # Create frame
        try:
            msg_type = MessageType(msg_type_byte)
        except ValueError:
            # Unknown message type - still create frame but with raw value
            msg_type = msg_type_byte
        
        return Frame(msg_type=msg_type, payload=payload)
