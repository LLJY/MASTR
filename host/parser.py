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
    
    def __init__(self, on_frame: Optional[Callable[[bytes], None]] = None):
        """
        Initialize the frame parser.
        
        Args:
            on_frame: Callback called when a complete frame is received
        """
        self.on_frame = on_frame
        self._reset()
    
    def _reset(self):
        """Reset parser state"""
        self._in_frame = False
        self._in_escape = False
        self._frame_buffer = bytearray()
    
    def feed_byte(self, byte: int) -> Optional[bytes]:
        """
        Feed a single byte to the parser.
        
        Args:
            byte: Byte value (0-255)
            
        Returns:
            Frame bytes if complete, None otherwise
            
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
                frame_bytes = bytes(self._frame_buffer)
                self._reset()
                if self.on_frame:
                    self.on_frame(frame_bytes)
                return frame_bytes
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
    
    def feed(self, data: bytes) -> list[bytes]:
        """
        Feed multiple bytes to the parser.
        
        Args:
            data: Bytes to parse
            
        Returns:
            List of complete frames parsed from the data
        """
        frames = []
        for byte in data:
            frame_bytes = self.feed_byte(byte)
            if frame_bytes:
                frames.append(frame_bytes)
        return frames
