"""
Protocol definitions for the Host-Token communication.
Mirrors the C protocol definitions from protocol.h
"""
# AI use delcaration: ONLY the skeleton code and documentation here is ai assisted.

from enum import IntEnum
from typing import NamedTuple

# Protocol constants
MAX_PAYLOAD_SIZE = 256
SOF_BYTE = 0x7F
EOF_BYTE = 0x7E
ESC_BYTE = 0x7D
ESC_SUB_SOF = 0x5F
ESC_SUB_EOF = 0x5E
ESC_SUB_ESC = 0x5D


class MessageType(IntEnum):
    """Message types for Host-Token protocol"""
    
    # Class 0: System Control Messages
    T2H_ERROR = 0x00
    T2H_NACK = 0x01
    
    # Phase 1: Mutual Attestation & Secure Channel Establishment
    H2T_ECDH_SHARE = 0x20
    T2H_ECDH_SHARE = 0x21
    T2H_CHANNEL_VERIFY_REQUEST = 0x22   # Token sends encrypted challenge to Host
    H2T_CHANNEL_VERIFY_RESPONSE = 0x23  # Host sends encrypted response to Token
    
    # Phase 2: (ENCRYPTED OR SIGNED REQUESTS) - Integrity Verification & Runtime Guard
    T2H_INTEGRITY_CHALLENGE = 0x30
    H2T_INTEGRITY_RESPONSE = 0x31
    T2H_BOOT_OK = 0x32
    T2H_INTEGRITY_FAIL_HALT = 0x33
    H2T_BOOT_OK_ACK = 0x34
    H2T_INTEGRITY_FAIL_HALT = 0x35
    # mutual ACK for integrity fail.
    INTEGRITY_FAIL_ACK = 0X36
    
    # Runtime Heartbeat
    H2T_HEARTBEAT = 0x40
    T2H_HEARTBEAT_ACK = 0x41
    
    # Testing & Debug Commands (counting down from 0xFE)
    DEBUG_MSG = 0xFE
    H2T_TEST_RANDOM_REQUEST = 0xFD
    T2H_TEST_RANDOM_RESPONSE = 0xFC
    H2T_DEBUG_SET_HOST_PUBKEY = 0xFB
    T2H_DEBUG_GET_TOKEN_PUBKEY = 0xFA
    H2T_DEBUG_SET_GOLDEN_HASH = 0xF9


class Frame(NamedTuple):
    """Represents a parsed protocol frame"""
    msg_type: MessageType
    payload: bytes
    
    @property
    def is_debug(self) -> bool:
        """Check if this is a debug message"""
        return self.msg_type == MessageType.DEBUG_MSG
    
    @property
    def debug_text(self) -> str:
        """Get debug message text (only valid for debug messages)"""
        if self.is_debug:
            return self.payload.decode('utf-8', errors='replace')
        return ""
    
    def __str__(self) -> str:
        """String representation of the frame"""
        if self.is_debug:
            return f"DEBUG: {self.debug_text}"
        return f"Frame(type={self.msg_type.name}, payload_len={len(self.payload)})"


def get_message_name(msg_type: int) -> str:
    """Get human-readable name for a message type"""
    try:
        return MessageType(msg_type).name
    except ValueError:
        return f"UNKNOWN_0x{msg_type:02X}"
