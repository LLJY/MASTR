"""
MASTR Configuration Constants

Configuration values for the MASTR protocol implementation.
"""

# Golden Hash Configuration
# File to hash for integrity verification during attestation
# This file's SHA256 hash is computed at runtime and sent to the token
# during integrity verification (Phase 2).
#
# Production: Should be a critical boot file (e.g., kernel image)
# Development: Can be any test file
# GOLDEN_HASH_FILE = "/boot/vmlinuz"

# Testing configuration
GOLDEN_HASH_FILE = "./testfile"

# Serial Port Configuration
# Default serial port for token communication
# Can be overridden via command-line arguments
DEFAULT_SERIAL_PORT = "/dev/ttyACM0"
DEFAULT_BAUDRATE = 115200

# TPM2 Resource Allocation
# Persistent handle for host permanent private key
TPM2_HOST_KEY_HANDLE = 0x81000080

# NVRAM index for token permanent public key
TPM2_TOKEN_PUBKEY_NV_INDEX = 0x01C00002

# Protocol Configuration
# Session timeout in seconds (for runtime heartbeat)
SESSION_TIMEOUT_SECONDS = 30

# Heartbeat interval in seconds
HEARTBEAT_INTERVAL_SECONDS = 5

# Maximum consecutive heartbeat timeouts before emergency shutdown
MAX_HEARTBEAT_TIMEOUTS = 3
