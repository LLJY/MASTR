"""
Mutual Authentication Demo

Demonstrates the full ECDH key exchange protocol with hardware crypto (ATECC608A):
1. Load permanent keys from files
2. Generate host ephemeral keypair
3. Sign ephemeral pubkey with host permanent key
4. Send H2T_ECDH_SHARE to token
5. Receive T2H_ECDH_SHARE from token
6. Verify token's signature
7. Compute ECDH shared secret
8. Derive AES session key via HKDF
9. Receive encrypted ping challenge
10. Send encrypted pong response

This is a DEMO - production code should be in main.py
"""

import time
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .serial_handler import SerialHandler
from .protocol import MessageType
from .crypto import CryptoHandler


class MutualAuthDemo:
    """Manages the mutual authentication demo flow"""
    
    def __init__(self, port: str, baudrate: int = 115200):
        """
        Initialize demo.
        
        Args:
            port: Serial port path
            baudrate: Serial baud rate
        """
        self.port = port
        self.baudrate = baudrate
        
        # Synchronization
        self.token_ecdh_share_received = None
        self.channel_challenge_received = None
        self.ecdh_complete_event = threading.Event()
        self.challenge_event = threading.Event()
        
        # State
        self.crypto_handler = None
        self.buffered_challenge_frame = None
        
        # Keys
        self.host_permanent_privkey = None
        self.token_permanent_pubkey_raw = None
    
    def on_frame_callback(self, frame):
        """Handles received frames with automatic decryption for encrypted messages."""
        print(f"\n[FRAME] Type: 0x{frame.msg_type.value:02X} ({frame.msg_type.name}), Length: {len(frame.payload)}")
        
        if frame.msg_type == MessageType.DEBUG_MSG:
            payload = frame.payload
            if self.crypto_handler:
                try:
                    decrypted = self.crypto_handler.decrypt_payload(payload)
                    if decrypted:
                        payload = decrypted
                except Exception:
                    pass
            
            try:
                debug_text = payload.decode('utf-8', errors='replace')
                print(f"   DEBUG: {debug_text}", end='')
            except Exception:
                print(f"   DEBUG (decode error): {payload.hex()}")
        
        elif frame.msg_type == MessageType.T2H_ECDH_SHARE:
            if len(frame.payload) == 128:
                self.token_ecdh_share_received = frame.payload
                self.ecdh_complete_event.set()
            else:
                print(f"   ERROR: Invalid payload length: {len(frame.payload)} (expected 128)")
                
        elif frame.msg_type == MessageType.T2H_CHANNEL_VERIFY_REQUEST:
            if self.crypto_handler:
                self.crypto_handler.set_protocol_state(0x22)
            
            if self.crypto_handler:
                decrypted = self.crypto_handler.decrypt_payload(frame.payload)
                if decrypted and len(decrypted) >= 4 and decrypted[:4] == b"ping":
                    self.channel_challenge_received = decrypted
                    self.challenge_event.set()
            else:
                self.buffered_challenge_frame = frame.payload
        
        else:
            print(f"   Payload (hex): {frame.payload[:64].hex()}{'...' if len(frame.payload) > 64 else ''}")
    
    def load_keys(self):
        """Load permanent keys from files"""
        try:
            with open('host_permanent_privkey.pem', 'rb') as f:
                self.host_permanent_privkey = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open('token_permanent_pubkey.bin', 'rb') as f:
                self.token_permanent_pubkey_raw = f.read()
            print("✓ Loaded permanent keys from files")
            return True
        except FileNotFoundError:
            print("ERROR: Key files not found. Run test_debug_keys.py first.")
            return False
    
    def run(self):
        """Execute the full mutual authentication demo"""
        
        # Load keys
        if not self.load_keys():
            return 1
        
        # Create serial handler
        sh = SerialHandler(self.port, on_frame=self.on_frame_callback)
        
        if not sh.connect():
            print("ERROR: Failed to connect to serial port")
            return 1
        
        sh.start()
        
        print("\n=== ECDH Key Exchange Demo ===")
        print("\n1. Generating host ephemeral keypair...")
        host_eph_privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
        host_eph_pubkey = host_eph_privkey.public_key()
        
        # Extract raw pubkey bytes (64 bytes: X || Y)
        pubkey_bytes = host_eph_pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        host_eph_pubkey_raw = pubkey_bytes[1:]  # Remove 0x04 prefix
        
        print(f"   Host ephemeral pubkey: {host_eph_pubkey_raw[:32].hex()}...")
        
        print("\n2. Signing ephemeral pubkey with permanent key...")
        signature = self.host_permanent_privkey.sign(
            host_eph_pubkey_raw,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Convert DER signature to raw (R || S, 64 bytes)
        r, s = decode_dss_signature(signature)
        signature_raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        
        print(f"   Signature: {signature_raw[:32].hex()}...")
        
        print("\n3. Sending H2T_ECDH_SHARE (pubkey + signature)...")
        payload = host_eph_pubkey_raw + signature_raw
        print(f"   Payload length: {len(payload)} bytes")
        sh.send_frame(MessageType.H2T_ECDH_SHARE.value, payload)
        print("   Sent!")
        
        # Give time for debug messages to arrive
        time.sleep(0.5)
        
        print("\n4. Waiting for T2H_ECDH_SHARE (timeout: 10s)...")
        if not self.ecdh_complete_event.wait(timeout=10.0):
            print("\nERROR: Timeout waiting for token ECDH share")
            print("Check debug messages above for errors.")
            time.sleep(1.0)
            sh.stop()
            return 1
        
        print("\n5. Processing token's ECDH share...")
        token_eph_pubkey_raw = self.token_ecdh_share_received[:64]
        token_signature_raw = self.token_ecdh_share_received[64:]
        
        print(f"   Token ephemeral pubkey: {token_eph_pubkey_raw[:32].hex()}...")
        print(f"   Token signature: {token_signature_raw[:32].hex()}...")
        
        print("\n6. Verifying token's signature...")
        # Reconstruct token permanent pubkey
        token_permanent_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b'\x04' + self.token_permanent_pubkey_raw
        )
        
        # Convert raw signature to DER
        r = int.from_bytes(token_signature_raw[:32], 'big')
        s = int.from_bytes(token_signature_raw[32:], 'big')
        token_signature_der = encode_dss_signature(r, s)
        
        try:
            token_permanent_pubkey.verify(
                token_signature_der,
                token_eph_pubkey_raw,
                ec.ECDSA(hashes.SHA256())
            )
            print("   ✓ Token signature verified!")
        except Exception as e:
            print(f"   ERROR: Signature verification failed: {e}")
            sh.stop()
            return 1
        
        print("\n7. Computing ECDH shared secret...")
        # Reconstruct token ephemeral pubkey
        token_eph_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b'\x04' + token_eph_pubkey_raw
        )
        
        # Compute shared secret
        shared_secret = host_eph_privkey.exchange(ec.ECDH(), token_eph_pubkey)
        print(f"   Shared secret: {shared_secret.hex()}")
        
        print("\n8. Deriving AES session key via HKDF...")
        aes_session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # AES-128
            salt=b"MASTR-Session-Key-v1",
            info=b"",
            backend=default_backend()
        ).derive(shared_secret)
        
        print(f"   Session key: {aes_session_key.hex()}")
        
        # Initialize crypto handler with derived key
        self.crypto_handler = CryptoHandler(session_key=aes_session_key)
        self.crypto_handler.set_protocol_state(0x21)  # ECDH complete
        sh.crypto = self.crypto_handler
        
        # Check if challenge was buffered
        if self.buffered_challenge_frame:
            print("\n   Processing buffered challenge...")
            decrypted = self.crypto_handler.decrypt_payload(self.buffered_challenge_frame)
            if decrypted and len(decrypted) >= 4:
                print(f"   Challenge (decrypted): {decrypted!r}")
                if decrypted[:4] == b"ping":
                    self.channel_challenge_received = decrypted
                    self.challenge_event.set()
        
        print("\n9. Waiting for channel verification challenge...")
        if not self.challenge_event.wait(timeout=5.0):
            print("ERROR: Timeout waiting for challenge")
            sh.stop()
            return 1
        
        print("\n10. Sending pong response (liveliness check)...")
        pong_payload = b"pong"
        print(f"   Pong payload (len={len(pong_payload)}): {pong_payload!r}")
        sh.send_frame(MessageType.H2T_CHANNEL_VERIFY_RESPONSE.value, pong_payload)
        
        print("\n✅ ECDH complete! Secure channel established.")
        print(f"   Session key: {aes_session_key.hex()}")
        
        # Wait for final debug messages
        time.sleep(2.0)
        
        sh.stop()
        return 0


def run_demo(port: str = '/dev/ttyACM1', baudrate: int = 115200):
    """
    Run the mutual authentication demo.
    
    Args:
        port: Serial port path
        baudrate: Serial baud rate
    
    Returns:
        Exit code (0 = success)
    """
    demo = MutualAuthDemo(port, baudrate)
    return demo.run()
