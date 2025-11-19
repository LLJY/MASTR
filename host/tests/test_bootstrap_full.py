import unittest
from unittest.mock import MagicMock, patch
import os
import struct
import time
import threading
from enum import IntEnum
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature

from host.bootstrap import BootstrapHost, BootstrapPanic
from host.protocol import MessageType, Frame
from host.crypto import NaiveCrypto
from host.logger import Logger

# Disable logging output during tests
Logger.enabled = False

class MockTokenState(IntEnum):
    INITIAL = 0x00
    WAIT_ECDH = 0x20
    ECDH_DONE = 0x21
    CHANNEL_VERIFY = 0x22
    INTEGRITY_VERIFY = 0x30
    BOOT_OK_SENT = 0x32
    RUNTIME = 0x40
    HALT = 0xFF

class MockToken:
    """
    Fully functional software simulation of the MASTR hardware token.
    Implements the complete protocol state machine and cryptographic operations.
    """
    def __init__(self):
        # Permanent Key (P-256)
        self.privkey = ec.generate_private_key(ec.SECP256R1())
        self.pubkey = self.privkey.public_key()
        self.pubkey_bytes = self.pubkey.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )[1:] # Skip 0x04 prefix for raw bytes

        # State
        self.state = MockTokenState.WAIT_ECDH
        self.is_encrypted = False
        self.session_key = None
        self.aes_gcm = None
        
        # Host info
        self.host_pubkey = None
        self.golden_hash = bytes(32) # Default zero hash
        
        # Ephemeral
        self.ephemeral_privkey = None
        self.ephemeral_pubkey = None
        self.integrity_nonce = None

        # Output queue (frames to send to host)
        self.out_queue = []
        
        # Halt spam thread
        self.halt_spam_thread = None
        self.halt_spam_running = False
        
        # Session management
        self.session_valid = False
        self.session_start_timestamp = 0
        self.session_timeout_ms = 30000

    def set_host_pubkey(self, pubkey_bytes):
        """Provision host public key"""
        # Add 0x04 prefix for X962 format
        try:
            self.host_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b'\x04' + pubkey_bytes
            )
        except Exception as e:
            print(f"MockToken: Failed to load host pubkey: {e}")

    def set_golden_hash(self, hash_bytes):
        """Provision golden hash"""
        self.golden_hash = hash_bytes

    def receive_frame(self, msg_type: int, payload: bytes):
        """Process incoming frame from host"""
        
        # Decrypt if necessary
        if self.is_encrypted:
            try:
                # Expect IV (12) + Ciphertext + Tag (16)
                if len(payload) < 28:
                    self._send_error(0x01, "Payload too short for encryption")
                    return
                
                iv = payload[:12]
                tag = payload[-16:]
                ciphertext = payload[12:-16]
                
                # AESGCM.decrypt expects ciphertext + tag concatenated
                payload = self.aes_gcm.decrypt(iv, ciphertext + tag, None)
            except Exception as e:
                print(f"MockToken: Decryption failed: {e}")
                self._send_error(0x02, "Decryption failed")
                return

        self._handle_message(msg_type, payload)

    def _send_frame(self, msg_type: int, payload: bytes):
        """Queue outgoing frame (encrypting if needed)"""
        if self.is_encrypted:
            iv = os.urandom(12)
            # AESGCM.encrypt returns ciphertext + tag
            ciphertext_tag = self.aes_gcm.encrypt(iv, payload, None)
            # Format: IV + Ciphertext + Tag (tag is already at end of ciphertext_tag)
            # Wait, AESGCM.encrypt returns ciphertext + tag. 
            # Our protocol expects IV + Ciphertext + Tag.
            # So we just prepend IV.
            # Wait, let's check how SerialHandler does it.
            # SerialHandler: iv = os.urandom(12); ciphertext = aesgcm.encrypt(iv, data, None); return iv + ciphertext
            # Yes, that matches.
            payload = iv + ciphertext_tag
            
        self.out_queue.append(Frame(MessageType(msg_type), payload))

    def _send_error(self, code, msg):
        payload = bytes([code]) + msg.encode('utf-8')
        self._send_frame(MessageType.T2H_ERROR, payload)

    def _handle_message(self, msg_type, payload):
        # State Machine
        
        if msg_type == MessageType.H2T_ECDH_SHARE:
            if self.state != MockTokenState.WAIT_ECDH:
                self._send_error(0x10, "Wrong state for ECDH")
                return
            
            if len(payload) != 128:
                self._send_error(0x11, "Invalid ECDH length")
                return

            host_eph_pub_bytes = payload[:64]
            host_sig_raw = payload[64:]

            # Convert raw signature (R||S) to DER for verification
            try:
                r = int.from_bytes(host_sig_raw[:32], 'big')
                s = int.from_bytes(host_sig_raw[32:], 'big')
                host_sig_der = encode_dss_signature(r, s)
                
                self.host_pubkey.verify(
                    host_sig_der,
                    host_eph_pub_bytes,
                    ec.ECDSA(hashes.SHA256())
                )
            except (ValueError, InvalidSignature):
                self._send_error(0x12, "Invalid ECDH signature")
                return

            # Generate own ephemeral key
            self.ephemeral_privkey = ec.generate_private_key(ec.SECP256R1())
            self.ephemeral_pubkey = self.ephemeral_privkey.public_key()
            eph_pub_bytes = self.ephemeral_pubkey.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )[1:]

            # Compute shared secret
            host_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b'\x04' + host_eph_pub_bytes
            )
            shared_secret = self.ephemeral_privkey.exchange(ec.ECDH(), host_eph_pub)

            # Derive session key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=16,
                salt=b"MASTR-Session-Key-v1",
                info=b"",
            )
            self.session_key = hkdf.derive(shared_secret)
            self.aes_gcm = AESGCM(self.session_key)

            # Sign own ephemeral key
            signature = self.privkey.sign(
                eph_pub_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            # Convert DER signature to raw r,s (64 bytes)
            # This is tricky in Python crypto lib, usually returns DER.
            # For simplicity in mock, we'll just assume the host accepts DER or we pad it?
            # Wait, host/tpm2_crypto.py expects raw 64 bytes.
            # Let's just use a dummy signature for the mock if the host doesn't strictly validate format,
            # OR we do it properly.
            # Proper way: decode DER, extract r,s, pad to 32 bytes each.
            r, s = decode_dss_signature(signature)
            raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

            # Send response
            resp_payload = eph_pub_bytes + raw_sig
            self._send_frame(MessageType.T2H_ECDH_SHARE, resp_payload)
            
            self.state = MockTokenState.ECDH_DONE
            
            # Add 1000ms delay matching firmware behavior
            time.sleep(1.0)
            
            # Token initiates channel verify
            self.is_encrypted = True # Enable encryption now
            self._send_frame(MessageType.T2H_CHANNEL_VERIFY_REQUEST, b'ping')
            self.state = MockTokenState.CHANNEL_VERIFY

        elif msg_type == MessageType.H2T_CHANNEL_VERIFY_RESPONSE:
            if self.state != MockTokenState.CHANNEL_VERIFY:
                self._send_error(0x20, "Wrong state for Channel Verify")
                return
            
            if payload != b'pong':
                self._send_error(0x21, "Invalid pong")
                return
            
            # Advance to Integrity
            self.state = MockTokenState.INTEGRITY_VERIFY
            self.integrity_nonce = os.urandom(4)
            self._send_frame(MessageType.T2H_INTEGRITY_CHALLENGE, self.integrity_nonce)

        elif msg_type == MessageType.H2T_INTEGRITY_RESPONSE:
            if self.state != MockTokenState.INTEGRITY_VERIFY:
                self._send_error(0x30, "Wrong state for Integrity")
                return
            
            if len(payload) != 96:
                self._send_frame(MessageType.T2H_NACK, b'')
                return
            
            rx_hash = payload[:32]
            rx_sig = payload[32:]
            
            # Verify signature FIRST (Security Critical: Check signature before hash)
            try:
                # Host sends hash + signature. Signature is over (hash + nonce)
                msg_to_verify = rx_hash + self.integrity_nonce
                
                # Convert raw signature to DER
                r = int.from_bytes(rx_sig[:32], 'big')
                s = int.from_bytes(rx_sig[32:], 'big')
                rx_sig_der = encode_dss_signature(r, s)
                
                self.host_pubkey.verify(
                    rx_sig_der,
                    msg_to_verify,
                    ec.ECDSA(hashes.SHA256())
                )
            except (ValueError, InvalidSignature):
                self._enter_halt_state()
                return
            
            # Verify golden hash SECOND
            if rx_hash != self.golden_hash:
                # Enter HALT state
                self._enter_halt_state()
                return
                
            # Success
            self.state = MockTokenState.BOOT_OK_SENT
            self._send_frame(MessageType.T2H_BOOT_OK, b'')

        elif msg_type == MessageType.H2T_BOOT_OK_ACK:
            if self.state != MockTokenState.BOOT_OK_SENT:
                self._send_error(0x40, "Wrong state for BOOT_ACK")
                return
            
            self.state = MockTokenState.RUNTIME
            # Session established
            self.session_valid = True
            self.session_start_timestamp = time.time()

        else:
            self._send_error(0xFF, "Unknown message")

    def _enter_halt_state(self):
        """Enter permanent halt state and spam error messages"""
        self.state = MockTokenState.HALT
        self.halt_spam_running = True
        self.halt_spam_thread = threading.Thread(target=self._halt_spam_loop)
        self.halt_spam_thread.daemon = True
        self.halt_spam_thread.start()
        
    def _halt_spam_loop(self):
        """Spam T2H_INTEGRITY_FAIL_HALT every second"""
        while self.halt_spam_running:
            self._send_frame(MessageType.T2H_INTEGRITY_FAIL_HALT, b'')
            time.sleep(1.0)
            
    def stop(self):
        """Stop any background threads"""
        self.halt_spam_running = False
        if self.halt_spam_thread:
            self.halt_spam_thread.join(timeout=0.5)


class TestBootstrapComprehensive(unittest.TestCase):
    def setUp(self):
        # Create Mock Token
        self.token = MockToken()
        
        # Create Host with NaiveCrypto (easier to manage keys than TPM mock)
        self.crypto = NaiveCrypto()
        # Ensure crypto has keys
        if not self.crypto.load_permanent_keys():
            self.crypto.generate_permanent_keypair()
        
        # Provision Token with Host Pubkey
        host_pub = self.crypto.get_host_permanent_pubkey()
        self.token.set_host_pubkey(host_pub)
        
        # Provision Host with Token Pubkey
        self.crypto.set_token_permanent_pubkey(self.token.pubkey_bytes)
        
        # Provision Token with Golden Hash
        # Default golden hash in host is SHA256(b"h\0") if file not provided
        # But bootstrap loads it. Let's set a known one.
        self.golden_hash = b'\xaa' * 32
        self.token.set_golden_hash(self.golden_hash)
        
        # Write golden hash to file (MASTRHost reads this file)
        with open('golden_hash.bin', 'wb') as f:
            f.write(self.golden_hash)
        
        # Mock Serial Handler
        self.mock_handler_patcher = patch('host.main.SerialHandler')
        self.MockSerialHandler = self.mock_handler_patcher.start()
        
        # Setup MockSerialHandler instance
        self.mock_serial = MagicMock()
        self.MockSerialHandler.return_value = self.mock_serial
        self.mock_serial.connect.return_value = True
        self.mock_serial.is_connected = True
        
        # Threading support for message delivery
        self.running = True
        self.delivery_thread = threading.Thread(target=self._delivery_loop)
        self.delivery_thread.daemon = True
        self.delivery_thread.start()
        
        # Wire up send_frame to token
        def side_effect_send_frame(msg_type, payload):
            # Encrypt if host expects encryption
            # Note: Real SerialHandler does this. Since we mock it, we must do it here.
            if hasattr(self, 'host_instance') and self.host_instance.crypto.should_encrypt():
                payload = self.host_instance.crypto.encrypt_payload(payload)
                
            self.token.receive_frame(msg_type, payload)
            return True
            
        self.mock_serial.send_frame.side_effect = side_effect_send_frame
        
    def _delivery_loop(self):
        """Background thread to deliver messages from token to host"""
        while self.running:
            if self.token.out_queue:
                # Get next frame
                frame = self.token.out_queue.pop(0)
                
                # Simulate network delay/processing time
                # This allows the host to update its state (e.g. enable encryption)
                # between messages if they were queued together.
                time.sleep(0.05)
                
                # Handle decryption if needed
                # We check if the HOST expects encryption
                if hasattr(self, 'host_instance'):
                    payload = frame.payload
                    if self.host_instance.crypto.should_encrypt():
                        try:
                            # Try to decrypt
                            # Note: frame.payload is (IV + Ciphertext + Tag)
                            decrypted = self.host_instance.crypto.decrypt_payload(payload)
                            frame = Frame(frame.msg_type, decrypted)
                        except Exception as e:
                            # If decryption fails, maybe it wasn't encrypted?
                            # Or maybe keys mismatch. Pass original.
                            pass
                    
                    self.host_instance.on_frame_received(frame)
            else:
                time.sleep(0.01)
        
    def tearDown(self):
        self.running = False
        self.delivery_thread.join(timeout=1.0)
        self.mock_handler_patcher.stop()
        
        # Cleanup golden hash file
        if os.path.exists('golden_hash.bin'):
            os.remove('golden_hash.bin')
            
        # Stop token threads
        self.token.stop()

    def test_full_handshake_success(self):
        """Test a complete successful handshake"""
        host = BootstrapHost(port='/dev/test', crypto=self.crypto, debug_mode=True)
        self.host_instance = host # For side_effect
        
        # Run bootstrap
        exit_code = host.bootstrap()
        
        self.assertEqual(exit_code, 0)
        self.assertEqual(self.token.state, MockTokenState.RUNTIME)

    def test_invalid_host_signature(self):
        """Test token rejecting invalid ECDH signature"""
        # Corrupt the host's signing key temporarily or mock the signing
        # Easier: Mock crypto.sign to return garbage
        
        with patch.object(self.crypto, 'sign_with_permanent_key', return_value=b'\x00'*64):
            host = BootstrapHost(port='/dev/test', crypto=self.crypto, debug_mode=True)
            self.host_instance = host
            
            exit_code = host.bootstrap()
            
            self.assertEqual(exit_code, 1)
            # Token should have stayed in WAIT_ECDH or sent error
            # Since it sends error, host fails
            
    def test_integrity_failure_golden_hash_mismatch(self):
        """Test token rejecting mismatching golden hash"""
        # Host computes different hash than token expects
        wrong_hash = b'\xbb' * 32
        
        # Overwrite golden hash file with wrong hash
        with open('golden_hash.bin', 'wb') as f:
            f.write(wrong_hash)
        
        host = BootstrapHost(port='/dev/test', crypto=self.crypto, debug_mode=True)
        self.host_instance = host
        
        exit_code = host.bootstrap()
        
        self.assertEqual(exit_code, 1)
        self.assertEqual(self.token.state, MockTokenState.HALT)

    def test_panic_on_debug_message(self):
        """Test host panic when receiving debug message in non-debug mode"""
        host = BootstrapHost(port='/dev/test', crypto=self.crypto, debug_mode=False)
        self.host_instance = host
        
        # Inject a debug message into the token's output queue
        # We need to do this while the host is running.
        # We can trigger it by mocking a step to inject it.
        
        # Let's inject it right after connection
        original_connect = self.mock_serial.connect
        def side_effect_connect():
            # Queue a debug message
            self.token.out_queue.append(Frame(MessageType.DEBUG_MSG, b"I am a spy"))
            return True
        self.mock_serial.connect.side_effect = side_effect_connect
        
        exit_code = host.bootstrap()
        
        self.assertEqual(exit_code, 1)
        # Should have logged PANIC

    def test_out_of_order_message(self):
        """Test token rejecting out of order message"""
        # We can't easily force the host to send out of order with the real host code.
        # But we can verify the token mock rejects it.
        
        self.token.receive_frame(MessageType.H2T_INTEGRITY_RESPONSE, b'\x00'*96)
        
        # Token should send error
        self.assertTrue(len(self.token.out_queue) > 0)
        frame = self.token.out_queue[0]
        self.assertEqual(frame.msg_type, MessageType.T2H_ERROR)

if __name__ == '__main__':
    unittest.main()
