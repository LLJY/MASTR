import unittest
from unittest.mock import MagicMock, patch
import sys
from host.bootstrap import BootstrapHost, BootstrapPanic
from host.protocol import MessageType

class TestBootstrapHost(unittest.TestCase):
    def setUp(self):
        self.mock_crypto = MagicMock()
        # Mock SerialHandler to avoid real connection attempts
        with patch('host.main.SerialHandler') as mock_handler_cls:
            self.host = BootstrapHost(port='/dev/test', crypto=self.mock_crypto, debug_mode=False)
            self.host.handler = MagicMock()
            
            # Mock internal methods to simulate success by default
            self.host._load_or_generate_keys = MagicMock(return_value=True)
            self.host._perform_ecdh_handshake = MagicMock(return_value=True)
            self.host._perform_channel_verification = MagicMock(return_value=True)
            self.host._perform_integrity_verification = MagicMock(return_value=True)
            self.host._store_session_key_for_runtime = MagicMock(return_value=True)

    def test_panic_on_debug_message(self):
        """Test that receiving a debug message raises BootstrapPanic when debug_mode is False"""
        self.host.debug_mode = False
        payload = b"This is a debug message"
        
        with self.assertRaises(BootstrapPanic):
            self.host._handle_debug_message(payload)

    def test_allow_debug_message_in_debug_mode(self):
        """Test that debug messages are allowed when debug_mode is True"""
        self.host.debug_mode = True
        payload = b"This is a debug message"
        
        try:
            self.host._handle_debug_message(payload)
        except BootstrapPanic:
            self.fail("BootstrapPanic raised in debug mode!")

    def test_bootstrap_success(self):
        """Test successful bootstrap returns 0"""
        self.host.handler.connect.return_value = True
        
        exit_code = self.host.bootstrap()
        self.assertEqual(exit_code, 0)
        
        # Verify sequence
        self.host.handler.connect.assert_called_once()
        self.host._load_or_generate_keys.assert_called_once()
        self.host._perform_ecdh_handshake.assert_called_once()
        self.host._perform_channel_verification.assert_called_once()
        self.host._perform_integrity_verification.assert_called_once()
        self.host._store_session_key_for_runtime.assert_called_once()

    def test_bootstrap_failure_connect(self):
        """Test failure to connect returns 1"""
        self.host.handler.connect.return_value = False
        exit_code = self.host.bootstrap()
        self.assertEqual(exit_code, 1)

    def test_bootstrap_failure_handshake(self):
        """Test failure in handshake returns 1"""
        self.host.handler.connect.return_value = True
        self.host._perform_ecdh_handshake.return_value = False
        
        exit_code = self.host.bootstrap()
        self.assertEqual(exit_code, 1)

if __name__ == '__main__':
    unittest.main()
