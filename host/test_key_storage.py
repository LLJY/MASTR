#!/usr/bin/env python3
"""
Test script for key storage backends (keyring and TPM2)

This script tests whether kernel keyring and TPM2 storage work
on your current system without needing a token device.

Usage:
    python3 -m host.test_key_storage
"""

import sys
import os

# Test key - 16 bytes (AES-128)
TEST_KEY = b"TestKey123456789"
TEST_KEY_ID = "mastr-test-key"


def test_keyring():
    """Test kernel keyring storage"""
    print("\n" + "="*60)
    print("Testing Kernel Keyring Storage")
    print("="*60)
    
    try:
        from host.keyring_storage import KeyringStorage
        from host.logger import Logger
        
        storage = KeyringStorage()
        
        # Check availability
        print("\n1. Checking availability...")
        if not storage.is_available():
            print("   ✗ Kernel keyring NOT available")
            print("   Possible reasons:")
            print("     - keyctl command not installed (install: apt-get install keyutils)")
            print("     - Kernel not compiled with CONFIG_KEYS=y")
            print("     - Insufficient permissions")
            return False
        print("   ✓ Kernel keyring is available")
        
        # Test store
        print("\n2. Testing store operation...")
        if not storage.store_session_key(TEST_KEY, TEST_KEY_ID):
            print("   ✗ Failed to store key")
            return False
        print("   ✓ Key stored successfully")
        
        # Test retrieve
        print("\n3. Testing retrieve operation...")
        retrieved = storage.retrieve_session_key(TEST_KEY_ID)
        if retrieved is None:
            print("   ✗ Failed to retrieve key")
            return False
        if retrieved != TEST_KEY:
            print(f"   ✗ Key mismatch!")
            print(f"      Stored:    {TEST_KEY.hex()}")
            print(f"      Retrieved: {retrieved.hex()}")
            return False
        print("   ✓ Key retrieved successfully")
        print(f"      Key: {retrieved.hex()}")
        
        # Test delete
        print("\n4. Testing delete operation...")
        if not storage.delete_session_key(TEST_KEY_ID):
            print("   ✗ Failed to delete key")
            return False
        print("   ✓ Key deleted successfully")
        
        # Verify deletion
        print("\n5. Verifying deletion...")
        retrieved = storage.retrieve_session_key(TEST_KEY_ID)
        if retrieved is not None:
            print("   ✗ Key still exists after deletion!")
            return False
        print("   ✓ Key no longer exists")
        
        print("\n" + "="*60)
        print("✅ Kernel Keyring Storage: ALL TESTS PASSED")
        print("="*60)
        return True
        
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tpm2():
    """Test TPM2 NVRAM storage"""
    print("\n" + "="*60)
    print("Testing TPM2 NVRAM Storage")
    print("="*60)
    
    try:
        from host.tpm2_storage import TPM2Storage
        from host.logger import Logger
        
        storage = TPM2Storage()
        
        # Check availability
        print("\n1. Checking availability...")
        if not storage.is_available():
            print("   ✗ TPM2 NOT available")
            print("   Possible reasons:")
            print("     - tpm2-tools not installed (install: apt-get install tpm2-tools)")
            print("     - No TPM2 hardware present")
            print("     - TPM disabled in BIOS")
            print("     - Insufficient permissions")
            print("\n   This is OK - TPM2 is optional (keyring is primary)")
            return False
        print("   ✓ TPM2 is available")
        
        # Test store
        print("\n2. Testing store operation...")
        if not storage.store_session_key(TEST_KEY, TEST_KEY_ID):
            print("   ✗ Failed to store key")
            return False
        print("   ✓ Key stored successfully")
        
        # Test retrieve
        print("\n3. Testing retrieve operation...")
        retrieved = storage.retrieve_session_key(TEST_KEY_ID)
        if retrieved is None:
            print("   ✗ Failed to retrieve key")
            return False
        if retrieved != TEST_KEY:
            print(f"   ✗ Key mismatch!")
            print(f"      Stored:    {TEST_KEY.hex()}")
            print(f"      Retrieved: {retrieved.hex()}")
            return False
        print("   ✓ Key retrieved successfully")
        print(f"      Key: {retrieved.hex()}")
        
        # Test delete
        print("\n4. Testing delete operation...")
        if not storage.delete_session_key(TEST_KEY_ID):
            print("   ✗ Failed to delete key")
            return False
        print("   ✓ Key deleted successfully")
        
        # Verify deletion
        print("\n5. Verifying deletion...")
        retrieved = storage.retrieve_session_key(TEST_KEY_ID)
        if retrieved is not None:
            print("   ✗ Key still exists after deletion!")
            return False
        print("   ✓ Key no longer exists")
        
        print("\n" + "="*60)
        print("✅ TPM2 NVRAM Storage: ALL TESTS PASSED")
        print("="*60)
        return True
        
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_hybrid():
    """Test hybrid storage (combines keyring + TPM2)"""
    print("\n" + "="*60)
    print("Testing Hybrid Key Storage")
    print("="*60)
    
    try:
        from host.hybrid_key_storage import HybridKeyStorage
        from host.logger import Logger
        
        storage = HybridKeyStorage()
        
        # Check availability
        print("\n1. Checking availability...")
        if not storage.is_available():
            print("   ✗ No storage backends available!")
            return False
        print("   ✓ At least one backend is available")
        
        # Test store
        print("\n2. Testing store operation (stores in all available backends)...")
        if not storage.store_session_key(TEST_KEY, TEST_KEY_ID):
            print("   ✗ Failed to store key")
            return False
        
        # Test retrieve
        print("\n3. Testing retrieve operation (tries keyring first, then TPM2)...")
        retrieved = storage.retrieve_session_key(TEST_KEY_ID)
        if retrieved is None:
            print("   ✗ Failed to retrieve key")
            return False
        if retrieved != TEST_KEY:
            print(f"   ✗ Key mismatch!")
            return False
        print("   ✓ Key retrieved successfully")
        
        # Test delete
        print("\n4. Testing delete operation...")
        if not storage.delete_session_key(TEST_KEY_ID):
            print("   ✗ Failed to delete key")
            return False
        print("   ✓ Key deleted successfully")
        
        print("\n" + "="*60)
        print("✅ Hybrid Key Storage: ALL TESTS PASSED")
        print("="*60)
        return True
        
    except ImportError as e:
        print(f"   ✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"   ✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all storage tests"""
    print("="*60)
    print("MASTR Key Storage Backend Tests")
    print("="*60)
    print("\nThis script tests whether key storage backends work on your system.")
    print("It does NOT require a MASTR token device.\n")
    
    results = {}
    
    # Test keyring
    results['keyring'] = test_keyring()
    
    # Test TPM2
    results['tpm2'] = test_tpm2()
    
    # Test hybrid
    results['hybrid'] = test_hybrid()
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Kernel Keyring: {'✅ PASS' if results['keyring'] else '❌ FAIL (optional)'}")
    print(f"TPM2 NVRAM:     {'✅ PASS' if results['tpm2'] else '❌ FAIL (optional)'}")
    print(f"Hybrid Storage: {'✅ PASS' if results['hybrid'] else '❌ FAIL'}")
    
    # Check if at least one backend works
    if results['keyring'] or results['tpm2']:
        print("\n✅ At least one storage backend works - system ready!")
        print("\nRecommendation:")
        if results['keyring']:
            print("  → Use kernel keyring (fast, ephemeral)")
        if results['tpm2']:
            print("  → TPM2 available as backup (persistent, hardware-backed)")
        return 0
    else:
        print("\n❌ No storage backends available - cannot deploy!")
        print("\nAction required:")
        print("  1. Install keyutils: sudo apt-get install keyutils")
        print("  2. OR install TPM2 tools: sudo apt-get install tpm2-tools")
        return 1


if __name__ == '__main__':
    sys.exit(main())