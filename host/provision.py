#!/usr/bin/env python3
"""
MASTR Host Provisioning Tool

Standalone tool for provisioning the host-side TPM2 cryptographic keys.
This is the production-recommended method for setting up host-token pairing.

Usage:
  python -m host.provision                         # Show status
  python -m host.provision --regenerate            # Generate new host keypair
  python -m host.provision --show-pubkey           # Display host public key
  python -m host.provision --set-token-pubkey <hex> # Store token public key
  python -m host.provision --show-token-pubkey     # Display token public key
  python -m host.provision --verify                # Verify provisioning complete

Provisioning Workflow:
  1. Generate host keypair: provision --regenerate
  2. Copy displayed host pubkey to token (via HTML UI)
  3. Copy token pubkey from HTML UI
  4. Store token pubkey: provision --set-token-pubkey <hex>
  5. Verify: provision --verify
"""

import sys
import argparse
from typing import Optional

from .tpm2_crypto import TPM2Crypto
from .logger import Logger, Colors
from .config import TPM2_HOST_KEY_HANDLE, TPM2_TOKEN_PUBKEY_NV_INDEX


class ProvisioningTool:
    """
    Host-side provisioning tool for MASTR protocol.

    Manages:
    - Host permanent keypair generation in TPM2
    - Token permanent pubkey storage in TPM2
    - Status display and verification
    """

    def __init__(self):
        """Initialize provisioning tool with TPM2 backend."""
        try:
            self.crypto = TPM2Crypto()
        except Exception as e:
            Logger.error(f"Failed to initialize TPM2: {e}")
            Logger.error("Is TPM2 available on this system?")
            sys.exit(1)

    def show_status(self) -> int:
        """
        Display current provisioning status.

        Returns:
            0 on success, 1 on error
        """
        Logger.header("MASTR Host Provisioning Status")
        print(f"TPM2 Host Key Handle: 0x{TPM2_HOST_KEY_HANDLE:08X}")
        print(f"TPM2 Token Pubkey NV Index: 0x{TPM2_TOKEN_PUBKEY_NV_INDEX:08X}")
        print()

        # Check host keypair
        Logger.section("Host Permanent Keypair")
        try:
            if self.crypto.load_permanent_keys():
                Logger.success("Host keypair exists in TPM2")
                host_pubkey = self.crypto.get_host_permanent_pubkey()
                if host_pubkey:
                    Logger.substep(f"Public key: {host_pubkey[:32].hex()}...")
            else:
                Logger.warning("Host keypair NOT found in TPM2")
                Logger.info("Run: python -m host.provision --regenerate")
        except Exception as e:
            Logger.error(f"Error checking host keypair: {e}")

        # Check token pubkey
        Logger.section("Token Permanent Public Key")
        try:
            if self.crypto.load_permanent_keys() and self.crypto.token_permanent_pubkey_raw:
                Logger.success("Token pubkey stored in TPM2")
                Logger.substep(f"Public key: {self.crypto.token_permanent_pubkey_raw[:32].hex()}...")
            else:
                Logger.warning("Token pubkey NOT stored in TPM2")
                Logger.info("Run: python -m host.provision --set-token-pubkey <hex>")
        except Exception as e:
            Logger.error(f"Error checking token pubkey: {e}")

        return 0

    def generate_host_keypair(self, force: bool = False) -> int:
        """
        Generate new host permanent keypair in TPM2.

        Args:
            force: If True, regenerate even if key exists

        Returns:
            0 on success, 1 on error
        """
        Logger.header("MASTR Host Keypair Generation")

        # Check if key already exists
        # If key doesn't exist, proceed with generation
        if not force:
            try:
                if self.crypto.load_permanent_keys():
                    Logger.warning("Host keypair already exists!")
                    Logger.info("Use --regenerate to force regeneration (will overwrite)")
                    return 1
            except Exception:
                pass  

        Logger.section("Generating Host Permanent Keypair")
        Logger.info("Creating P-256 ECC keypair in TPM2...")

        try:
            if not self.crypto.generate_permanent_keypair():
                Logger.error("Failed to generate keypair")
                return 1

            Logger.success("Host keypair generated successfully")
            Logger.substep(f"Stored at TPM2 handle: 0x{TPM2_HOST_KEY_HANDLE:08X}")

            # Display public key for copying to token
            host_pubkey = self.crypto.get_host_permanent_pubkey()
            if not host_pubkey:
                Logger.error("Failed to retrieve host public key")
                return 1

            host_pubkey_hex = host_pubkey.hex()

            print()
            Logger.section("Host Public Key (Copy to Token)")
            print("=" * 70)
            print(f"{Colors.GREEN}{host_pubkey_hex}{Colors.RESET}")
            print("=" * 70)
            print()
            Logger.info("Copy the above public key to the token via HTML UI")
            Logger.info("Token URL: http://192.168.4.1 (when connected to token AP)")

            return 0

        except Exception as e:
            Logger.error(f"Exception during keypair generation: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def show_host_pubkey(self) -> int:
        """
        Display host public key (if exists).

        Returns:
            0 on success, 1 on error
        """
        Logger.header("Host Public Key")

        try:
            if not self.crypto.load_permanent_keys():
                Logger.error("Host keypair not found")
                Logger.info("Run: python -m host.provision --regenerate")
                return 1

            host_pubkey = self.crypto.get_host_permanent_pubkey()
            if not host_pubkey:
                Logger.error("Failed to retrieve host public key")
                return 1

            host_pubkey_hex = host_pubkey.hex()

            print()
            print("=" * 70)
            print(f"{Colors.GREEN}{host_pubkey_hex}{Colors.RESET}")
            print("=" * 70)
            print()
            Logger.info("Copy this to the token provisioning UI")

            return 0

        except Exception as e:
            Logger.error(f"Error retrieving host public key: {e}")
            return 1

    def set_token_pubkey(self, token_pubkey_hex: str) -> int:
        """
        Store token permanent public key in TPM2.

        Args:
            token_pubkey_hex: Token public key as hex string (128 chars)

        Returns:
            0 on success, 1 on error
        """
        Logger.header("Store Token Public Key")

        # Validate hex format
        token_pubkey_hex = token_pubkey_hex.strip()

        if len(token_pubkey_hex) != 128:
            Logger.error(f"Invalid pubkey length: {len(token_pubkey_hex)} chars (expected 128)")
            Logger.info("Token pubkey should be 64 bytes = 128 hex characters")
            return 1

        try:
            token_pubkey_bytes = bytes.fromhex(token_pubkey_hex)
        except ValueError as e:
            Logger.error(f"Invalid hex format: {e}")
            return 1

        if len(token_pubkey_bytes) != 64:
            Logger.error(f"Invalid pubkey byte length: {len(token_pubkey_bytes)} (expected 64)")
            return 1

        Logger.info("Storing token public key in TPM2...")
        Logger.substep(f"Token pubkey: {token_pubkey_hex[:32]}...")

        try:
            if not self.crypto.set_token_permanent_pubkey(token_pubkey_bytes):
                Logger.error("Failed to store token pubkey in TPM2")
                return 1

            Logger.success("Token public key stored successfully")
            Logger.substep(f"Stored at TPM2 NVRAM: 0x{TPM2_TOKEN_PUBKEY_NV_INDEX:08X}")

            return 0

        except Exception as e:
            Logger.error(f"Exception storing token pubkey: {e}")
            import traceback
            traceback.print_exc()
            return 1

    def show_token_pubkey(self) -> int:
        """
        Display stored token public key (if exists).

        Returns:
            0 on success, 1 on error
        """
        Logger.header("Token Public Key")

        try:
            if not self.crypto.load_permanent_keys():
                Logger.error("Failed to load keys from TPM2")
                return 1

            if not self.crypto.token_permanent_pubkey_raw:
                Logger.error("Token pubkey not found in TPM2")
                Logger.info("Run: python -m host.provision --set-token-pubkey <hex>")
                return 1

            token_pubkey_hex = self.crypto.token_permanent_pubkey_raw.hex()

            print()
            print("=" * 70)
            print(f"{Colors.CYAN}{token_pubkey_hex}{Colors.RESET}")
            print("=" * 70)
            print()

            return 0

        except Exception as e:
            Logger.error(f"Error retrieving token public key: {e}")
            return 1

    def verify_provisioning(self) -> int:
        """
        Verify that provisioning is complete (both keys exist).

        Returns:
            0 if complete, 1 if incomplete
        """
        Logger.header("Verify Provisioning Status")

        all_ok = True

        try:
            # Check if we can load both keys
            if not self.crypto.load_permanent_keys():
                Logger.error("Failed to load keys from TPM2")
                return 1

            # Check host keypair
            Logger.step(1, "Checking host permanent keypair...")
            host_pubkey = self.crypto.get_host_permanent_pubkey()
            if host_pubkey:
                Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Host keypair exists (TPM2 0x{TPM2_HOST_KEY_HANDLE:08X})")
            else:
                Logger.substep(f"{Colors.RED}✗{Colors.RESET} Host keypair missing")
                Logger.substep("   Run: python -m host.provision --regenerate")
                all_ok = False

            # Check token pubkey
            Logger.step(2, "Checking token permanent public key...")
            if self.crypto.token_permanent_pubkey_raw and len(self.crypto.token_permanent_pubkey_raw) == 64:
                Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Token pubkey stored (TPM2 NVRAM 0x{TPM2_TOKEN_PUBKEY_NV_INDEX:08X})")
            else:
                Logger.substep(f"{Colors.RED}✗{Colors.RESET} Token pubkey missing")
                Logger.substep("   Run: python -m host.provision --set-token-pubkey <hex>")
                all_ok = False

            print()
            if all_ok:
                Logger.success_header("✅ Provisioning Complete!")
                Logger.info("Host is ready for bootstrap and attestation")
                Logger.info("Next steps:")
                Logger.info("  1. Copy bootstrap.py into initramfs")
                Logger.info("  2. Reboot system")
                Logger.info("  3. Bootstrap will perform attestation automatically")
                return 0
            else:
                Logger.error("Provisioning incomplete - see errors above")
                return 1

        except Exception as e:
            Logger.error(f"Error verifying provisioning: {e}")
            return 1


def main() -> int:
    """
    Main entry point for provisioning tool.

    Returns:
        Exit code (0 = success)
    """
    parser = argparse.ArgumentParser(
        description='MASTR Host Provisioning Tool - TPM2-based key management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Show current provisioning status
  python -m host.provision

  # Generate host keypair and display pubkey
  python -m host.provision --regenerate

  # Show host public key (for copying to token)
  python -m host.provision --show-pubkey

  # Store token public key (received from token HTML UI)
  python -m host.provision --set-token-pubkey a1b2c3d4...

  # Display stored token pubkey
  python -m host.provision --show-token-pubkey

  # Verify provisioning is complete
  python -m host.provision --verify

Typical Workflow:
  1. python -m host.provision --regenerate
     → Copy displayed host pubkey to token HTML UI

  2. python -m host.provision --set-token-pubkey <hex-from-token>
     → Store token pubkey received from HTML UI

  3. python -m host.provision --verify
     → Confirm both keys are provisioned
        '''
    )

    # Mutually exclusive operation group
    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        '--regenerate',
        action='store_true',
        help='Generate new host permanent keypair (overwrites existing)'
    )

    group.add_argument(
        '--show-pubkey',
        action='store_true',
        help='Display host public key for copying to token'
    )

    group.add_argument(
        '--set-token-pubkey',
        type=str,
        metavar='HEX',
        help='Store token public key (128 hex chars = 64 bytes)'
    )

    group.add_argument(
        '--show-token-pubkey',
        action='store_true',
        help='Display stored token public key'
    )

    group.add_argument(
        '--verify',
        action='store_true',
        help='Verify that provisioning is complete'
    )

    args = parser.parse_args()

    # Initialize provisioning tool
    tool = ProvisioningTool()

    # Execute requested operation
    if args.regenerate:
        return tool.generate_host_keypair(force=True)

    elif args.show_pubkey:
        return tool.show_host_pubkey()

    elif args.set_token_pubkey:
        return tool.set_token_pubkey(args.set_token_pubkey)

    elif args.show_token_pubkey:
        return tool.show_token_pubkey()

    elif args.verify:
        return tool.verify_provisioning()

    else:
        return tool.show_status()


if __name__ == '__main__':
    sys.exit(main())
