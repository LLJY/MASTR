"""
HTTP client for MASTR API provisioning endpoints.

NOTE: This module is for DEBUG/TESTING only.
      Production provisioning uses the standalone HTML UI.
      REMOVE THIS FILE when main.py becomes production script.
"""

import requests
import socket
import time
import json
from typing import Optional, Dict, Any, Callable
from .logger import Logger, Colors


class MastrApiClient:
    """HTTP client for MASTR provisioning API (DEBUG ONLY)"""

    def __init__(self, base_url: str = "http://192.168.4.1", timeout: int = 10, max_retries: int = 3):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()

    def _retry_request(self, request_fn: Callable, operation_name: str) -> Any:
        """Retry a request up to max_retries times"""
        for attempt in range(1, self.max_retries + 1):
            try:
                return request_fn()
            except Exception as e:
                if attempt < self.max_retries:
                    Logger.substep(f"{Colors.YELLOW}⚠{Colors.RESET} {operation_name} failed (attempt {attempt}/{self.max_retries}): {e}")
                    time.sleep(1.0 * attempt)  # Exponential backoff
                else:
                    Logger.error(f"{operation_name} failed after {self.max_retries} attempts: {e}")
                    raise

    def check_provisioning_available(self) -> bool:
        """
        Check if provisioning endpoints are available (404 = already provisioned).
        Returns True if available, False if 404 (provisioned).
        """
        def _check():
            resp = self.session.get(
                f"{self.base_url}/api/provision/token_info",
                timeout=self.timeout
            )
            if resp.status_code == 404:
                return False  # Endpoints not registered = already provisioned
            elif resp.status_code == 200:
                return True  # Endpoints available
            else:
                raise Exception(f"Unexpected status: {resp.status_code}")

        try:
            return self._retry_request(_check, "Provisioning availability check")
        except Exception:
            return False

    def get_token_info(self) -> Optional[Dict[str, str]]:
        """GET /api/provision/token_info - Returns token pubkey (hex format)"""
        def _get():
            resp = self.session.get(
                f"{self.base_url}/api/provision/token_info",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                raise Exception("Token already provisioned (404)")
            else:
                raise Exception(f"Unexpected status: {resp.status_code}")

        try:
            return self._retry_request(_get, "Get token info")
        except Exception as e:
            Logger.error(f"Failed to get token info: {e}")
            return None

    def _raw_post(self, path: str, body: bytes) -> tuple[int, str]:
        """
        Raw socket POST to work around lwIP HTTP server buffering issue.

        The lwIP server processes requests as soon as it sees \\r\\n\\r\\n,
        before the body arrives. Using raw sockets ensures headers+body
        are sent together in a single TCP packet.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            # Extract host and port from base_url
            host = self.base_url.replace("http://", "").replace("https://", "")
            if ":" in host:
                host, port = host.split(":")
                port = int(port)
            else:
                port = 80

            sock.connect((host, port))

            # Build complete HTTP request (headers + body in one packet)
            http_request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode('ascii') + body

            # Send everything at once
            sock.sendall(http_request)

            # Read response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Check if we have complete response
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break

            sock.close()

            # Parse response
            response_str = response.decode('utf-8', errors='replace')
            lines = response_str.split('\r\n')
            status_line = lines[0]
            status_code = int(status_line.split()[1])

            # Extract body (after \r\n\r\n)
            body_start = response_str.find('\r\n\r\n')
            if body_start >= 0:
                body_str = response_str[body_start + 4:]
            else:
                body_str = ""

            return status_code, body_str

        except Exception as e:
            raise Exception(f"Raw POST failed: {e}")
        finally:
            try:
                sock.close()
            except:
                pass

    def post_host_pubkey(self, pubkey_hex: str) -> bool:
        """POST /api/provision/host_pubkey - Submit host public key (128 hex chars, raw body)"""
        def _post():
            body = pubkey_hex.encode('ascii')
            status_code, response_body = self._raw_post("/api/provision/host_pubkey", body)

            if status_code == 202:  # Accepted (non-blocking)
                return True
            else:
                raise Exception(f"Status {status_code}: {response_body}")

        try:
            self._retry_request(_post, "Post host pubkey")
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Host pubkey submitted (202 Accepted)")
            return True
        except Exception as e:
            Logger.error(f"Failed to post host pubkey: {e}")
            return False

    def get_host_pubkey_status(self) -> Optional[str]:
        """GET /api/provision/host_pubkey/status - Check write status"""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/provision/host_pubkey/status",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("status", "unknown")
            return None
        except Exception:
            return None

    def post_golden_hash(self, hash_hex: str) -> bool:
        """POST /api/provision/golden_hash - Submit golden hash (64 hex chars, raw body)"""
        def _post():
            body = hash_hex.encode('ascii')
            status_code, response_body = self._raw_post("/api/provision/golden_hash", body)

            if status_code == 202:
                return True
            else:
                raise Exception(f"Status {status_code}: {response_body}")

        try:
            self._retry_request(_post, "Post golden hash")
            Logger.substep(f"{Colors.GREEN}✓{Colors.RESET} Golden hash submitted (202 Accepted)")
            return True
        except Exception as e:
            Logger.error(f"Failed to post golden hash: {e}")
            return False

    def get_golden_hash_status(self) -> Optional[str]:
        """GET /api/provision/golden_hash/status - Check write status"""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/provision/golden_hash/status",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("status", "unknown")
            return None
        except Exception:
            return None

    def poll_status(self, check_fn: Callable, max_polls: int = 20, delay: float = 0.5) -> bool:
        """Poll a status endpoint until ready/success or failed/error or timeout"""
        for i in range(max_polls):
            status = check_fn()
            # C API inconsistency: host_pubkey uses "ready", golden_hash uses "success"
            if status in ("ready", "success"):
                return True
            elif status in ("failed", "error"):
                Logger.error(f"Token reported {status} status")
                return False
            elif status is None:
                # Network error, retry
                pass
            time.sleep(delay)

        Logger.error(f"Status polling timeout after {max_polls * delay:.1f}s")
        return False
