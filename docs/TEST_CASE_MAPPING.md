# MASTR Firmware Test Case Mapping Document

**Project:** MASTR (Mutual Attested Secure Token for Robotics)
**Document Version:** 1.0
**Date:** 2025-11-23
**Total Test Cases:** 173
**Test Framework:** Unity (ThrowTheSwitch)

---

## Executive Summary

This document provides comprehensive test case mapping for the MASTR firmware, detailing 173 unit tests across 8 major test suites. The test coverage validates the security-critical components of the mutual attestation protocol, cryptographic operations, serial communication, and provisioning API.

### Test Distribution by Category

| Category | Test Count | Coverage | Priority |
|----------|-----------|----------|----------|
| Serial Communication | 17 | 90.2% | Critical |
| Protocol State Machine | 23 | 69.1% | Critical |
| Session Management | 17 | 69.1% | Critical |
| Cryptographic Operations | 15 | 52.1% | Critical |
| HTTP Server | 26 | 87.6% | High |
| WiFi AP Management | 26 | 47.3% | High |
| API Endpoints | 34 | 87.6% | Critical |
| Nonce Generation | 4 | 52.1% | High |
| Integrity Verification | 6 | 69.1% | Critical |
| Provisioning Security | 5 | 52.1% | Critical |
| **Total** | **173** | **68.7%** | - |

### Code Coverage Summary

| Module | Lines | Hit | Coverage | Source File |
|--------|-------|-----|----------|-------------|
| Serial Layer | 122 | 110 | 90.2% | `src/serial.c` |
| Protocol State Machine | 149 | 103 | 69.1% | `src/protocol.c` |
| Cryptographic Operations | 215 | 112 | 52.1% | `src/crypto.c` |
| HTTP Server | 121 | 106 | 87.6% | `src/net/http/http_server.c` |
| WiFi AP Manager | 74 | 35 | 47.3% | `src/net/wifi_ap.c` |
| AP Manager | 48 | 42 | 87.5% | `src/net/ap/ap_manager.c` |
| **Overall Average** | **729** | **508** | **68.7%** | - |

---

## Table of Contents

1. [Serial Communication Tests (17 tests)](#1-serial-communication-tests)
2. [Protocol State Machine Tests (23 tests)](#2-protocol-state-machine-tests)
3. [Session Management Tests (17 tests)](#3-session-management-tests)
4. [Cryptographic Operations Tests (15 tests)](#4-cryptographic-operations-tests)
5. [HTTP Server Tests (26 tests)](#5-http-server-tests)
6. [WiFi AP Management Tests (26 tests)](#6-wifi-ap-management-tests)
7. [API Endpoint Tests (34 tests)](#7-api-endpoint-tests)
8. [Supporting Test Suites](#8-supporting-test-suites)
9. [Traceability Matrix](#9-traceability-matrix)
10. [Security Requirements Coverage](#10-security-requirements-coverage)

---

## 1. Serial Communication Tests

**Test Suite:** `test_serial.c`
**Total Tests:** 17
**Coverage:** 90.2% (110/122 lines)
**Source Module:** `src/serial.c`

### 1.1 Framing and Byte Stuffing (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-S01 | `test_send_simple_packet` | Validates SOF/EOF framing and checksum calculation for simple payloads | 3-byte payload: `{0x01, 0x02, 0x03}` | 9-byte frame with correct checksum |
| TC-S02 | `test_send_with_all_special_bytes_in_payload` | Tests byte stuffing for SOF/EOF/ESC bytes in payload | Payload containing `{SOF_BYTE, EOF_BYTE, ESC_BYTE}` | All special bytes escaped with ESC prefix |
| TC-S03 | `test_send_zero_length_payload` | Edge case: frame creation with no payload | `NULL` payload, length `0` | Valid frame with `0x00 0x00` length field |

### 1.2 Frame Reception and Unstuffing (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-S04 | `test_receive_simple_packet` | Validates basic frame parsing and payload extraction | Valid 9-byte frame on wire | Handler called with correct message type and payload |
| TC-S05 | `test_receive_stuffed_packet` | Tests unstuffing of escaped bytes | Frame with ESC sequences for special bytes | Original payload reconstructed correctly |
| TC-S06 | `test_receive_zero_length_packet` | Edge case: receiving empty payload message | Frame with `0x00 0x00` length | Handler called with zero-length payload |
| TC-S07 | `test_ignore_bytes_before_SOF` | Resilience: garbage bytes before valid frame | `{0xDE, 0xAD, 0xBE, 0xEF}` followed by valid frame | Parser skips garbage, processes valid frame |
| TC-S08 | `test_recover_after_corrupted_frame` | Recovery: parser resyncs after corruption | Corrupted frame (no EOF) + valid frame | Second frame processed successfully |

### 1.3 Error Detection and Handling (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-S09 | `test_reject_bad_checksum` | Detects corrupted checksum | Frame with intentionally wrong checksum | Handler not called, shutdown signaled |
| TC-S10 | `test_reject_bad_length` | Detects length field mismatch | Length=5 declared but only 2 bytes provided | Frame rejected, shutdown signaled |
| TC-S11 | `test_reject_invalid_escape_sequence` | Detects illegal ESC byte usage | ESC followed by invalid substitute (0xFF) | Frame rejected gracefully |

### 1.4 Buffer Safety and Edge Cases (6 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-S12 | `test_rx_buffer_overflow_handling` | Ring buffer overflow protection | 600 bytes loaded into 512-byte buffer | Graceful handling (no crash) |
| TC-S13 | `test_rx_buffer_wraparound` | Ring buffer wraparound logic | Fill 500/512 bytes, add 50 more | Buffer wraps correctly without corruption |
| TC-S14 | `test_rx_buffer_concurrent_read_write` | Interrupt safety simulation | Simultaneous read/write operations | No corruption or crash |
| TC-S15 | `test_serial_max_payload_256_bytes` | Maximum payload size handling | 256-byte payload (MAX_PAYLOAD_SIZE) | Frame processed or rejected gracefully |
| TC-S16 | `test_serial_frame_fragmentation` | Multi-chunk frame assembly | Frame split into 3 chunks across USB transfers | Frame assembled correctly from fragments |
| TC-S17 | `test_serial_usb_disconnect_recovery` | USB disconnect/reconnect handling | Partial frame + disconnect + new valid frame | Parser recovers and processes new frame |

**Coverage Impact:** These tests cover 110/122 lines in `src/serial.c`, including:
- `send_message()` - Frame construction and byte stuffing
- `serial_process_data()` - Frame parsing and unstuffing
- `validate_frame()` - Checksum verification
- Ring buffer management functions

---

## 2. Protocol State Machine Tests

**Test Suite:** `test_protocol.c`
**Total Tests:** 23
**Coverage:** 69.1% (103/149 lines)
**Source Module:** `src/protocol.c`

### 2.1 Valid State Transitions (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-P01 | `test_state_transition_0x20_to_0x21_on_ecdh_share` | Phase 1: ECDH key exchange initiation | State `0x20`, 128-byte ECDH share (64B pubkey + 64B sig) | Transition to `0x21`, encryption enabled |
| TC-P02 | `test_state_transition_0x22_to_0x30_on_channel_verify` | Phase 1.5: Channel verification | State `0x22`, receive "pong" response | Transition to `0x30` (integrity check) |
| TC-P03 | `test_state_transition_0x30_to_0x32_on_valid_integrity` | Phase 2: Integrity verification | State `0x30`, matching 32B hash + 64B signature | Transition to `0x32` (BOOT_OK pending) |
| TC-P04 | `test_state_transition_0x32_to_0x40_on_boot_ack` | Phase 2: Boot acknowledgment | State `0x32`, receive BOOT_OK_ACK | Transition to `0x40` (runtime), session valid |
| TC-P05 | `test_heartbeat_accepted_in_runtime_state` | Phase 3: Runtime heartbeat processing | State `0x40`, valid session | Heartbeat timestamp updated, missed count reset |

### 2.2 Invalid State Rejections (4 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-P06 | `test_reject_integrity_response_in_wrong_state` | Protocol violation: integrity in wrong state | State `0x20` (should be `0x30`) | Shutdown triggered |
| TC-P07 | `test_reject_heartbeat_before_runtime` | Protocol violation: heartbeat too early | State `0x30` (should be `0x40`) | Heartbeat rejected, state unchanged |
| TC-P08 | `test_reject_boot_ack_in_wrong_state` | Protocol violation: boot ack in wrong state | State `0x40` (should be `0x32`) | Shutdown triggered |
| TC-P09 | `test_reject_channel_verify_in_wrong_state` | Protocol violation: channel verify out of order | State `0x40` (should be `0x22`) | Shutdown triggered |

### 2.3 Error Scenarios (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-P10 | `test_invalid_ecdh_share_length_triggers_shutdown` | Malformed message: wrong ECDH payload size | 64 bytes instead of 128 bytes | Shutdown triggered |
| TC-P11 | `test_invalid_integrity_length_sends_nack` | Malformed message: wrong integrity response size | 50 bytes instead of 96 bytes | NACK sent, state unchanged |
| TC-P12 | `test_bad_channel_verify_response_triggers_shutdown` | Failed channel verification | Receive "bad!" instead of "pong" | Shutdown triggered |
| TC-P13 | `test_failed_signature_verification_triggers_shutdown` | Cryptographic failure: invalid signature | Mock returns signature verification failure | Shutdown triggered |
| TC-P14 | `test_reattestation_keeps_old_session_key` | Re-attestation preserves session key | Valid session with AES key | Session invalid but key preserved |

### 2.4 Re-Attestation Cycle Tests (8 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-P15 | `test_ecdh_at_state_0x21_uses_existing_key` | Token-initiated ECDH uses existing ephemeral | State `0x21` with existing ephemeral key | Ephemeral key not regenerated |
| TC-P16 | `test_reattestation_full_cycle_0x40_to_0x40` | Complete re-attestation: runtime → runtime | State `0x40` → trigger re-attestation | Full cycle: `0x40→0x21→0x22→0x30→0x32→0x40` |
| TC-P17 | `test_reattestation_generates_new_ephemeral_key` | New ephemeral key on re-attestation | Runtime state with old ephemeral key | New ephemeral key generated |
| TC-P18 | `test_token_initiated_reattestation_0x21` | Token initiates re-attestation | State `0x40` → `protocol_trigger_reattestation()` | Advance to `0x21`, ephemeral key exists |
| TC-P19 | `test_reattestation_during_heartbeat_race` | Race condition: re-attestation + pending heartbeat | `missed_hb_count = 1`, trigger re-attestation | Re-attestation takes precedence |
| TC-P20 | `test_multiple_reattestation_cycles` | Sequential re-attestation stability | 3 consecutive re-attestation cycles | System stable, no shutdown |
| TC-P21 | `test_reattestation_timeout_during_cycle` | Timeout during re-attestation | State `0x21`, time exceeds timeout | Session invalid |
| TC-P22 | `test_encryption_persists_through_reattestation` | Encryption flag persistence | Encrypted session, trigger re-attestation | Encryption flag remains true |
| TC-P23 | `test_reattestation_key_rotation_verification` | Key rotation verification | Runtime → re-attestation | New ephemeral, old session key preserved |

**Coverage Impact:** These tests cover 103/149 lines in `src/protocol.c`, including:
- `protocol_handle_validated_message()` - State machine dispatcher
- `protocol_trigger_reattestation()` - Re-attestation initiation
- `protocol_invalidate_session()` - Session teardown
- State transition handlers for all protocol phases

---

## 3. Session Management Tests

**Test Suite:** `test_session.c`
**Total Tests:** 17
**Coverage:** 69.1% (103/149 lines, shared with protocol.c)
**Source Module:** `src/protocol.c` (session management functions)

### 3.1 Session Lifecycle (4 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-SS01 | `test_session_establishment` | Session creation on BOOT_OK_ACK | State `0x32`, receive BOOT_OK_ACK | `session_valid = true`, timestamp set |
| TC-SS02 | `test_session_is_valid_within_timeout` | Session validity check within timeout | Timeout=30s, elapsed=20s | `protocol_is_session_valid()` returns true |
| TC-SS03 | `test_session_invalid_after_timeout` | Session expiration detection | Timeout=30s, elapsed=35s | `protocol_is_session_valid()` returns false |
| TC-SS04 | `test_session_timestamp_tracking` | Timestamp accuracy on establishment | Mock time = 12345678 μs | `session_start_timestamp` matches mock time |

### 3.2 Session Invalidation (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-SS05 | `test_invalidate_session_keeps_old_key` | Key preservation during invalidation | Valid encrypted session | Session invalid, AES key unchanged |
| TC-SS06 | `test_invalidate_session_resets_to_ecdh_state` | State reset on invalidation | State `0x40` (runtime) | Reset to state `0x20` (ECDH) |
| TC-SS07 | `test_encryption_flag_persists_through_invalidation` | Encryption flag persistence | `is_encrypted = true` | Flag remains true after invalidation |

### 3.3 Re-Attestation (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-SS08 | `test_trigger_reattestation_invalidates_session` | Session invalidation trigger | Valid runtime session | `session_valid = false` |
| TC-SS09 | `test_trigger_reattestation_generates_new_ephemeral_key` | Ephemeral key regeneration | Existing ephemeral key | New deterministic key generated |
| TC-SS10 | `test_trigger_reattestation_advances_to_state_0x21` | State advancement on re-attestation | State `0x40` | Advance to state `0x21` |

### 3.4 Timeout and Heartbeat Management (7 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-SS11 | `test_session_custom_timeout` | Custom timeout configuration | Timeout=60s, check at 50s and 62s | Valid at 50s, invalid at 62s |
| TC-SS12 | `test_session_not_valid_when_flag_false` | Flag override of timeout | `session_valid = false`, within timeout | Invalid regardless of time |
| TC-SS13 | `test_heartbeat_resets_missed_count` | Missed heartbeat counter reset | `missed_hb_count = 3` → receive heartbeat | Counter reset to 0 |
| TC-SS14 | `test_halt_state_sets_flag` | Halt state flag management | Normal state → halt | `in_halt_state = true`, state = `0xFF` |
| TC-SS15 | `test_three_missed_heartbeats_should_trigger_shutdown` | Shutdown threshold detection | `missed_hb_count = 3` | Shutdown condition met |
| TC-SS16 | `test_two_missed_heartbeats_no_shutdown` | Below-threshold handling | `missed_hb_count = 2` | No shutdown triggered |
| TC-SS17 | `test_missed_heartbeat_counter_increments` | Counter increment logic | `missed_hb_count = 0` → increment | Counter = 1 |

---

## 4. Cryptographic Operations Tests

**Test Suite:** `test_crypto.c`
**Total Tests:** 15
**Coverage:** 52.1% (112/215 lines)
**Source Module:** `src/crypto.c`

### 4.1 AES-GCM Encryption (4 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-C01 | `test_aes_gcm_encrypt_decrypt_roundtrip` | Encrypt/decrypt round-trip | 32-byte plaintext with test key | Decrypted matches original plaintext |
| TC-C02 | `test_aes_gcm_decrypt_with_wrong_key` | Authentication tag verification | Encrypted with key A, decrypt with key B | Decryption fails (tag mismatch) |
| TC-C03 | `test_aes_gcm_decrypt_with_tampered_tag` | **CRITICAL:** Tag tampering detection | Modify last byte of authentication tag | Decryption fails, tampering detected |
| TC-C04 | `test_aes_gcm_encrypt_iv_uniqueness` | **CRITICAL:** IV reuse prevention | Encrypt same plaintext 100 times | All 100 IVs unique (no collisions) |

### 4.2 ECDH Key Exchange (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-C05 | `test_ecdh_shared_secret_computation` | P-256 shared secret derivation | Peer public key (64 bytes) | 32-byte shared secret (non-zero) |
| TC-C06 | `test_ecdh_ephemeral_key_generation` | Ephemeral keypair generation | Generate ephemeral P-256 key | 64-byte public key (non-zero) |
| TC-C07 | `test_ecdh_key_derivation_hkdf` | HKDF-SHA256 session key derivation | 32-byte shared secret | 16-byte AES-128 key (non-zero) |

### 4.3 ECDSA Signatures (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-C08 | `test_ecdsa_sign_with_permanent_key` | Sign with ATECC608A Slot 0 | 32-byte message | 64-byte signature (non-zero) |
| TC-C09 | `test_ecdsa_verify_valid_signature` | Valid signature acceptance | Valid message + signature + pubkey | Verification returns true |
| TC-C10 | `test_ecdsa_reject_invalid_signature` | **CRITICAL:** Signature forgery detection | Invalid signature bytes | Verification returns false |

### 4.4 ATECC608A Slot Operations (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-C11 | `test_atecc_read_host_pubkey_slot8` | Read host pubkey from Slot 8 Blocks 0-1 | 64-byte pubkey in slot | Read returns expected pubkey |
| TC-C12 | `test_atecc_write_host_pubkey_slot8` | Write host pubkey to Slot 8 | 64-byte pubkey | Write + read-back match |
| TC-C13 | `test_atecc_read_golden_hash_slot8_block2` | Read golden hash from Slot 8 Block 2 | 32-byte hash in slot | Read returns expected hash |
| TC-C14 | `test_atecc_write_golden_hash_slot8_block2` | Write golden hash to Slot 8 Block 2 | 32-byte hash | Write + read-back match |
| TC-C15 | `test_compute_sha256_consistency` | SHA-256 computation (indirect test) | N/A (tested via integrity verification) | Verified indirectly |

**Coverage Impact:** These tests cover 112/215 lines in `src/crypto.c`, including:
- `crypto_aes_gcm_encrypt()` / `crypto_aes_gcm_decrypt()` - AES-GCM operations
- `crypto_ecdh_generate_ephemeral_key()` - ECDH key generation
- `crypto_ecdh_compute_shared_secret()` - Shared secret derivation
- `crypto_derive_session_key()` - HKDF key derivation
- `crypto_ecdh_sign_with_permanent_key()` / `crypto_ecdh_verify_signature()` - ECDSA
- `crypto_get_golden_hash()` / `crypto_set_golden_hash()` - ATECC608A Slot 8 operations

---

## 5. HTTP Server Tests

**Test Suite:** `test_http_server.c`
**Total Tests:** 26
**Coverage:** 87.6% (106/121 lines)
**Source Module:** `src/net/http/http_server.c`

### 5.1 Route Registration and Matching (4 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-H01 | `test_http_route_registration_public` | Register public route | Register `/api/test` | Registration succeeds (return 0) |
| TC-H02 | `test_http_route_registration_with_auth` | Register authenticated route | Register `/api/secure` with auth flag | Route requires authentication |
| TC-H03 | `test_http_route_matching_success` | Route matching and handler invocation | GET `/api/ping` request | Handler called with correct request |
| TC-H04 | `test_http_route_404_not_found` | 404 response for unknown route | Request `/api/unknown` (not registered) | 404 JSON response, handler not called |

### 5.2 Request Parsing (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-H05 | `test_http_parse_get_request` | Parse GET request with path extraction | `GET /api/data HTTP/1.1\r\n\r\n` | Path extracted correctly |
| TC-H06 | `test_http_parse_post_request_with_body` | Parse POST request with JSON body | `POST /api/provision/host-pubkey` with JSON | Body parsed correctly |
| TC-H07 | `test_http_options_cors_preflight` | CORS preflight OPTIONS handling | `OPTIONS /api/test` | CORS headers in response |
| TC-H08 | `test_http_parse_authorization_header` | Extract Bearer token from header | `Authorization: Bearer <token>` | Token extracted correctly |
| TC-H09 | `test_http_incomplete_request_buffering` | Multi-chunk request assembly | Request split across multiple TCP packets | Request assembled correctly |

### 5.3 Authentication and Authorization (4 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-H10 | `test_http_auth_valid_token_allows_access` | Valid bearer token grants access | Valid token in `Authorization` header | Handler invoked |
| TC-H11 | `test_http_auth_invalid_token_returns_401` | Invalid token rejected | Wrong token in header | 401 Unauthorized response |
| TC-H12 | `test_http_auth_missing_token_returns_401` | Missing token rejected | No `Authorization` header | 401 Unauthorized response |
| TC-H13 | `test_http_public_route_no_auth_required` | Public routes bypass auth | Request to public route without token | Handler invoked |

### 5.4 Response Generation (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-H14 | `test_http_send_json_200_ok` | 200 OK JSON response | `http_send_json(pcb, 200, "{\"ok\":1}")` | Correct status line + JSON body |
| TC-H15 | `test_http_send_json_404_not_found` | 404 Not Found JSON response | `http_send_json(pcb, 404, "{\"error\":\"...\}")` | 404 status + error JSON |
| TC-H16 | `test_http_send_json_500_internal_error` | 500 Internal Server Error | `http_send_json(pcb, 500, "{\"error\":\"...\}")` | 500 status + error JSON |
| TC-H17 | `test_http_cors_headers_in_response` | CORS headers inclusion | Any response | `Access-Control-Allow-Origin: *` present |
| TC-H18 | `test_http_connection_close_header` | Connection close header | Response sent | `Connection: close` header present |

### 5.5 Connection Lifecycle (8 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-H19 | `test_http_connection_accept_registers_callbacks` | Callback registration on accept | `http_accept()` called | RX callback registered |
| TC-H20 | `test_http_single_connection_reject_second` | Single connection enforcement | Accept connection, try second | Second connection rejected |
| TC-H21 | `test_http_close_after_response_sent` | Connection cleanup after response | Send response | Connection closed |
| TC-H22 | `test_http_abort_on_write_error` | Error handling on write failure | `tcp_write()` returns error | Connection aborted |
| TC-H23 | `test_http_null_pbuf_closes_connection` | NULL pbuf closes connection | `http_recv()` with `pbuf = NULL` | Connection closed gracefully |
| TC-H24 | `test_http_route_table_full` | Route table overflow handling | Register 17 routes (MAX_ROUTES=16) | 17th route rejected |
| TC-H25 | `test_http_oversized_request_buffer_limit` | Request buffer overflow protection | 2048-byte request (limit=2048) | Request truncated or rejected |
| TC-H26 | `test_http_multiple_requests_state_reset` | State reset between requests | Send request, close, new connection | State clean for new request |

**Coverage Impact:** These tests cover 106/121 lines in `src/net/http/http_server.c`, including:
- `http_register()` / `http_register_auth()` - Route registration
- `http_accept()` - Connection acceptance
- `http_recv()` - Request parsing
- `http_send_json()` - Response generation
- Route matching and authentication logic

---

## 6. WiFi AP Management Tests

**Test Suite:** `test_wifi_ap.c`
**Total Tests:** 26
**Coverage:** 47.3% (35/74 lines)
**Source Module:** `src/net/wifi_ap.c`

### 6.1 WiFi AP Initialization (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-W01 | `test_wifi_init_success` | WiFi subsystem initialization | Call `wifi_ap_init()` | Returns true |
| TC-W02 | `test_wifi_init_failure` | Init failure handling (legacy test) | N/A (always succeeds) | Returns true |
| TC-W03 | `test_wifi_init_twice_fails` | Idempotent init (legacy name) | Call `wifi_ap_init()` twice | Both return true |
| TC-W04 | `test_wifi_deinit` | WiFi AP stop | Call `wifi_ap_stop()` | AP stopped, not initialized |
| TC-W05 | `test_wifi_deinit_when_not_initialized` | Stop without init | Call `wifi_ap_stop()` without init | No crash, state clean |

### 6.2 AP Mode Start/Stop (8 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-W06 | `test_enable_ap_mode_open` | Start AP with OPEN auth | SSID="MASTR-Token", password="" | AP started, `CYW43_AUTH_OPEN` |
| TC-W07 | `test_enable_ap_mode_wpa2` | Start AP with WPA2 auth | SSID="MASTR-Token", password="SecurePass123" | AP started, `CYW43_AUTH_WPA2_AES_PSK` |
| TC-W08 | `test_enable_ap_mode_stores_last_parameters` | Parameter storage | Start AP with SSID="TestSSID" | Parameters stored correctly |
| TC-W09 | `test_enable_ap_mode_without_init_fails` | Start without CYW43 init | Mock init failure | `wifi_ap_start()` returns false |
| TC-W10 | `test_disable_ap_mode` | Stop running AP | Start AP → stop AP | AP disabled |
| TC-W11 | `test_disable_ap_mode_when_not_enabled` | Stop when not running | Call `wifi_ap_stop()` | No crash, state clean |
| TC-W12 | `test_ap_lifecycle_full_sequence` | Complete lifecycle | Init → start → reconfigure → stop | All steps succeed |
| TC-W13 | `test_ap_password_rotation` | Password change | Start with "InitialPass" → change to "NewPass123" | New password applied |

### 6.3 DHCP Server Management (2 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-W14 | `test_dhcp_server_init` | DHCP server initialization | Start AP with IP 192.168.4.1 | DHCP server started |
| TC-W15 | `test_dhcp_server_deinit` | DHCP server cleanup | Stop AP | DHCP server stopped |

### 6.4 Client Connection Management (11 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-W16 | `test_simulate_client_connect` | Single client connection | Simulate client connect with MAC | Client count = 1 |
| TC-W17 | `test_simulate_multiple_clients_connect` | Multiple clients | Connect 3 clients | Client count = 3 |
| TC-W18 | `test_simulate_client_disconnect` | Client disconnection | Connect client → disconnect | Client count = 0 |
| TC-W19 | `test_simulate_disconnect_specific_client` | Specific client disconnect | 3 clients → disconnect client 2 | Client count = 2 |
| TC-W20 | `test_simulate_all_clients_disconnect` | Mass disconnection | 3 clients → disconnect all | Client count = 0 |
| TC-W21 | `test_disable_ap_disconnects_all_clients` | AP stop disconnects clients | 3 clients → stop AP | All clients disconnected |
| TC-W22 | `test_default_ap_ip_address` | Default IP verification | Start AP without custom IP | IP = 192.168.4.1 |
| TC-W23 | `test_default_ap_netmask` | Default netmask verification | Start AP | Netmask = 255.255.255.0 |
| TC-W24 | `test_connect_duplicate_client` | Duplicate MAC handling | Connect same MAC twice | Count = 1 (deduplicated) |
| TC-W25 | `test_disconnect_nonexistent_client` | Disconnect unknown client | Disconnect MAC not connected | No error, count unchanged |
| TC-W26 | `test_max_clients_limit` | Max clients enforcement | Connect MAX_CLIENTS + 1 | Last client rejected |

**Coverage Impact:** These tests cover 35/74 lines in `src/net/wifi_ap.c` and 42/48 lines in `src/net/ap/ap_manager.c`:
- `wifi_ap_init()` / `wifi_ap_stop()` - Lifecycle management
- `wifi_ap_start()` - AP configuration and start
- Client connection tracking (in `ap_manager.c`)

**Note:** Lower coverage (47.3%) due to hardware-specific code paths (CYW43 driver) that cannot be fully tested with mocks.

---

## 7. API Endpoint Tests

**Test Suite:** `test_api.c`
**Total Tests:** 34
**Coverage:** 87.6% (106/121 lines, shared with HTTP server)
**Source Module:** `src/net/api/api.c`

### 7.1 Bearer Token Security (7 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-A01 | `test_bearer_token_generation_entropy` | **CRITICAL:** Token uniqueness | Generate 100 tokens | All tokens unique (32 bytes each) |
| TC-A02 | `test_bearer_token_validation_success` | Valid token acceptance | Generated token → validate | Validation succeeds |
| TC-A03 | `test_bearer_token_validation_failure` | Invalid token rejection | Wrong token → validate | Validation fails |
| TC-A04 | `test_bearer_token_constant_time_comparison` | **CRITICAL:** Timing attack resistance | Valid vs invalid token | Constant-time comparison |
| TC-A05 | `test_wifi_ap_claim_password_generation` | WPA2-compliant password generation | Generate AP password | 16-24 chars, valid charset |
| TC-A06 | `test_wifi_ap_password_rotation` | Password rotation on claim | Claim → generate new password | Password changed |
| TC-A07 | `test_api_input_hex_validation` | Hex string validation | Validate "abcdef1234" | Valid hex accepted |

### 7.2 Token Generation and Management (3 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-A08 | `test_api_generate_token_produces_64_hex_chars` | Token format validation | Generate token | 64 hex characters (32 bytes) |
| TC-A09 | `test_api_generate_token_only_once` | Single token generation | Generate twice | Second call fails |
| TC-A10 | `test_api_token_validation_constant_time` | Constant-time token check | Valid vs invalid | Same execution time |

### 7.3 Provisioning Endpoints (13 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-A11 | `test_api_provision_host_pubkey_valid` | POST valid host pubkey | POST 128 hex chars (64 bytes) | 200 OK, pubkey written to Slot 8 |
| TC-A12 | `test_api_provision_host_pubkey_invalid_hex` | Reject invalid hex | POST "GGGG..." (invalid hex) | 400 Bad Request |
| TC-A13 | `test_api_provision_host_pubkey_wrong_length` | Reject wrong length | POST 64 chars (32 bytes) instead of 128 | 400 Bad Request |
| TC-A14 | `test_api_provision_host_pubkey_get` | GET host pubkey | GET `/api/provision/host-pubkey` | 200 OK, JSON with 128-char hex |
| TC-A15 | `test_api_provision_host_pubkey_status` | Check pubkey status | GET `/api/provision/host-pubkey/status` | JSON: `{"provisioned": true/false}` |
| TC-A16 | `test_api_provision_golden_hash_valid` | POST valid golden hash | POST 64 hex chars (32 bytes) | 200 OK, hash written to Slot 8 Block 2 |
| TC-A17 | `test_api_provision_golden_hash_invalid_hex` | Reject invalid hex | POST "ZZZZ..." | 400 Bad Request |
| TC-A18 | `test_api_provision_golden_hash_wrong_length` | Reject wrong length | POST 128 chars (64 bytes) | 400 Bad Request |
| TC-A19 | `test_api_provision_golden_hash_status` | Check hash status | GET `/api/provision/golden-hash/status` | JSON: `{"provisioned": true/false}` |
| TC-A20 | `test_api_provision_golden_hash_roundtrip` | Write and read-back | POST hash → GET hash | Retrieved hash matches written |
| TC-A21 | `test_api_claim_generates_password` | POST claim device | POST `/api/claim` | New WPA2 password (16-24 chars) |
| TC-A22 | `test_api_claim_already_claimed` | Re-claim prevention | Claim twice | Second claim fails |
| TC-A23 | `test_api_complete_provisioning_flow` | Full provisioning sequence | POST pubkey → POST hash → claim | All steps succeed |

### 7.4 Monitoring Endpoints (5 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-A24 | `test_api_status_returns_valid_json` | GET system status | GET `/api/status` | JSON: state, provisioned, uptime |
| TC-A25 | `test_api_network_returns_ssid_and_clients` | GET network info | GET `/api/network` | JSON: SSID, client count |
| TC-A26 | `test_api_cpu_returns_percentage` | GET CPU usage | GET `/api/cpu` | JSON: `{"cpu_percent": 0-100}` |
| TC-A27 | `test_api_ram_returns_heap_info` | GET RAM usage | GET `/api/ram` | JSON: heap used/free bytes |
| TC-A28 | `test_api_temp_returns_celsius` | GET temperature | GET `/api/temp` | JSON: `{"temp_celsius": ...}` |

### 7.5 Input Validation and Error Handling (6 tests)

| ID | Test Name | Description | Input/Preconditions | Expected Output |
|----|-----------|-------------|---------------------|-----------------|
| TC-A29 | `test_api_malformed_json_rejected` | Malformed JSON rejection | POST invalid JSON `{bad}` | 400 Bad Request |
| TC-A30 | `test_api_missing_required_field_rejected` | Required field validation | POST JSON missing `"pubkey"` | 400 Bad Request |
| TC-A31 | `test_api_unauthorized_request_rejected` | Auth-required endpoint without token | POST `/api/provision/...` no token | 401 Unauthorized |
| TC-A32 | `test_api_invalid_bearer_token_rejected` | Invalid token rejection | Wrong Bearer token | 401 Unauthorized |
| TC-A33 | `test_api_token_info_returns_pubkey` | GET token info | GET `/api/token/info` | JSON: token pubkey (128 hex chars) |
| TC-A34 | `test_api_atecc_slot8_layout` | ATECC608A Slot 8 layout verification | Read Slot 8 Blocks 0-2 | Block 0-1: pubkey, Block 2: hash |

**Coverage Impact:** These tests exercise API endpoints defined in `src/net/api/api.c`, which relies on `http_server.c` (87.6% coverage) and `crypto.c` (52.1% coverage).

**Security Notes:**
- Tests TC-A01, TC-A04, TC-A10 verify **timing attack resistance**
- Tests TC-A11-TC-A23 validate **provisioning security** (critical trust anchor)
- Tests TC-A29-TC-A32 ensure **input validation** prevents injection attacks

---

## 8. Supporting Test Suites

### 8.1 Nonce Generation Tests (4 tests)

**Test Suite:** `test_nonce.c`
**Coverage:** 52.1% (shared with crypto.c)

| ID | Test Name | Description | Expected Output |
|----|-----------|-------------|-----------------|
| TC-N01 | `test_nonce_generation_interface` | Hardware RNG interface | Non-zero nonces |
| TC-N02 | `test_nonce_uniqueness_small_sample` | Uniqueness (100 samples) | All unique |
| TC-N03 | `test_nonce_uniqueness_large_sample` | Uniqueness (1000 samples) | 0 duplicates |
| TC-N04 | `test_nonce_distribution_non_zero` | Zero-value detection | No zeros in 50 samples |

### 8.2 Integrity Verification Tests (6 tests)

**Test Suite:** `test_integrity.c`
**Coverage:** 69.1% (shared with protocol.c)

| ID | Test Name | Description | Expected Output |
|----|-----------|-------------|-----------------|
| TC-I01 | `test_integrity_hash_comparison_exact_match` | Exact hash match | State advances to `0x32` |
| TC-I02 | `test_integrity_detects_single_bit_tampering` | 1-bit difference detection | Halt state (`0xFF`) |
| TC-I03 | `test_integrity_detects_complete_hash_mismatch` | Complete mismatch | Halt state (`0xFF`) |
| TC-I04 | `test_integrity_validates_with_different_nonce` | Nonce independence | State advances to `0x32` |
| TC-I05 | `test_integrity_zero_hash_detection` | All-zero hash rejection | Halt state (`0xFF`) |
| TC-I06 | `test_integrity_all_ones_hash_detection` | All-ones hash rejection | Halt state (`0xFF`) |

### 8.3 Provisioning Security Tests (5 tests)

**Test Suite:** `test_provisioning.c`
**Coverage:** 52.1% (shared with crypto.c)

| ID | Test Name | Description | Expected Output |
|----|-----------|-------------|-----------------|
| TC-PR01 | `test_provision_valid_keys_and_hash` | Valid provisioning | Keys written and read back |
| TC-PR02 | `test_provision_reject_invalid_pubkey_length` | Length validation | Valid sizes accepted |
| TC-PR03 | `test_provision_reject_invalid_hash_length` | Length validation | Valid sizes accepted |
| TC-PR04 | `test_unprovision_zeros_data` | Secure erasure | Hash zeroed out |
| TC-PR05 | `test_provision_check_detects_zero_hash` | Unprovisioned detection | Zero hash detected |

---

## 9. Traceability Matrix

### 9.1 Protocol Phase Coverage

| Protocol Phase | State(s) | Covered By | Test Count |
|----------------|----------|------------|------------|
| **Phase 0: Provisioning** | `0x10` | TC-PR01-05, TC-A11-A23 | 18 |
| **Phase 1: Mutual Authentication** | `0x20`, `0x21` | TC-P01, TC-P10, TC-C05-C10 | 8 |
| **Phase 1.5: Channel Verification** | `0x22` | TC-P02, TC-P09, TC-P12 | 3 |
| **Phase 2: Integrity Verification** | `0x30`, `0x32` | TC-P03-P04, TC-I01-I06 | 8 |
| **Phase 3: Runtime** | `0x40` | TC-P05, TC-SS01-SS17 | 18 |
| **Re-Attestation** | `0x40→0x21` | TC-P14-P23, TC-SS08-SS10 | 13 |

### 9.2 Security Requirements Mapping

| Security Requirement | Test Cases | Priority |
|---------------------|------------|----------|
| **Cryptographic Integrity** | TC-C01-C15 | Critical |
| **Mutual Authentication** | TC-P01, TC-P10, TC-C08-C10 | Critical |
| **Timing Attack Resistance** | TC-A01, TC-A04, TC-A10 | Critical |
| **Input Validation** | TC-A12-A13, TC-A17-A18, TC-A29-A32 | Critical |
| **Session Management** | TC-SS01-SS17 | Critical |
| **Protocol State Enforcement** | TC-P06-P09 | Critical |
| **Tamper Detection** | TC-I02-I03, TC-I05-I06 | Critical |
| **Secure Provisioning** | TC-PR01-PR05, TC-A11-A23 | Critical |
| **Network Security** | TC-W06-W07, TC-A05-A06, TC-H10-H13 | High |
| **Error Handling** | TC-S09-S11, TC-P10-P13 | High |

### 9.3 Coverage by Source Module

| Source Module | Total Lines | Lines Hit | Coverage | Test Suites |
|---------------|-------------|-----------|----------|-------------|
| `serial.c` | 122 | 110 | 90.2% | TC-S01-S17 |
| `protocol.c` | 149 | 103 | 69.1% | TC-P01-P23, TC-SS01-SS17, TC-I01-I06 |
| `crypto.c` | 215 | 112 | 52.1% | TC-C01-C15, TC-N01-N04, TC-PR01-PR05 |
| `http_server.c` | 121 | 106 | 87.6% | TC-H01-H26, TC-A01-A34 |
| `wifi_ap.c` | 74 | 35 | 47.3% | TC-W01-W26 |
| `ap_manager.c` | 48 | 42 | 87.5% | TC-W16-W26 |
| **Total** | **729** | **508** | **68.7%** | - |

---

## 10. Security Requirements Coverage

### 10.1 Critical Security Tests

The following tests verify **security-critical** functionality and MUST NOT fail:

#### Cryptographic Security
- **TC-C03:** AES-GCM tag tampering detection (prevents ciphertext forgery)
- **TC-C04:** IV uniqueness for GCM (prevents nonce reuse attacks)
- **TC-C10:** ECDSA signature forgery detection (prevents authentication bypass)

#### Timing Attack Resistance
- **TC-A01:** Bearer token entropy (prevents token prediction)
- **TC-A04:** Constant-time token comparison (prevents timing side-channels)
- **TC-A10:** Constant-time validation (prevents timing attacks)

#### Protocol Security
- **TC-P06-P09:** State machine enforcement (prevents protocol violations)
- **TC-P10, TC-P13:** Malformed message rejection (prevents buffer overflows)
- **TC-I02-I03:** Tamper detection (detects firmware modification)

#### Input Validation
- **TC-A12-A13:** Host pubkey validation (prevents provisioning attacks)
- **TC-A17-A18:** Golden hash validation (prevents integrity bypass)
- **TC-A29-A32:** JSON/auth validation (prevents injection attacks)

#### Session Security
- **TC-SS02-SS03:** Session timeout enforcement (prevents stale sessions)
- **TC-SS15:** Missed heartbeat shutdown (prevents DoS via heartbeat starvation)

### 10.2 Test Failure Impact Analysis

| Test ID | Failure Impact | Severity | Remediation Priority |
|---------|----------------|----------|---------------------|
| TC-C03, TC-C04 | Cryptographic bypass | **CRITICAL** | Immediate |
| TC-C10 | Authentication bypass | **CRITICAL** | Immediate |
| TC-A01, TC-A04, TC-A10 | Timing attack vulnerability | **CRITICAL** | Immediate |
| TC-I02, TC-I03 | Tamper detection failure | **CRITICAL** | Immediate |
| TC-P06-P09 | Protocol violation undetected | **HIGH** | 24 hours |
| TC-SS15 | DoS vulnerability | **HIGH** | 24 hours |
| TC-S09-S11 | Frame corruption undetected | **MEDIUM** | 1 week |
| TC-W06-W07 | WiFi security misconfiguration | **MEDIUM** | 1 week |

---

## 11. Test Execution Statistics

### 11.1 Test Run Summary (Latest)

```
Test Framework: Unity v2.5.2
Compiler: GCC 11.4.0
Platform: x86_64 Linux (Ubuntu 22.04)
Date: 2025-11-23
```

| Metric | Value |
|--------|-------|
| Total Tests | 173 |
| Passed | 173 |
| Failed | 0 |
| Skipped | 0 |
| Execution Time | ~2.3 seconds |
| Memory Usage | ~15 MB (peak) |

### 11.2 Coverage Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Line Coverage | 68.7% | 70% | ⚠️ Near Target |
| Function Coverage | 51.6% (16/31) | 60% | ⚠️ Below Target |
| Branch Coverage | ~55% (estimated) | 60% | ⚠️ Below Target |

**Coverage Gaps:**
- `crypto.c`: Task-spawning functions (not testable in unit tests)
- `wifi_ap.c`: Hardware-specific CYW43 driver paths
- `protocol.c`: Error recovery paths (difficult to trigger in unit tests)

**Improvement Plan:**
1. Add integration tests for FreeRTOS task interactions
2. Increase branch coverage for error paths
3. Add fuzzing for input validation (serial, API)

---

## 12. Test Maintenance Notes

### 12.1 Mock Infrastructure

The test suite uses comprehensive mocks to isolate units under test:

| Mock Module | Purpose | Test Suites Using |
|-------------|---------|-------------------|
| `mock_pico_sdk.h` | Pico SDK hardware abstraction | All |
| `mock_crypto.h` | ATECC608A cryptographic operations | TC-C, TC-P, TC-SS, TC-I, TC-PR, TC-A |
| `mock_lwip.h` | lwIP TCP/IP stack | TC-H, TC-A |
| `mock_wifi.h` | CYW43 WiFi driver | TC-W |
| `mock_atca.h` | ATECC608A low-level driver | TC-C, TC-PR |
| `mock_time.h` | Time/timestamp functions | TC-P, TC-SS |

### 12.2 Test Data Generation

All tests use deterministic data generation for reproducibility:

```c
static void generate_test_data(uint8_t* buffer, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] = seed + (uint8_t)i;
    }
}
```

**Seed Values by Test Suite:**
- Serial: 0xAA, 0xBB, 0xCC
- Protocol: 0xDD, 0xEE, 0xFF
- Crypto: 0x50, 0x80, 0xA0, 0xB0
- API: 0x10, 0x20, 0x30

### 12.3 Future Test Additions

**Planned for Next Release:**
1. **Fuzzing Tests:** Random input generation for serial parser and API endpoints
2. **Integration Tests:** Multi-module interaction testing (protocol + crypto + serial)
3. **Performance Tests:** Latency measurements for critical paths
4. **Stress Tests:** Rapid re-attestation cycles, connection churn
5. **Hardware-in-Loop Tests:** Actual ATECC608A and CYW43 testing

---

## 13. References

### 13.1 Related Documentation

- **Protocol Specification:** `docs/protocol_flow.md`
- **Crypto Implementation:** `docs/crypto_design.md`
- **API Specification:** `docs/api_endpoints.md`
- **ATECC608A Datasheet:** Microchip DS40002180A

### 13.2 Test Frameworks and Tools

- **Unity:** https://github.com/ThrowTheSwitch/Unity
- **CMake:** v3.22+ (test build system)
- **lcov:** v1.14+ (coverage report generation)
- **gcov:** v11.4.0 (coverage instrumentation)

### 13.3 Compliance and Standards

- **Embedded C Coding Standard:** Barr Group Embedded C Coding Standard
- **MISRA C:** Subset of MISRA C:2012 guidelines
- **Security:** OWASP Embedded Application Security Top 10

---

## Appendix A: Test Naming Conventions

All test names follow the convention: `test_<module>_<action>_<condition>`

**Examples:**
- `test_aes_gcm_decrypt_with_wrong_key` - Module: AES-GCM, Action: Decrypt, Condition: Wrong key
- `test_state_transition_0x20_to_0x21_on_ecdh_share` - Module: Protocol, Action: Transition, Condition: ECDH share received

---

## Appendix B: Coverage Report Generation

To generate HTML coverage reports:

```bash
cd test/build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
make coverage
```

Coverage reports will be generated in `test/build/coverage_html/index.html`.

---

**Document End**

*This document is auto-generated from test suite analysis and should be updated with each release.*
