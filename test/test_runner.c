#include "unity.h"

// Forward declarations - Serial Tests
void test_send_simple_packet(void);
void test_send_with_all_special_bytes_in_payload(void);
void test_send_zero_length_payload(void);
void test_receive_simple_packet(void);
void test_receive_stuffed_packet(void);
void test_receive_zero_length_packet(void);
void test_ignore_bytes_before_SOF(void);
void test_reject_bad_checksum(void);
void test_reject_bad_length(void);
void test_reject_invalid_escape_sequence(void);
void test_recover_after_corrupted_frame(void);

// Forward declarations - Protocol Tests
void test_state_transition_0x20_to_0x21_on_ecdh_share(void);
void test_state_transition_0x22_to_0x30_on_channel_verify(void);
void test_state_transition_0x30_to_0x32_on_valid_integrity(void);
void test_state_transition_0x32_to_0x40_on_boot_ack(void);
void test_heartbeat_accepted_in_runtime_state(void);
void test_reject_integrity_response_in_wrong_state(void);
void test_reject_heartbeat_before_runtime(void);
void test_reject_boot_ack_in_wrong_state(void);
void test_reject_channel_verify_in_wrong_state(void);
void test_invalid_ecdh_share_length_triggers_shutdown(void);
void test_invalid_integrity_length_sends_nack(void);
void test_bad_channel_verify_response_triggers_shutdown(void);
void test_failed_signature_verification_triggers_shutdown(void);
void test_reattestation_keeps_old_session_key(void);
void test_ecdh_at_state_0x21_uses_existing_key(void);

// Forward declarations - Session Tests
void test_session_establishment(void);
void test_session_is_valid_within_timeout(void);
void test_session_invalid_after_timeout(void);
void test_session_timestamp_tracking(void);
void test_invalidate_session_keeps_old_key(void);
void test_invalidate_session_resets_to_ecdh_state(void);
void test_encryption_flag_persists_through_invalidation(void);
void test_trigger_reattestation_invalidates_session(void);
void test_trigger_reattestation_generates_new_ephemeral_key(void);
void test_trigger_reattestation_advances_to_state_0x21(void);
void test_session_custom_timeout(void);
void test_session_not_valid_when_flag_false(void);
void test_heartbeat_resets_missed_count(void);
void test_halt_state_sets_flag(void);
void test_three_missed_heartbeats_should_trigger_shutdown(void);
void test_two_missed_heartbeats_no_shutdown(void);
void test_missed_heartbeat_counter_increments(void);

// Forward declarations - Nonce Tests
void test_nonce_generation_interface(void);
void test_nonce_uniqueness_small_sample(void);
void test_nonce_uniqueness_large_sample(void);
void test_nonce_distribution_non_zero(void);

// Forward declarations - Integrity Tests
void test_integrity_hash_comparison_exact_match(void);
void test_integrity_detects_single_bit_tampering(void);
void test_integrity_detects_complete_hash_mismatch(void);
void test_integrity_validates_with_different_nonce(void);
void test_integrity_zero_hash_detection(void);
void test_integrity_all_ones_hash_detection(void);

// Forward declarations - Crypto Tests (NEW - Group A: 15 tests)
void test_aes_gcm_encrypt_decrypt_roundtrip(void);
void test_aes_gcm_decrypt_with_wrong_key(void);
void test_aes_gcm_decrypt_with_tampered_tag(void);
void test_aes_gcm_encrypt_iv_uniqueness(void);
void test_ecdh_shared_secret_computation(void);
void test_ecdh_ephemeral_key_generation(void);
void test_ecdh_key_derivation_hkdf(void);
void test_ecdsa_sign_with_permanent_key(void);
void test_ecdsa_verify_valid_signature(void);
void test_ecdsa_reject_invalid_signature(void);
void test_atecc_read_host_pubkey_slot8(void);
void test_atecc_write_host_pubkey_slot8(void);
void test_atecc_read_golden_hash_slot8_block2(void);
void test_atecc_write_golden_hash_slot8_block2(void);
void test_compute_sha256_consistency(void);

// Forward declarations - Protocol Re-Attestation Tests (NEW - Group B: 8 tests)
void test_reattestation_full_cycle_0x40_to_0x40(void);
void test_reattestation_generates_new_ephemeral_key(void);
void test_token_initiated_reattestation_0x21(void);
void test_reattestation_during_heartbeat_race(void);
void test_multiple_reattestation_cycles(void);
void test_reattestation_timeout_during_cycle(void);
void test_encryption_persists_through_reattestation(void);
void test_reattestation_key_rotation_verification(void);

// Forward declarations - Serial Buffer Safety Tests (NEW - Group C: 6 tests)
void test_rx_buffer_overflow_handling(void);
void test_rx_buffer_wraparound(void);
void test_rx_buffer_concurrent_read_write(void);
void test_serial_max_payload_256_bytes(void);
void test_serial_frame_fragmentation(void);
void test_serial_usb_disconnect_recovery(void);

// Forward declarations - Provisioning Tests (NEW - Group D: 5 tests)
void test_provision_valid_keys_and_hash(void);
void test_provision_reject_invalid_pubkey_length(void);
void test_provision_reject_invalid_hash_length(void);
void test_unprovision_zeros_data(void);
void test_provision_check_detects_zero_hash(void);

// Forward declarations - API Security Tests (NEW - Group E: 7 tests)
void test_bearer_token_generation_entropy(void);
void test_bearer_token_validation_success(void);
void test_bearer_token_validation_failure(void);
void test_bearer_token_constant_time_comparison(void);
void test_wifi_ap_claim_password_generation(void);
void test_wifi_ap_password_rotation(void);
void test_api_input_hex_validation(void);

// Forward declarations - API Endpoint Tests (NEW - Group F: 27 tests)
void test_api_generate_token_produces_64_hex_chars(void);
void test_api_generate_token_only_once(void);
void test_api_token_validation_constant_time(void);
void test_api_provision_host_pubkey_valid(void);
void test_api_provision_host_pubkey_invalid_hex(void);
void test_api_provision_host_pubkey_wrong_length(void);
void test_api_provision_host_pubkey_get(void);
void test_api_provision_host_pubkey_status(void);
void test_api_provision_golden_hash_valid(void);
void test_api_provision_golden_hash_invalid_hex(void);
void test_api_provision_golden_hash_wrong_length(void);
void test_api_provision_golden_hash_status(void);
void test_api_provision_golden_hash_roundtrip(void);
void test_api_claim_generates_password(void);
void test_api_claim_already_claimed(void);
void test_api_status_returns_valid_json(void);
void test_api_network_returns_ssid_and_clients(void);
void test_api_cpu_returns_percentage(void);
void test_api_ram_returns_heap_info(void);
void test_api_temp_returns_celsius(void);
void test_api_malformed_json_rejected(void);
void test_api_missing_required_field_rejected(void);
void test_api_unauthorized_request_rejected(void);
void test_api_invalid_bearer_token_rejected(void);
void test_api_token_info_returns_pubkey(void);
void test_api_complete_provisioning_flow(void);
void test_api_atecc_slot8_layout(void);

// Forward declarations - HTTP Server Tests (NEW - Group G: 26 tests)
void test_http_route_registration_public(void);
void test_http_route_registration_with_auth(void);
void test_http_route_matching_success(void);
void test_http_route_404_not_found(void);
void test_http_parse_get_request(void);
void test_http_parse_post_request_with_body(void);
void test_http_options_cors_preflight(void);
void test_http_parse_authorization_header(void);
void test_http_incomplete_request_buffering(void);
void test_http_auth_valid_token_allows_access(void);
void test_http_auth_invalid_token_returns_401(void);
void test_http_auth_missing_token_returns_401(void);
void test_http_public_route_no_auth_required(void);
void test_http_send_json_200_ok(void);
void test_http_send_json_404_not_found(void);
void test_http_send_json_500_internal_error(void);
void test_http_cors_headers_in_response(void);
void test_http_connection_close_header(void);
void test_http_connection_accept_registers_callbacks(void);
void test_http_single_connection_reject_second(void);
void test_http_close_after_response_sent(void);
void test_http_abort_on_write_error(void);
void test_http_null_pbuf_closes_connection(void);
void test_http_route_table_full(void);
void test_http_oversized_request_buffer_limit(void);
void test_http_multiple_requests_state_reset(void);

// Forward declarations - WiFi AP Tests (NEW - Group H: 26 tests)
void test_wifi_init_success(void);
void test_wifi_init_failure(void);
void test_wifi_init_twice_fails(void);
void test_wifi_deinit(void);
void test_wifi_deinit_when_not_initialized(void);
void test_enable_ap_mode_open(void);
void test_enable_ap_mode_wpa2(void);
void test_enable_ap_mode_stores_last_parameters(void);
void test_enable_ap_mode_without_init_fails(void);
void test_disable_ap_mode(void);
void test_disable_ap_mode_when_not_enabled(void);
void test_ap_lifecycle_full_sequence(void);
void test_ap_password_rotation(void);
void test_dhcp_server_init(void);
void test_dhcp_server_deinit(void);
void test_simulate_client_connect(void);
void test_simulate_multiple_clients_connect(void);
void test_simulate_client_disconnect(void);
void test_simulate_disconnect_specific_client(void);
void test_simulate_all_clients_disconnect(void);
void test_disable_ap_disconnects_all_clients(void);
void test_default_ap_ip_address(void);
void test_default_ap_netmask(void);
void test_connect_duplicate_client(void);
void test_disconnect_nonexistent_client(void);
void test_max_clients_limit(void);

int main(void) {
    UNITY_BEGIN();

    // ========================================================================
    // Serial Layer Tests
    // ========================================================================
    RUN_TEST(test_send_simple_packet);
    RUN_TEST(test_send_with_all_special_bytes_in_payload);
    RUN_TEST(test_send_zero_length_payload);
    RUN_TEST(test_receive_simple_packet);
    RUN_TEST(test_receive_stuffed_packet);
    RUN_TEST(test_receive_zero_length_packet);
    RUN_TEST(test_ignore_bytes_before_SOF);
    RUN_TEST(test_reject_bad_checksum);
    RUN_TEST(test_reject_bad_length);
    RUN_TEST(test_reject_invalid_escape_sequence);
    RUN_TEST(test_recover_after_corrupted_frame);

    // ========================================================================
    // Protocol State Machine Tests
    // ========================================================================
    RUN_TEST(test_state_transition_0x20_to_0x21_on_ecdh_share);
    RUN_TEST(test_state_transition_0x22_to_0x30_on_channel_verify);
    RUN_TEST(test_state_transition_0x30_to_0x32_on_valid_integrity);
    RUN_TEST(test_state_transition_0x32_to_0x40_on_boot_ack);
    RUN_TEST(test_heartbeat_accepted_in_runtime_state);
    RUN_TEST(test_reject_integrity_response_in_wrong_state);
    RUN_TEST(test_reject_heartbeat_before_runtime);
    RUN_TEST(test_reject_boot_ack_in_wrong_state);
    RUN_TEST(test_reject_channel_verify_in_wrong_state);
    RUN_TEST(test_invalid_ecdh_share_length_triggers_shutdown);
    RUN_TEST(test_invalid_integrity_length_sends_nack);
    RUN_TEST(test_bad_channel_verify_response_triggers_shutdown);
    RUN_TEST(test_failed_signature_verification_triggers_shutdown);
    RUN_TEST(test_reattestation_keeps_old_session_key);
    RUN_TEST(test_ecdh_at_state_0x21_uses_existing_key);

    // ========================================================================
    // Session Management Tests
    // ========================================================================
    RUN_TEST(test_session_establishment);
    RUN_TEST(test_session_is_valid_within_timeout);
    RUN_TEST(test_session_invalid_after_timeout);
    RUN_TEST(test_session_timestamp_tracking);
    RUN_TEST(test_invalidate_session_keeps_old_key);
    RUN_TEST(test_invalidate_session_resets_to_ecdh_state);
    RUN_TEST(test_encryption_flag_persists_through_invalidation);
    RUN_TEST(test_trigger_reattestation_invalidates_session);
    RUN_TEST(test_trigger_reattestation_generates_new_ephemeral_key);
    RUN_TEST(test_trigger_reattestation_advances_to_state_0x21);
    RUN_TEST(test_session_custom_timeout);
    RUN_TEST(test_session_not_valid_when_flag_false);
    RUN_TEST(test_heartbeat_resets_missed_count);
    RUN_TEST(test_halt_state_sets_flag);
    RUN_TEST(test_three_missed_heartbeats_should_trigger_shutdown);
    RUN_TEST(test_two_missed_heartbeats_no_shutdown);
    RUN_TEST(test_missed_heartbeat_counter_increments);

    // ========================================================================
    // Nonce Generation Tests
    // ========================================================================
    RUN_TEST(test_nonce_generation_interface);
    RUN_TEST(test_nonce_uniqueness_small_sample);
    RUN_TEST(test_nonce_uniqueness_large_sample);
    RUN_TEST(test_nonce_distribution_non_zero);

    // ========================================================================
    // Integrity Check Tests
    // ========================================================================
    RUN_TEST(test_integrity_hash_comparison_exact_match);
    RUN_TEST(test_integrity_detects_single_bit_tampering);
    RUN_TEST(test_integrity_detects_complete_hash_mismatch);
    RUN_TEST(test_integrity_validates_with_different_nonce);
    RUN_TEST(test_integrity_zero_hash_detection);
    RUN_TEST(test_integrity_all_ones_hash_detection);

    // ========================================================================
    // NEW TESTS - Phase 1 (41 tests)
    // ========================================================================

    // Group A: Cryptographic Operations Tests (15 tests)
    RUN_TEST(test_aes_gcm_encrypt_decrypt_roundtrip);
    RUN_TEST(test_aes_gcm_decrypt_with_wrong_key);
    RUN_TEST(test_aes_gcm_decrypt_with_tampered_tag);
    RUN_TEST(test_aes_gcm_encrypt_iv_uniqueness);
    RUN_TEST(test_ecdh_shared_secret_computation);
    RUN_TEST(test_ecdh_ephemeral_key_generation);
    RUN_TEST(test_ecdh_key_derivation_hkdf);
    RUN_TEST(test_ecdsa_sign_with_permanent_key);
    RUN_TEST(test_ecdsa_verify_valid_signature);
    RUN_TEST(test_ecdsa_reject_invalid_signature);
    RUN_TEST(test_atecc_read_host_pubkey_slot8);
    RUN_TEST(test_atecc_write_host_pubkey_slot8);
    RUN_TEST(test_atecc_read_golden_hash_slot8_block2);
    RUN_TEST(test_atecc_write_golden_hash_slot8_block2);
    RUN_TEST(test_compute_sha256_consistency);

    // Group B: Protocol Re-Attestation Tests (8 tests)
    RUN_TEST(test_reattestation_full_cycle_0x40_to_0x40);
    RUN_TEST(test_reattestation_generates_new_ephemeral_key);
    RUN_TEST(test_token_initiated_reattestation_0x21);
    RUN_TEST(test_reattestation_during_heartbeat_race);
    RUN_TEST(test_multiple_reattestation_cycles);
    RUN_TEST(test_reattestation_timeout_during_cycle);
    RUN_TEST(test_encryption_persists_through_reattestation);
    RUN_TEST(test_reattestation_key_rotation_verification);

    // Group C: Serial Buffer Safety Tests (6 tests)
    RUN_TEST(test_rx_buffer_overflow_handling);
    RUN_TEST(test_rx_buffer_wraparound);
    RUN_TEST(test_rx_buffer_concurrent_read_write);
    RUN_TEST(test_serial_max_payload_256_bytes);
    RUN_TEST(test_serial_frame_fragmentation);
    RUN_TEST(test_serial_usb_disconnect_recovery);

    // Group D: Provisioning Security Tests (5 tests)
    RUN_TEST(test_provision_valid_keys_and_hash);
    RUN_TEST(test_provision_reject_invalid_pubkey_length);
    RUN_TEST(test_provision_reject_invalid_hash_length);
    RUN_TEST(test_unprovision_zeros_data);
    RUN_TEST(test_provision_check_detects_zero_hash);

    // Group E: WiFi/API Security Tests (7 tests)
    RUN_TEST(test_bearer_token_generation_entropy);
    RUN_TEST(test_bearer_token_validation_success);
    RUN_TEST(test_bearer_token_validation_failure);
    RUN_TEST(test_bearer_token_constant_time_comparison);
    RUN_TEST(test_wifi_ap_claim_password_generation);
    RUN_TEST(test_wifi_ap_password_rotation);
    RUN_TEST(test_api_input_hex_validation);

    // Group F: API Endpoint Tests (27 tests)
    RUN_TEST(test_api_generate_token_produces_64_hex_chars);
    RUN_TEST(test_api_generate_token_only_once);
    RUN_TEST(test_api_token_validation_constant_time);
    RUN_TEST(test_api_provision_host_pubkey_valid);
    RUN_TEST(test_api_provision_host_pubkey_invalid_hex);
    RUN_TEST(test_api_provision_host_pubkey_wrong_length);
    RUN_TEST(test_api_provision_host_pubkey_get);
    RUN_TEST(test_api_provision_host_pubkey_status);
    RUN_TEST(test_api_provision_golden_hash_valid);
    RUN_TEST(test_api_provision_golden_hash_invalid_hex);
    RUN_TEST(test_api_provision_golden_hash_wrong_length);
    RUN_TEST(test_api_provision_golden_hash_status);
    RUN_TEST(test_api_provision_golden_hash_roundtrip);
    RUN_TEST(test_api_claim_generates_password);
    RUN_TEST(test_api_claim_already_claimed);
    RUN_TEST(test_api_status_returns_valid_json);
    RUN_TEST(test_api_network_returns_ssid_and_clients);
    RUN_TEST(test_api_cpu_returns_percentage);
    RUN_TEST(test_api_ram_returns_heap_info);
    RUN_TEST(test_api_temp_returns_celsius);
    RUN_TEST(test_api_malformed_json_rejected);
    RUN_TEST(test_api_missing_required_field_rejected);
    RUN_TEST(test_api_unauthorized_request_rejected);
    RUN_TEST(test_api_invalid_bearer_token_rejected);
    RUN_TEST(test_api_token_info_returns_pubkey);
    RUN_TEST(test_api_complete_provisioning_flow);
    RUN_TEST(test_api_atecc_slot8_layout);

    // ========================================================================
    // NEW TESTS - Phase 2: HTTP Server Tests (26 tests)
    // ========================================================================

    // Group G: HTTP Server Tests (26 tests)
    RUN_TEST(test_http_route_registration_public);
    RUN_TEST(test_http_route_registration_with_auth);
    RUN_TEST(test_http_route_matching_success);
    RUN_TEST(test_http_route_404_not_found);
    RUN_TEST(test_http_parse_get_request);
    RUN_TEST(test_http_parse_post_request_with_body);
    RUN_TEST(test_http_options_cors_preflight);
    RUN_TEST(test_http_parse_authorization_header);
    RUN_TEST(test_http_incomplete_request_buffering);
    RUN_TEST(test_http_auth_valid_token_allows_access);
    RUN_TEST(test_http_auth_invalid_token_returns_401);
    RUN_TEST(test_http_auth_missing_token_returns_401);
    RUN_TEST(test_http_public_route_no_auth_required);
    RUN_TEST(test_http_send_json_200_ok);
    RUN_TEST(test_http_send_json_404_not_found);
    RUN_TEST(test_http_send_json_500_internal_error);
    RUN_TEST(test_http_cors_headers_in_response);
    RUN_TEST(test_http_connection_close_header);
    RUN_TEST(test_http_connection_accept_registers_callbacks);
    RUN_TEST(test_http_single_connection_reject_second);
    RUN_TEST(test_http_close_after_response_sent);
    RUN_TEST(test_http_abort_on_write_error);
    RUN_TEST(test_http_null_pbuf_closes_connection);
    RUN_TEST(test_http_route_table_full);
    RUN_TEST(test_http_oversized_request_buffer_limit);
    RUN_TEST(test_http_multiple_requests_state_reset);

    // ========================================================================
    // NEW TESTS - Phase 3: WiFi AP Tests (26 tests)
    // ========================================================================

    // Group H: WiFi AP Management Tests (26 tests)
    RUN_TEST(test_wifi_init_success);
    RUN_TEST(test_wifi_init_failure);
    RUN_TEST(test_wifi_init_twice_fails);
    RUN_TEST(test_wifi_deinit);
    RUN_TEST(test_wifi_deinit_when_not_initialized);
    RUN_TEST(test_enable_ap_mode_open);
    RUN_TEST(test_enable_ap_mode_wpa2);
    RUN_TEST(test_enable_ap_mode_stores_last_parameters);
    RUN_TEST(test_enable_ap_mode_without_init_fails);
    RUN_TEST(test_disable_ap_mode);
    RUN_TEST(test_disable_ap_mode_when_not_enabled);
    RUN_TEST(test_ap_lifecycle_full_sequence);
    RUN_TEST(test_ap_password_rotation);
    RUN_TEST(test_dhcp_server_init);
    RUN_TEST(test_dhcp_server_deinit);
    RUN_TEST(test_simulate_client_connect);
    RUN_TEST(test_simulate_multiple_clients_connect);
    RUN_TEST(test_simulate_client_disconnect);
    RUN_TEST(test_simulate_disconnect_specific_client);
    RUN_TEST(test_simulate_all_clients_disconnect);
    RUN_TEST(test_disable_ap_disconnects_all_clients);
    RUN_TEST(test_default_ap_ip_address);
    RUN_TEST(test_default_ap_netmask);
    RUN_TEST(test_connect_duplicate_client);
    RUN_TEST(test_disconnect_nonexistent_client);
    RUN_TEST(test_max_clients_limit);

    // ========================================================================
    // Total: 55 existing + 41 crypto/serial/provision + 34 API + 26 HTTP + 26 WiFi = 173 tests
    // ========================================================================

    return UNITY_END();
}