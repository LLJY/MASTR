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

    return UNITY_END();
}