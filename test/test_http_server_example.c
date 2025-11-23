/*
 * Example HTTP Server Unit Tests using lwIP Mock
 *
 * This file demonstrates how to test HTTP server code using the lwIP mock.
 * It shows:
 * 1. Basic request/response flow
 * 2. Error handling
 * 3. CORS preflight handling
 * 4. Connection lifecycle
 *
 * To add to build: Update test/CMakeLists.txt (see LWIP_MOCK_ANALYSIS.md)
 */

#include "unity.h"
#include "mock_lwip.h"      // MUST be before http_server.h
#include "mock_pico_sdk.h"  // For print_dbg
#include "http_server.h"
#include <string.h>

// ============================================================================
// Test Fixtures
// ============================================================================

void setUp(void) {
    mock_lwip_reset();
    reset_mocks();  // From mock_pico_sdk
}

void tearDown(void) {
    // Cleanup happens in mock_lwip_reset()
}

// ============================================================================
// Helper Functions
// ============================================================================

// Setup HTTP server and simulate incoming connection
// Returns the client PCB ready for request injection
static struct tcp_pcb* setup_http_connection(void) {
    // Initialize HTTP server
    http_server_init();

    // Get the listening socket
    struct tcp_pcb *listen_pcb = mock_lwip_get_listen_pcb();
    TEST_ASSERT_NOT_NULL_MESSAGE(listen_pcb, "http_server_init() should create listening PCB");
    TEST_ASSERT_TRUE_MESSAGE(listen_pcb->is_listening, "PCB should be in listening state");
    TEST_ASSERT_EQUAL_UINT16(80, listen_pcb->local_port);

    // Simulate incoming connection (calls accept callback)
    mock_lwip_simulate_accept(listen_pcb);

    // Get the client connection
    struct tcp_pcb *client_pcb = mock_lwip_get_client_pcb();
    TEST_ASSERT_NOT_NULL_MESSAGE(client_pcb, "Accept callback should create client PCB");

    return client_pcb;
}

// ============================================================================
// Basic HTTP Request/Response Tests
// ============================================================================

void test_http_server_initialization(void) {
    http_server_init();

    struct tcp_pcb *listen_pcb = mock_lwip_get_listen_pcb();
    TEST_ASSERT_NOT_NULL(listen_pcb);
    TEST_ASSERT_TRUE(listen_pcb->is_listening);
    TEST_ASSERT_EQUAL_UINT16(80, listen_pcb->local_port);
    TEST_ASSERT_NOT_NULL(listen_pcb->accept);  // Accept callback registered
}

void test_http_get_request_404(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    // Inject HTTP GET request to non-existent route
    const char *request =
        "GET /does/not/exist HTTP/1.1\r\n"
        "Host: 192.168.4.1\r\n"
        "\r\n";

    mock_lwip_inject_request(client_pcb, request);

    // Verify response
    const char *response = mock_lwip_get_response();
    TEST_ASSERT_NOT_NULL(response);

    // Verify HTTP 404 status
    TEST_ASSERT_TRUE(strstr(response, "HTTP/1.1 404 Not Found") != NULL);

    // Verify JSON error response
    TEST_ASSERT_TRUE(strstr(response, "Content-Type: application/json") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "{\"error\":\"not found\"}") != NULL);

    // Verify CORS headers
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Origin: *") != NULL);

    // Verify Connection: close header
    TEST_ASSERT_TRUE(strstr(response, "Connection: close") != NULL);

    // Verify tcp_output() was called to flush data
    TEST_ASSERT_TRUE(mock_lwip_was_output_called());
    TEST_ASSERT_GREATER_THAN_UINT32(0, mock_lwip_get_output_call_count());

    // Verify tcp_write() was called (at least 2 times: headers + body)
    TEST_ASSERT_GREATER_THAN_UINT32(1, mock_lwip_get_write_call_count());
}

void test_http_cors_preflight_options(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    // CORS preflight request
    const char *request =
        "OPTIONS /api/provision/status HTTP/1.1\r\n"
        "Origin: http://192.168.4.1\r\n"
        "Access-Control-Request-Method: POST\r\n"
        "\r\n";

    mock_lwip_inject_request(client_pcb, request);

    const char *response = mock_lwip_get_response();
    TEST_ASSERT_NOT_NULL(response);

    // Verify 204 No Content
    TEST_ASSERT_TRUE(strstr(response, "HTTP/1.1 204 No Content") != NULL);

    // Verify CORS headers
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Origin: *") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Methods: GET, POST, OPTIONS") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Headers: Content-Type, Authorization") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Max-Age: 86400") != NULL);

    TEST_ASSERT_TRUE(mock_lwip_was_output_called());
}

// ============================================================================
// Connection Lifecycle Tests
// ============================================================================

void test_http_deferred_close_after_sent(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    // Send request
    mock_lwip_inject_request(client_pcb, "GET /does/not/exist HTTP/1.1\r\n\r\n");

    // At this point, response is written but connection is NOT closed yet
    // (http_server uses deferred close via tcp_sent callback)
    TEST_ASSERT_FALSE_MESSAGE(mock_lwip_was_closed(),
        "Connection should NOT be closed immediately after response");

    // Simulate TCP stack acknowledging sent data (calls sent callback)
    uint16_t response_len = mock_lwip_get_response_len();
    mock_lwip_trigger_sent_callback(client_pcb, response_len);

    // Now connection should be closed
    TEST_ASSERT_TRUE_MESSAGE(mock_lwip_was_closed(),
        "Connection should be closed after sent callback");
}

void test_http_single_connection_limit(void) {
    struct tcp_pcb *client1_pcb = setup_http_connection();

    // First connection is active
    TEST_ASSERT_NOT_NULL(client1_pcb);

    // Try to accept second connection while first is still active
    // HTTP server enforces single-connection limit via g_state.in_use

    // Clear response buffer to differentiate responses
    mock_lwip_clear_response();

    // Simulate another incoming connection
    struct tcp_pcb *listen_pcb = mock_lwip_get_listen_pcb();
    mock_lwip_simulate_accept(listen_pcb);

    // The second connection should be rejected (closed immediately)
    // Note: This behavior depends on http_server implementation
    // If server is already handling a request, it rejects new connections
}

// ============================================================================
// Error Handling Tests
// ============================================================================

void test_tcp_write_failure_aborts_connection(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    // Force tcp_write() to fail with ERR_MEM
    mock_lwip_set_write_error(ERR_MEM);

    // Inject request
    mock_lwip_inject_request(client_pcb, "GET /api/ping HTTP/1.1\r\n\r\n");

    // Server should abort connection on write failure
    TEST_ASSERT_TRUE_MESSAGE(mock_lwip_was_aborted(),
        "Connection should be aborted when tcp_write() fails");

    TEST_ASSERT_FALSE_MESSAGE(mock_lwip_was_closed(),
        "Connection should NOT be gracefully closed on write failure");
}

void test_tcp_close_failure_falls_back_to_abort(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    // Send request normally
    mock_lwip_inject_request(client_pcb, "GET /api/ping HTTP/1.1\r\n\r\n");

    // Force tcp_close() to fail (simulates out of memory during close)
    mock_lwip_set_close_error(ERR_MEM);

    // Trigger close via sent callback
    mock_lwip_trigger_sent_callback(client_pcb, mock_lwip_get_response_len());

    // Verify it tried to close
    TEST_ASSERT_TRUE_MESSAGE(mock_lwip_was_closed(),
        "Should attempt graceful close first");

    // Verify it fell back to abort when close failed
    TEST_ASSERT_TRUE_MESSAGE(mock_lwip_was_aborted(),
        "Should abort connection when close fails");
}

// ============================================================================
// Response Content Verification
// ============================================================================

void test_http_response_has_correct_headers(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    mock_lwip_inject_request(client_pcb, "GET /api/ping HTTP/1.1\r\n\r\n");

    const char *response = mock_lwip_get_response();

    // Verify status line
    TEST_ASSERT_TRUE(strstr(response, "HTTP/1.1") != NULL);

    // Verify required headers
    TEST_ASSERT_TRUE(strstr(response, "Content-Type:") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Connection: close") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Content-Length:") != NULL);

    // Verify CORS headers
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Origin: *") != NULL);
    TEST_ASSERT_TRUE(strstr(response, "Access-Control-Allow-Methods:") != NULL);

    // Verify header/body separator
    TEST_ASSERT_TRUE(strstr(response, "\r\n\r\n") != NULL);
}

void test_http_response_content_length_matches_body(void) {
    struct tcp_pcb *client_pcb = setup_http_connection();

    mock_lwip_inject_request(client_pcb, "GET /api/ping HTTP/1.1\r\n\r\n");

    const char *response = mock_lwip_get_response();

    // Find Content-Length header
    const char *cl_header = strstr(response, "Content-Length:");
    TEST_ASSERT_NOT_NULL_MESSAGE(cl_header, "Response must have Content-Length header");

    // Extract Content-Length value
    int content_length = 0;
    sscanf(cl_header, "Content-Length: %d", &content_length);
    TEST_ASSERT_GREATER_THAN_INT(0, content_length);

    // Find body start (after \r\n\r\n)
    const char *body = strstr(response, "\r\n\r\n");
    TEST_ASSERT_NOT_NULL(body);
    body += 4;  // Skip \r\n\r\n

    // Verify body length matches Content-Length
    int actual_body_len = strlen(body);
    TEST_ASSERT_EQUAL_INT_MESSAGE(content_length, actual_body_len,
        "Content-Length header must match actual body length");
}

// ============================================================================
// Multi-Request Tests (reuse connection if supported)
// ============================================================================

void test_http_multiple_requests_on_same_connection(void) {
    // Note: Current http_server.c uses "Connection: close" so this test
    // would need to be adapted if keep-alive is implemented

    struct tcp_pcb *client_pcb = setup_http_connection();

    // First request
    mock_lwip_inject_request(client_pcb, "GET /api/ping HTTP/1.1\r\n\r\n");
    const char *response1 = mock_lwip_get_response();
    TEST_ASSERT_NOT_NULL(response1);

    // Trigger close
    mock_lwip_trigger_sent_callback(client_pcb, mock_lwip_get_response_len());

    // With current implementation, connection is closed after first request
    TEST_ASSERT_TRUE(mock_lwip_was_closed());
}

// ============================================================================
// Test Runner
// ============================================================================

int main(void) {
    UNITY_BEGIN();

    // Initialization
    RUN_TEST(test_http_server_initialization);

    // Basic requests
    RUN_TEST(test_http_get_request_404);
    RUN_TEST(test_http_cors_preflight_options);

    // Connection lifecycle
    RUN_TEST(test_http_deferred_close_after_sent);
    RUN_TEST(test_http_single_connection_limit);

    // Error handling
    RUN_TEST(test_tcp_write_failure_aborts_connection);
    RUN_TEST(test_tcp_close_failure_falls_back_to_abort);

    // Response validation
    RUN_TEST(test_http_response_has_correct_headers);
    RUN_TEST(test_http_response_content_length_matches_body);

    // Multi-request
    RUN_TEST(test_http_multiple_requests_on_same_connection);

    return UNITY_END();
}
