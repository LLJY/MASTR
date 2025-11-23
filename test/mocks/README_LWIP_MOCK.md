# lwIP TCP/IP Stack Mock for Unit Testing

## Quick Start

```c
#include "unity.h"
#include "mock_lwip.h"      // Include BEFORE http_server.h
#include "http_server.h"

void test_my_http_endpoint(void) {
    // 1. Reset mock state
    mock_lwip_reset();

    // 2. Initialize HTTP server
    http_server_init();

    // 3. Simulate incoming connection
    struct tcp_pcb *listen_pcb = mock_lwip_get_listen_pcb();
    mock_lwip_simulate_accept(listen_pcb);

    // 4. Inject HTTP request
    struct tcp_pcb *client_pcb = mock_lwip_get_client_pcb();
    mock_lwip_inject_request(client_pcb,
        "GET /api/endpoint HTTP/1.1\r\n\r\n");

    // 5. Verify response
    const char *response = mock_lwip_get_response();
    TEST_ASSERT_TRUE(strstr(response, "HTTP/1.1 200 OK") != NULL);
}
```

## What This Mock Does

**Truthful Testing:** Simulates lwIP TCP/IP stack behavior accurately. Server code generates REAL HTTP responses, not stubbed values.

**Complete Coverage:** All 16 lwIP functions used by `http_server.c` are mocked.

**Error Injection:** Test failure paths by forcing `tcp_write()` or `tcp_close()` to fail.

**Full Introspection:** Inspect accumulated response data, call counts, connection state.

## Files

- `mock_lwip.h` - Type definitions, function declarations, test helpers (154 lines)
- `mock_lwip.c` - Mock implementations (315 lines)
- `../LWIP_MOCK_ANALYSIS.md` - Detailed design documentation
- `../test_http_server_example.c` - Complete example tests

## API Reference

### Setup/Teardown
```c
void mock_lwip_reset(void);              // Reset all state (call in setUp())
void mock_lwip_clear_response(void);     // Clear only response buffer
```

### Request Injection
```c
// Inject HTTP request (creates pbuf, calls recv callback)
void mock_lwip_inject_request(struct tcp_pcb *pcb, const char *request);

// Simulate incoming connection (calls accept callback)
void mock_lwip_simulate_accept(struct tcp_pcb *listen_pcb);

// Trigger sent callback (data acknowledged)
void mock_lwip_trigger_sent_callback(struct tcp_pcb *pcb, uint16_t len);
```

### Response Inspection
```c
const char* mock_lwip_get_response(void);        // Get accumulated response
uint16_t mock_lwip_get_response_len(void);       // Response length
uint32_t mock_lwip_get_write_call_count(void);   // tcp_write() call count
uint32_t mock_lwip_get_output_call_count(void);  // tcp_output() call count
```

### State Queries
```c
bool mock_lwip_was_closed(void);         // tcp_close() called?
bool mock_lwip_was_aborted(void);        // tcp_abort() called?
struct tcp_pcb* mock_lwip_get_listen_pcb(void);
struct tcp_pcb* mock_lwip_get_client_pcb(void);
```

### Error Injection
```c
void mock_lwip_set_write_error(err_t error);   // Force tcp_write() to fail
void mock_lwip_set_close_error(err_t error);   // Force tcp_close() to fail
```

## lwIP Functions Mocked

### Connection Management
- `tcp_new_ip_type()` - Create TCP PCB
- `tcp_bind()` - Bind to port
- `tcp_listen()` - Start listening
- `tcp_accept()` - Register accept callback
- `tcp_close()` - Graceful close
- `tcp_abort()` - Forceful abort

### Callbacks
- `tcp_arg()` - Set callback argument
- `tcp_recv()` - Register receive callback
- `tcp_sent()` - Register sent callback
- `tcp_err()` - Register error callback

### Data Transfer
- `tcp_write()` - Queue data for transmission
- `tcp_output()` - Flush send buffer
- `tcp_recved()` - Acknowledge received data

### Packet Buffers
- `pbuf_alloc()` - Allocate packet buffer
- `pbuf_free()` - Free packet buffer
- `pbuf_copy_partial()` - Copy data from pbuf

## Error Codes (err_t)

```c
ERR_OK          0    // Success
ERR_MEM        -1    // Out of memory
ERR_BUF        -2    // Buffer error
ERR_ABRT       -13   // Connection aborted
ERR_RST        -14   // Connection reset
ERR_CLSD       -15   // Connection closed
ERR_ARG        -16   // Invalid argument
```

## Testing Philosophy

**NO FAKE TESTS:** Mocks simulate real lwIP behavior, not convenient test behavior.

 **What We Test:**
- HTTP request parsing
- Response generation
- Error handling
- Callback lifecycle
- CORS headers

L **What We Don't Test:**
- Real network I/O
- TCP state machine
- Retransmission/flow control
- lwIP memory pools

**These limitations are acceptable for unit testing.**

## Example Test Pattern

```c
void test_endpoint_with_deferred_close(void) {
    mock_lwip_reset();

    // Setup server and connection
    http_server_init();
    struct tcp_pcb *listen_pcb = mock_lwip_get_listen_pcb();
    mock_lwip_simulate_accept(listen_pcb);
    struct tcp_pcb *client_pcb = mock_lwip_get_client_pcb();

    // Send request
    mock_lwip_inject_request(client_pcb, "GET /api/test HTTP/1.1\r\n\r\n");

    // Verify response written but NOT closed yet
    TEST_ASSERT_TRUE(mock_lwip_was_output_called());
    TEST_ASSERT_FALSE(mock_lwip_was_closed());

    // Trigger deferred close (http_server uses tcp_sent callback)
    mock_lwip_trigger_sent_callback(client_pcb,
        mock_lwip_get_response_len());

    // Verify connection closed gracefully
    TEST_ASSERT_TRUE(mock_lwip_was_closed());
    TEST_ASSERT_FALSE(mock_lwip_was_aborted());
}
```

## Integration with CMake

Add to `test/CMakeLists.txt`:

```cmake
add_library(mock_lwip STATIC mocks/mock_lwip.c)
target_include_directories(mock_lwip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mocks)

add_executable(test_http_server
    test_http_server.c
    ${PROJECT_SOURCE_DIR}/src/net/http/http_server.c
)
target_link_libraries(test_http_server unity mock_lwip mock_pico_sdk)
target_include_directories(test_http_server PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/net/http
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
)

add_test(NAME http_server COMMAND test_http_server)
```

## Common Pitfalls

### L Wrong: Including real lwIP headers
```c
#include <lwip/tcp.h>     // DON'T DO THIS
#include "mock_lwip.h"
```

###  Correct: Mock headers first
```c
#include "mock_lwip.h"    // Provides lwIP types
#include "http_server.h"  // Uses those types
```

### L Wrong: Forgetting to reset
```c
void test_something(void) {
    http_server_init();  // State from previous test!
}
```

###  Correct: Always reset in setUp()
```c
void setUp(void) {
    mock_lwip_reset();  // Clean slate
}
```

### L Wrong: Not freeing pbuf
```c
struct pbuf *p = pbuf_alloc(0, 100, 0);
// Memory leak!
```

###  Correct: Free after use
```c
struct pbuf *p = pbuf_alloc(0, 100, 0);
pbuf_free(p);  // Always free
```

## Debugging Tips

### Print response for inspection
```c
const char *response = mock_lwip_get_response();
printf("Response:\n%s\n", response);
```

### Check call counts
```c
printf("tcp_write() called %u times\n", mock_lwip_get_write_call_count());
printf("tcp_output() called %u times\n", mock_lwip_get_output_call_count());
```

### Verify connection state
```c
printf("Closed: %d, Aborted: %d\n",
    mock_lwip_was_closed(), mock_lwip_was_aborted());
```

## See Also

- `../LWIP_MOCK_ANALYSIS.md` - Complete design documentation
- `../test_http_server_example.c` - Full example tests
- lwIP docs: https://www.nongnu.org/lwip/2_1_x/

---

**Author:** Claude Code (Anthropic)
**Date:** 2025-11-23
**Version:** 1.0
