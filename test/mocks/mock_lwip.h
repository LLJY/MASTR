#ifndef MOCK_LWIP_H
#define MOCK_LWIP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// lwIP Error Codes (from lwip/err.h)
// ============================================================================
typedef int8_t err_t;
#define ERR_OK          0    // No error
#define ERR_MEM        -1    // Out of memory
#define ERR_BUF        -2    // Buffer error
#define ERR_TIMEOUT    -3    // Timeout
#define ERR_RTE        -4    // Routing problem
#define ERR_INPROGRESS -5    // Operation in progress
#define ERR_VAL        -6    // Illegal value
#define ERR_WOULDBLOCK -7    // Operation would block
#define ERR_USE        -8    // Address in use
#define ERR_ALREADY    -9    // Already connecting
#define ERR_ISCONN     -10   // Already connected
#define ERR_CONN       -11   // Not connected
#define ERR_IF         -12   // Low-level netif error
#define ERR_ABRT       -13   // Connection aborted
#define ERR_RST        -14   // Connection reset
#define ERR_CLSD       -15   // Connection closed
#define ERR_ARG        -16   // Illegal argument

// ============================================================================
// lwIP IP Address Types
// ============================================================================
#define IPADDR_TYPE_V4   0
#define IPADDR_TYPE_V6   1
#define IPADDR_TYPE_ANY  2

// IPv4 address structure
typedef struct {
    uint32_t addr;
} ip4_addr_t;

// Generic IP address (supports both v4 and v6)
typedef struct {
    union {
        ip4_addr_t ip4;
        uint32_t ip4_u32;  // Direct access
    } u_addr;
    uint8_t type;  // IPADDR_TYPE_V4, V6, or ANY
} ip_addr_t;

// Helper macros for IP address manipulation
#define IP4_ADDR(ipaddr, a,b,c,d) \
    (ipaddr)->addr = ((uint32_t)((d) & 0xff) << 24) | \
                     ((uint32_t)((c) & 0xff) << 16) | \
                     ((uint32_t)((b) & 0xff) << 8)  | \
                      (uint32_t)((a) & 0xff)

#define ip4_addr1(ipaddr) (((ipaddr)->addr) & 0xff)
#define ip4_addr2(ipaddr) (((ipaddr)->addr >> 8) & 0xff)
#define ip4_addr3(ipaddr) (((ipaddr)->addr >> 16) & 0xff)
#define ip4_addr4(ipaddr) (((ipaddr)->addr >> 24) & 0xff)

#define ip_2_ip4(ipaddr)   (&((ipaddr)->u_addr.ip4))
#define ip4_addr_get_u32(ipaddr) ((ipaddr)->addr)

// ============================================================================
// TCP Write Flags
// ============================================================================
#define TCP_WRITE_FLAG_COPY 0x01  // Copy data to internal buffer
#define TCP_WRITE_FLAG_MORE 0x02  // More data coming

// ============================================================================
// lwIP Protocol Buffer (pbuf) - Network Packet Container
// ============================================================================
struct pbuf {
    struct pbuf *next;     // Next pbuf in chain (for fragmented packets)
    void *payload;         // Pointer to actual data
    uint16_t tot_len;      // Total length of this pbuf + all next pbufs
    uint16_t len;          // Length of this pbuf only
    uint8_t type;          // Type of pbuf (ROM/RAM/etc)
    uint8_t flags;         // Misc flags
    uint16_t ref;          // Reference count
};

// u16_t typedef for lwIP compatibility
typedef uint16_t u16_t;

// ============================================================================
// lwIP TCP Control Block (tcp_pcb) - Connection State
// ============================================================================
struct tcp_pcb {
    void *callback_arg;    // User-provided argument for callbacks

    // Callback function pointers
    err_t (*recv)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    err_t (*sent)(void *arg, struct tcp_pcb *tpcb, u16_t len);
    void (*err)(void *arg, err_t err);
    err_t (*accept)(void *arg, struct tcp_pcb *newpcb, err_t err);

    // Mock-specific tracking
    bool is_listening;     // Is this a listening PCB?
    uint16_t local_port;   // Local port number
    uint32_t mock_id;      // Unique ID for debugging
};

// ============================================================================
// lwIP TCP API Functions (Mocked)
// ============================================================================

// PCB creation and setup
struct tcp_pcb* tcp_new_ip_type(uint8_t type);
err_t tcp_bind(struct tcp_pcb *pcb, const void *ipaddr, uint16_t port);
struct tcp_pcb* tcp_listen(struct tcp_pcb *pcb);
void tcp_accept(struct tcp_pcb *pcb, err_t (*accept)(void *arg, struct tcp_pcb *newpcb, err_t err));

// Connection management
err_t tcp_close(struct tcp_pcb *pcb);
void tcp_abort(struct tcp_pcb *pcb);

// Data transmission
err_t tcp_write(struct tcp_pcb *pcb, const void *data, uint16_t len, uint8_t flags);
err_t tcp_output(struct tcp_pcb *pcb);
void tcp_recved(struct tcp_pcb *pcb, uint16_t len);

// Callback registration
void tcp_arg(struct tcp_pcb *pcb, void *arg);
void tcp_recv(struct tcp_pcb *pcb, err_t (*recv)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err));
void tcp_sent(struct tcp_pcb *pcb, err_t (*sent)(void *arg, struct tcp_pcb *tpcb, u16_t len));
void tcp_err(struct tcp_pcb *pcb, void (*err)(void *arg, err_t err));

// Protocol buffer management
struct pbuf* pbuf_alloc(uint8_t layer, uint16_t length, uint8_t type);
void pbuf_free(struct pbuf *p);
uint16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, uint16_t len, uint16_t offset);

// ============================================================================
// Mock Control Functions (Test Helpers)
// ============================================================================

// Reset mock state between tests
void mock_lwip_reset(void);

// Inject a simulated HTTP request into the server
// Creates a pbuf and calls the recv callback on the pcb
void mock_lwip_inject_request(struct tcp_pcb *pcb, const char *request_data);

// Get the captured response data that was written via tcp_write()
const char* mock_lwip_get_response(void);
uint16_t mock_lwip_get_response_len(void);

// Check if tcp_close() or tcp_abort() was called
bool mock_lwip_was_closed(void);
bool mock_lwip_was_aborted(void);

// Check if tcp_output() was called
bool mock_lwip_was_output_called(void);
uint32_t mock_lwip_get_output_call_count(void);

// Force tcp_write() to fail with specified error
void mock_lwip_set_write_error(err_t error);

// Force tcp_close() to fail with specified error
void mock_lwip_set_close_error(err_t error);

// Simulate successful data transmission (trigger sent callback)
void mock_lwip_trigger_sent_callback(struct tcp_pcb *pcb, uint16_t len);

// Get number of times tcp_write was called
uint32_t mock_lwip_get_write_call_count(void);

// Clear the response buffer (for multi-request tests)
void mock_lwip_clear_response(void);

// Get listening PCB (for test setup)
struct tcp_pcb* mock_lwip_get_listen_pcb(void);

// Get client PCB (created during accept)
struct tcp_pcb* mock_lwip_get_client_pcb(void);

// Simulate incoming connection (triggers accept callback)
void mock_lwip_simulate_accept(struct tcp_pcb *listen_pcb);

#endif // MOCK_LWIP_H
