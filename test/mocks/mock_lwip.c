#include "mock_lwip.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// Mock State
// ============================================================================

static char g_response_buffer[8192];  // Captured tcp_write() data
static uint16_t g_response_len = 0;
static bool g_was_closed = false;
static bool g_was_aborted = false;
static uint32_t g_output_call_count = 0;
static err_t g_write_error = ERR_OK;
static err_t g_close_error = ERR_OK;
static uint32_t g_write_call_count = 0;

// Track allocated PCBs for cleanup
#define MAX_PCBS 10
static struct tcp_pcb* g_allocated_pcbs[MAX_PCBS];
static int g_pcb_count = 0;

// Track listening and client PCBs for test helpers
static struct tcp_pcb* g_listen_pcb = NULL;
static struct tcp_pcb* g_client_pcb = NULL;

// ============================================================================
// Mock Control Functions
// ============================================================================

void mock_lwip_reset(void) {
    g_response_len = 0;
    g_response_buffer[0] = '\0';
    g_was_closed = false;
    g_was_aborted = false;
    g_output_call_count = 0;
    g_write_error = ERR_OK;
    g_close_error = ERR_OK;
    g_write_call_count = 0;

    // Free all allocated PCBs
    for (int i = 0; i < g_pcb_count; i++) {
        if (g_allocated_pcbs[i]) {
            free(g_allocated_pcbs[i]);
            g_allocated_pcbs[i] = NULL;
        }
    }
    g_pcb_count = 0;

    g_listen_pcb = NULL;
    g_client_pcb = NULL;
}

void mock_lwip_inject_request(struct tcp_pcb *pcb, const char *request_data) {
    if (!pcb || !pcb->recv) return;

    // Create a pbuf with the request data
    struct pbuf *p = pbuf_alloc(0, strlen(request_data), 0);
    if (!p) return;

    // Copy request data into pbuf
    memcpy(p->payload, request_data, strlen(request_data));

    // Call the registered recv callback
    pcb->recv(pcb->callback_arg, pcb, p, ERR_OK);
}

const char* mock_lwip_get_response(void) {
    return g_response_buffer;
}

uint16_t mock_lwip_get_response_len(void) {
    return g_response_len;
}

const char* mock_lwip_get_full_response(void) {
    return g_response_buffer;
}

bool mock_lwip_was_closed(void) {
    return g_was_closed;
}

bool mock_lwip_was_aborted(void) {
    return g_was_aborted;
}

bool mock_lwip_was_output_called(void) {
    return g_output_call_count > 0;
}

uint32_t mock_lwip_get_output_call_count(void) {
    return g_output_call_count;
}

void mock_lwip_set_write_error(err_t error) {
    g_write_error = error;
}

void mock_lwip_set_close_error(err_t error) {
    g_close_error = error;
}

void mock_lwip_trigger_sent_callback(struct tcp_pcb *pcb, uint16_t len) {
    if (pcb && pcb->sent) {
        pcb->sent(pcb->callback_arg, pcb, len);
    }
}

uint32_t mock_lwip_get_write_call_count(void) {
    return g_write_call_count;
}

void mock_lwip_clear_response(void) {
    g_response_len = 0;
    g_response_buffer[0] = '\0';
    g_write_call_count = 0;
    g_output_call_count = 0;
}

struct tcp_pcb* mock_lwip_get_listen_pcb(void) {
    return g_listen_pcb;
}

struct tcp_pcb* mock_lwip_get_client_pcb(void) {
    return g_client_pcb;
}

void mock_lwip_simulate_accept(struct tcp_pcb *listen_pcb) {
    if (!listen_pcb || !listen_pcb->accept) {
        return;
    }

    // Create a new client PCB
    struct tcp_pcb *client_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!client_pcb) {
        return;
    }

    g_client_pcb = client_pcb;

    // Call the accept callback (simulates incoming connection)
    listen_pcb->accept(listen_pcb->callback_arg, client_pcb, ERR_OK);
}

// ============================================================================
// lwIP TCP API Implementation (Mocked)
// ============================================================================

struct tcp_pcb* tcp_new_ip_type(uint8_t type) {
    (void)type;

    if (g_pcb_count >= MAX_PCBS) {
        return NULL;  // Too many PCBs
    }

    struct tcp_pcb *pcb = (struct tcp_pcb*)calloc(1, sizeof(struct tcp_pcb));
    if (pcb) {
        g_allocated_pcbs[g_pcb_count++] = pcb;
    }
    return pcb;
}

err_t tcp_bind(struct tcp_pcb *pcb, const void *ipaddr, uint16_t port) {
    (void)ipaddr;
    if (!pcb) return ERR_ARG;
    pcb->local_port = port;
    return ERR_OK;
}

struct tcp_pcb* tcp_listen(struct tcp_pcb *pcb) {
    if (!pcb) return NULL;
    pcb->is_listening = true;
    g_listen_pcb = pcb;  // Track for test helpers
    return pcb;  // In real lwIP, this might return a different PCB
}

void tcp_accept(struct tcp_pcb *pcb, err_t (*accept)(void *arg, struct tcp_pcb *newpcb, err_t err)) {
    if (pcb) {
        pcb->accept = accept;
    }
}

err_t tcp_close(struct tcp_pcb *pcb) {
    if (!pcb) return ERR_ARG;

    g_was_closed = true;

    if (g_close_error != ERR_OK) {
        return g_close_error;  // Simulate close failure
    }

    return ERR_OK;
}

void tcp_abort(struct tcp_pcb *pcb) {
    (void)pcb;
    g_was_aborted = true;
}

err_t tcp_write(struct tcp_pcb *pcb, const void *data, uint16_t len, uint8_t flags) {
    (void)pcb;
    (void)flags;

    g_write_call_count++;

    if (g_write_error != ERR_OK) {
        return g_write_error;  // Simulate write failure
    }

    if (!data || len == 0) {
        return ERR_ARG;
    }

    // Append to response buffer
    if (g_response_len + len < sizeof(g_response_buffer)) {
        memcpy(g_response_buffer + g_response_len, data, len);
        g_response_len += len;
        g_response_buffer[g_response_len] = '\0';
    }

    return ERR_OK;
}

err_t tcp_output(struct tcp_pcb *pcb) {
    (void)pcb;
    g_output_call_count++;
    return ERR_OK;
}

void tcp_recved(struct tcp_pcb *pcb, uint16_t len) {
    (void)pcb;
    (void)len;
    // In real lwIP, this updates the TCP window
}

void tcp_arg(struct tcp_pcb *pcb, void *arg) {
    if (pcb) {
        pcb->callback_arg = arg;
    }
}

void tcp_recv(struct tcp_pcb *pcb, err_t (*recv)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)) {
    if (pcb) {
        pcb->recv = recv;
    }
}

void tcp_sent(struct tcp_pcb *pcb, err_t (*sent)(void *arg, struct tcp_pcb *tpcb, uint16_t len)) {
    if (pcb) {
        pcb->sent = sent;
    }
}

void tcp_err(struct tcp_pcb *pcb, void (*err)(void *arg, err_t err)) {
    if (pcb) {
        pcb->err = err;
    }
}

// ============================================================================
// Protocol Buffer (pbuf) Management
// ============================================================================

struct pbuf* pbuf_alloc(uint8_t layer, uint16_t length, uint8_t type) {
    (void)layer;
    (void)type;

    struct pbuf *p = (struct pbuf*)malloc(sizeof(struct pbuf));
    if (!p) return NULL;

    p->payload = malloc(length);
    if (!p->payload) {
        free(p);
        return NULL;
    }

    p->tot_len = length;
    p->len = length;
    p->next = NULL;
    p->ref = 1;

    return p;
}

void pbuf_free(struct pbuf *p) {
    if (!p) return;

    // Free chained pbufs
    struct pbuf *next = p->next;

    if (p->payload) {
        free(p->payload);
    }
    free(p);

    if (next) {
        pbuf_free(next);
    }
}

uint16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, uint16_t len, uint16_t offset) {
    if (!p || !dataptr || len == 0) return 0;

    // Simple implementation: copy from payload starting at offset
    if (offset >= p->len) return 0;

    uint16_t available = p->len - offset;
    uint16_t to_copy = (len < available) ? len : available;

    memcpy(dataptr, (uint8_t*)p->payload + offset, to_copy);

    return to_copy;
}
