// Rebuilt HTTP server file: cleaned duplicates, minimal single-connection server
// with deferred close via tcp_sent to reduce intermittent curl failures.

#include "http_server.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "serial.h"


struct route_entry { const char *path; http_handler_fn handler; };
static struct route_entry routes[MAX_ROUTES];

int http_register(const char *path, http_handler_fn handler) {
    for (int i = 0; i < MAX_ROUTES; ++i) {
        if (routes[i].path == NULL) {
            routes[i].path = path;
            routes[i].handler = handler;
            return 0;
        }
    }
#ifdef DEBUG
    print_dbg("[HTTP] Route table full, failed to register: %s\n", path);
#endif
    return -1;
}

static http_state_t g_state;

static void reset_state(void) {
    g_state.request_len = 0;
    g_state.request[0] = '\0';
    g_state.in_use = false;
    g_state.close_when_sent = false;
    
    // Track connection closing
    http_connection_closed();
}

static void send_response(struct tcp_pcb *pcb, const char *status, const char *content_type, const char *body) {
    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n",
        status, content_type, (int)strlen(body));

    if (tcp_write(pcb, header, header_len, TCP_WRITE_FLAG_COPY) != ERR_OK) {
        tcp_abort(pcb); return; }
    if (tcp_write(pcb, body, strlen(body), TCP_WRITE_FLAG_COPY) != ERR_OK) {
        tcp_abort(pcb); return; }
    tcp_output(pcb);
    g_state.close_when_sent = true;
}

void http_send_json(struct tcp_pcb *pcb, int status_code, const char *json_body) {
    char status[32];
    switch (status_code) {
        case 200: strcpy(status, "200 OK"); break;
        case 404: strcpy(status, "404 Not Found"); break;
        case 500: strcpy(status, "500 Internal Server Error"); break;
        default: snprintf(status, sizeof(status), "%d", status_code); break;
    }
    send_response(pcb, status, "application/json", json_body);
}

static void handle_request(struct tcp_pcb *pcb, char *request) {
    char method[8], path[64];
    sscanf(request, "%7s %63s", method, path);
    for (int i = 0; i < MAX_ROUTES; ++i) {
        if (routes[i].path && strcmp(path, routes[i].path) == 0) {
            routes[i].handler(pcb, request);
            return;
        }
    }
    send_response(pcb, "404 Not Found", "application/json", "{\"error\":\"not found\"}");
}

static err_t http_close(struct tcp_pcb *pcb) {
    reset_state();
    return tcp_close(pcb);
}

static void http_err(void *arg, err_t err) {
    (void)arg; (void)err; reset_state(); }

static err_t http_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)len;
    if (g_state.close_when_sent) return http_close(pcb);
    return ERR_OK;
}

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) return http_close(pcb);
    if (p->tot_len > 0) {
        int copy_len = sizeof(g_state.request) - g_state.request_len - 1;
        if (copy_len < 0) copy_len = 0;
        if (p->tot_len < copy_len) copy_len = p->tot_len;
        if (copy_len > 0) {
            pbuf_copy_partial(p, g_state.request + g_state.request_len, copy_len, 0);
            g_state.request_len += copy_len;
            g_state.request[g_state.request_len] = '\0';
        }
        tcp_recved(pcb, p->tot_len);
        if (strstr(g_state.request, "\r\n\r\n")) {
            handle_request(pcb, g_state.request);
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t http_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    (void)arg; (void)err;
    if (g_state.in_use) { 
        tcp_close(client_pcb); 
        return ERR_OK; 
    }
    
    // Track new connection
    http_connection_opened();
    
    g_state.in_use = true; g_state.request_len = 0; g_state.close_when_sent = false; g_state.request[0] = '\0';
    tcp_arg(client_pcb, &g_state);
    tcp_recv(client_pcb, http_recv);
    tcp_err(client_pcb, http_err);
    tcp_sent(client_pcb, http_sent);
    return ERR_OK;
}

void http_server_init(void) {
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) { print_dbg("HTTP: tcp_new failed\n"); return; }
    if (tcp_bind(pcb, NULL, 80) != ERR_OK) { print_dbg("HTTP: bind failed\n"); tcp_abort(pcb); return; }
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, http_accept);
    print_dbg("HTTP server initialized on port 80\n");
}

// ============================================================================
// HTTP Server Monitoring Functions
// ============================================================================

static uint32_t g_active_connections = 0;

static void http_connection_opened(void) {
    g_active_connections++;
}

static void http_connection_closed(void) {
    if (g_active_connections > 0) {
        g_active_connections--;
    }
}

uint32_t http_get_active_connections(void) {
    return g_active_connections;
}
