#include "http/http_server.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "serial.h"

// Forward declaration of internal helper
static void send_response(struct tcp_pcb *pcb, const char *status, const char *content_type, const char *body);

// Simple route table for exact-match routes
#define MAX_ROUTES 8
typedef void (*http_handler_fn_t)(struct tcp_pcb *pcb, const char *request);
struct route_entry { const char *path; http_handler_fn_t handler; };
static struct route_entry routes[MAX_ROUTES];

int http_register(const char *path, http_handler_fn handler) {
    for (int i = 0; i < MAX_ROUTES; ++i) {
        if (routes[i].path == NULL) {
            routes[i].path = path;
            routes[i].handler = handler;
            return 0;
        }
    }
    return -1;
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

#define HTTP_PORT 80

typedef struct {
    char request[1024];
    int request_len;
    bool is_in_use; // Flag to track if we are busy
} http_state_t;

// Single static instance for simplicity/stability
static http_state_t connection_state;

static void send_response(struct tcp_pcb *pcb, const char *status, const char *content_type, const char *body) {
    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n\r\n",
        status, content_type, (int)strlen(body));

    tcp_write(pcb, header, header_len, TCP_WRITE_FLAG_COPY);
    tcp_write(pcb, body, strlen(body), TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);
}

static void handle_request(struct tcp_pcb *pcb, char *request) {
    char method[8], path[64];
    sscanf(request, "%7s %63s", method, path);

    // Check registered routes first
    for (int i = 0; i < MAX_ROUTES; ++i) {
        if (routes[i].path != NULL && strcmp(path, routes[i].path) == 0) {
            routes[i].handler(pcb, request);
            return;
        }
    }

    // No built-in application routes here; transport returns 404 for unknown paths.
    send_response(pcb, "404 Not Found", "application/json", "{\"error\":\"not found\"}");
}

static err_t http_close(struct tcp_pcb *pcb) {
    connection_state.is_in_use = false;
    connection_state.request_len = 0;
    tcp_close(pcb);
    return ERR_OK;
}

static void http_err(void *arg, err_t err) {
    (void)arg; (void)err;
    connection_state.is_in_use = false;
    connection_state.request_len = 0;
}

static err_t http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) {
        return http_close(pcb);
    }

    if (p->tot_len > 0) {
        int copy_len = sizeof(connection_state.request) - connection_state.request_len - 1;
        if (p->tot_len < copy_len) copy_len = p->tot_len;

        pbuf_copy_partial(p, connection_state.request + connection_state.request_len, copy_len, 0);
        connection_state.request_len += copy_len;
        connection_state.request[connection_state.request_len] = '\0';
        tcp_recved(pcb, p->tot_len);

        if (strstr(connection_state.request, "\r\n\r\n")) {
            handle_request(pcb, connection_state.request);
            pbuf_free(p);
            return http_close(pcb);
        }
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t http_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    (void)arg; (void)err;
    if (connection_state.is_in_use) {
        tcp_abort(client_pcb);
        return ERR_ABRT;
    }

    connection_state.is_in_use = true;
    tcp_arg(client_pcb, &connection_state);
    tcp_recv(client_pcb, http_recv);
    tcp_err(client_pcb, http_err);
    return ERR_OK;
}

void http_server_init(void) {
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    tcp_bind(pcb, NULL, HTTP_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, http_accept);
    print_dbg("HTTP server initialized on port 80\n");
}
