#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <stdint.h>
#include <stdbool.h>

struct tcp_pcb;
typedef void (*http_handler_fn)(struct tcp_pcb *pcb, const char *request);

void http_server_init(void);

// Register a handler for an exact path (e.g. "/api/ping").
// Returns 0 on success, -1 on failure (no space).
int http_register(const char *path, http_handler_fn handler);

// Register a handler with optional authentication requirement
int http_register_auth(const char *path, http_handler_fn handler, bool requires_auth);

// Helper to send a JSON response with a numeric status code (200, 404, ...)
void http_send_json(struct tcp_pcb *pcb, int status_code, const char *json_body);

// Validate bearer token from request (called internally by HTTP server)
// Implemented in api.c
bool http_validate_bearer_token(const char *request);

// HTTP connection monitoring functions
uint32_t http_get_active_connections(void);

typedef struct {
    char request[1024];
    int request_len;
    bool in_use;
    bool close_when_sent;
} http_state_t;

#define MAX_ROUTES 16 
static void http_connection_opened(void);
static void http_connection_closed(void);

#endif // HTTP_SERVER_H
