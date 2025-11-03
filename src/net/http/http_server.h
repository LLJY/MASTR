#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

struct tcp_pcb;
typedef void (*http_handler_fn)(struct tcp_pcb *pcb, const char *request);

void http_server_init(void);

// Register a handler for an exact path (e.g. "/api/ping").
// Returns 0 on success, -1 on failure (no space).
int http_register(const char *path, http_handler_fn handler);

// Helper to send a JSON response with a numeric status code (200, 404, ...)
void http_send_json(struct tcp_pcb *pcb, int status_code, const char *json_body);

#endif // HTTP_SERVER_H
