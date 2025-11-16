#ifndef API_H
#define API_H

#include <stdbool.h>

// Register API routes with the HTTP server. Call after http_server_init().
void api_register_routes(void);

// Bearer token validation (called by HTTP server)
// Returns true if request has valid bearer token, false otherwise
bool http_validate_bearer_token(const char *request);

#endif // API_H
