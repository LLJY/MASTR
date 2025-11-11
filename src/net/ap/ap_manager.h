#ifndef AP_MANAGER_H
#define AP_MANAGER_H

int start_access_point(const char *ssid, const char *pass);
void stop_access_point(void);

// Forward declare DHCP server type
typedef struct _dhcp_server_t dhcp_server_t;

// Get DHCP server for querying connected clients
const dhcp_server_t* get_dhcp_server(void);

#endif // AP_MANAGER_H
