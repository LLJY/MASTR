#ifndef AP_MANAGER_H
#define AP_MANAGER_H

int start_access_point(const char *ssid, const char *pass);
void stop_access_point(void);

// Reconfigure AP without fully deinitializing the driver: disable AP mode,
// then enable again with new SSID/password. Returns 0 on success.
int reconfigure_access_point(const char *ssid, const char *pass);

// Forward declare DHCP server type
typedef struct _dhcp_server_t dhcp_server_t;

// Get DHCP server for querying connected clients
const dhcp_server_t* get_dhcp_server(void);

#endif // AP_MANAGER_H
