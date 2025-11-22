/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2019 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "cyw43_config.h"
#include "dhcpserver.h"
#include "lwip/udp.h"

#define DHCPDISCOVER    (1)
#define DHCPOFFER       (2)
#define DHCPREQUEST     (3)
#define DHCPDECLINE     (4)
#define DHCPACK         (5)
#define DHCPNACK        (6)
#define DHCPRELEASE     (7)
#define DHCPINFORM      (8)

#define DHCP_OPT_PAD                (0)
#define DHCP_OPT_SUBNET_MASK        (1)
#define DHCP_OPT_ROUTER             (3)
#define DHCP_OPT_DNS                (6)
#define DHCP_OPT_HOST_NAME          (12)
#define DHCP_OPT_REQUESTED_IP       (50)
#define DHCP_OPT_IP_LEASE_TIME      (51)
#define DHCP_OPT_MSG_TYPE           (53)
#define DHCP_OPT_SERVER_ID          (54)
#define DHCP_OPT_PARAM_REQUEST_LIST (55)
#define DHCP_OPT_MAX_MSG_SIZE       (57)
#define DHCP_OPT_VENDOR_CLASS_ID    (60)
#define DHCP_OPT_CLIENT_ID          (61)
#define DHCP_OPT_END                (255)

#define PORT_DHCP_SERVER (67)
#define PORT_DHCP_CLIENT (68)

#define DEFAULT_LEASE_TIME_S (24 * 60 * 60)

#define MAC_LEN (6)
#define MAKE_IP4(a, b, c, d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))

typedef struct {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint8_t ciaddr[4];
    uint8_t yiaddr[4];
    uint8_t siaddr[4];
    uint8_t giaddr[4];
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
} dhcp_msg_t;

/*******************************************************************************
 * @brief Convert lwIP IPv4 address to dotted-order bytes.
 * @param a Source IP address.
 * @param buf Destination buffer for four octets.
 * @return void
 ******************************************************************************/
static void ipaddr_to_bytes(const ip_addr_t *a, uint8_t *buf) {
    const ip4_addr_t *ip4 = ip_2_ip4((ip_addr_t *)a);
    buf[0] = ip4_addr1(ip4);
    buf[1] = ip4_addr2(ip4);
    buf[2] = ip4_addr3(ip4);
    buf[3] = ip4_addr4(ip4);
}

/*******************************************************************************
 * @brief Allocate a UDP socket for DHCP.
 * @param udp Output pointer for the PCB.
 * @param cb_data User data passed to the callback.
 * @param cb_udp_recv Receive callback.
 * @return 0 on success, negative errno on failure.
 ******************************************************************************/
static int dhcp_socket_new_dgram(struct udp_pcb **udp, void *cb_data, udp_recv_fn cb_udp_recv) {
    *udp = udp_new();
    if (*udp == NULL) {
        return -ENOMEM;
    }

    udp_recv(*udp, cb_udp_recv, (void *)cb_data);

    return 0;
}

/*******************************************************************************
 * @brief Free a DHCP UDP socket.
 * @param udp PCB pointer to clear.
 * @return void
 ******************************************************************************/
static void dhcp_socket_free(struct udp_pcb **udp) {
    if (*udp != NULL) {
        udp_remove(*udp);
        *udp = NULL;
    }
}

/*******************************************************************************
 * @brief Bind a DHCP UDP socket to a port.
 * @param udp PCB pointer.
 * @param port Port number.
 * @return lwIP status code.
 ******************************************************************************/
static int dhcp_socket_bind(struct udp_pcb **udp, uint16_t port) {
    return udp_bind(*udp, IP_ANY_TYPE, port);
}

/*******************************************************************************
 * @brief Send a DHCP UDP datagram.
 * @param udp PCB pointer.
 * @param nif Network interface to send on (optional).
 * @param buf Payload buffer.
 * @param len Payload length.
 * @param ip Destination IPv4 address.
 * @param port Destination port.
 * @return Bytes sent or error code.
 ******************************************************************************/
static int dhcp_socket_sendto(struct udp_pcb **udp, struct netif *nif, const void *buf, size_t len, uint32_t ip, uint16_t port) {
    if (len > 0xffff) {
        len = 0xffff;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (p == NULL) {
        return -ENOMEM;
    }

    memcpy(p->payload, buf, len);

    ip_addr_t dest;
    IP4_ADDR(ip_2_ip4(&dest), ip >> 24 & 0xff, ip >> 16 & 0xff, ip >> 8 & 0xff, ip & 0xff);
    err_t err;
    if (nif != NULL) {
        err = udp_sendto_if(*udp, p, &dest, port, nif);
    } else {
        err = udp_sendto(*udp, p, &dest, port);
    }

    pbuf_free(p);

    if (err != ERR_OK) {
        return err;
    }

    return len;
}

/*******************************************************************************
 * @brief Find a DHCP option within an options buffer.
 * @param opt Options buffer start.
 * @param cmd Option code to search for.
 * @return Pointer to matching option or NULL.
 ******************************************************************************/
static uint8_t *opt_find(uint8_t *opt, uint8_t cmd) {
    for (int i = 0; i < 308 && opt[i] != DHCP_OPT_END;) {
        if (opt[i] == cmd) {
            return &opt[i];
        }
        i += 2 + opt[i + 1];
    }
    return NULL;
}

/*******************************************************************************
 * @brief Write a DHCP option with arbitrary length.
 * @param opt Cursor pointer updated on return.
 * @param cmd Option code.
 * @param n Length of data.
 * @param data Pointer to data bytes.
 * @return void
 ******************************************************************************/
static void opt_write_n(uint8_t **opt, uint8_t cmd, size_t n, const void *data) {
    uint8_t *o = *opt;
    *o++ = cmd;
    *o++ = n;
    memcpy(o, data, n);
    *opt = o + n;
}

/*******************************************************************************
 * @brief Write a one-byte DHCP option.
 * @param opt Cursor pointer updated on return.
 * @param cmd Option code.
 * @param val Option value.
 * @return void
 ******************************************************************************/
static void opt_write_u8(uint8_t **opt, uint8_t cmd, uint8_t val) {
    uint8_t *o = *opt;
    *o++ = cmd;
    *o++ = 1;
    *o++ = val;
    *opt = o;
}

/*******************************************************************************
 * @brief Write a four-byte DHCP option.
 * @param opt Cursor pointer updated on return.
 * @param cmd Option code.
 * @param val Option value.
 * @return void
 ******************************************************************************/
static void opt_write_u32(uint8_t **opt, uint8_t cmd, uint32_t val) {
    uint8_t *o = *opt;
    *o++ = cmd;
    *o++ = 4;
    *o++ = val >> 24;
    *o++ = val >> 16;
    *o++ = val >> 8;
    *o++ = val;
    *opt = o;
}

/*******************************************************************************
 * @brief Process inbound DHCP packets and respond appropriately.
 * @param arg DHCP server context.
 * @param upcb UDP PCB (unused).
 * @param p Incoming pbuf.
 * @param src_addr Source address (unused).
 * @param src_port Source port (unused).
 * @return void
 ******************************************************************************/
static void dhcp_server_process(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *src_addr, u16_t src_port) {
    dhcp_server_t *d = arg;
    (void)upcb;
    (void)src_addr;
    (void)src_port;

    dhcp_msg_t dhcp_msg;

    #define DHCP_MIN_SIZE (240 + 3)
    if (p->tot_len < DHCP_MIN_SIZE) {
        goto ignore_request;
    }

    size_t len = pbuf_copy_partial(p, &dhcp_msg, sizeof(dhcp_msg), 0);
    if (len < DHCP_MIN_SIZE) {
        goto ignore_request;
    }

    dhcp_msg.op = DHCPOFFER;
    ipaddr_to_bytes(&d->ip, dhcp_msg.yiaddr);

    uint8_t *opt = (uint8_t *)&dhcp_msg.options;
    opt += 4;

    uint8_t *msgtype = opt_find(opt, DHCP_OPT_MSG_TYPE);
    if (msgtype == NULL) {
        goto ignore_request;
    }

    switch (msgtype[2]) {
        case DHCPDISCOVER: {
            int yi = DHCPS_MAX_IP;
            for (int i = 0; i < DHCPS_MAX_IP; ++i) {
                if (memcmp(d->lease[i].mac, dhcp_msg.chaddr, MAC_LEN) == 0) {
                    yi = i;
                    break;
                }
                if (yi == DHCPS_MAX_IP) {
                    if (memcmp(d->lease[i].mac, "\x00\x00\x00\x00\x00\x00", MAC_LEN) == 0) {
                        yi = i;
                    }
                    uint32_t expiry = d->lease[i].expiry << 16 | 0xffff;
                    if ((int32_t)(expiry - cyw43_hal_ticks_ms()) < 0) {
                        memset(d->lease[i].mac, 0, MAC_LEN);
                        yi = i;
                    }
                }
            }
            if (yi == DHCPS_MAX_IP) {
                goto ignore_request;
            }
            dhcp_msg.yiaddr[3] = DHCPS_BASE_IP + yi;
            opt_write_u8(&opt, DHCP_OPT_MSG_TYPE, DHCPOFFER);
            break;
        }

        case DHCPREQUEST: {
            uint8_t *o = opt_find(opt, DHCP_OPT_REQUESTED_IP);
            if (o == NULL) {
                goto ignore_request;
            }
            uint8_t server_id_bytes[4];
            ipaddr_to_bytes(&d->ip, server_id_bytes);
            if (memcmp(o + 2, server_id_bytes, 3) != 0) {
                goto ignore_request;
            }
            uint8_t yi = o[5] - DHCPS_BASE_IP;
            if (yi >= DHCPS_MAX_IP) {
                goto ignore_request;
            }
            if (memcmp(d->lease[yi].mac, dhcp_msg.chaddr, MAC_LEN) == 0) {
            } else if (memcmp(d->lease[yi].mac, "\x00\x00\x00\x00\x00\x00", MAC_LEN) == 0) {
                memcpy(d->lease[yi].mac, dhcp_msg.chaddr, MAC_LEN);
            } else {
                goto ignore_request;
            }
            d->lease[yi].expiry = (cyw43_hal_ticks_ms() + DEFAULT_LEASE_TIME_S * 1000) >> 16;
            dhcp_msg.yiaddr[3] = DHCPS_BASE_IP + yi;
            opt_write_u8(&opt, DHCP_OPT_MSG_TYPE, DHCPACK);
            break;
        }

        default:
            goto ignore_request;
    }

    uint8_t tmp_ip[4];
    ipaddr_to_bytes(&d->ip, tmp_ip);
    opt_write_n(&opt, DHCP_OPT_SERVER_ID, 4, tmp_ip);
    ipaddr_to_bytes(&d->nm, tmp_ip);
    opt_write_n(&opt, DHCP_OPT_SUBNET_MASK, 4, tmp_ip);
    ipaddr_to_bytes(&d->ip, tmp_ip);
    opt_write_n(&opt, DHCP_OPT_ROUTER, 4, tmp_ip);
    ipaddr_to_bytes(&d->ip, tmp_ip);
    opt_write_n(&opt, DHCP_OPT_DNS, 4, tmp_ip);
    opt_write_u32(&opt, DHCP_OPT_IP_LEASE_TIME, DEFAULT_LEASE_TIME_S);
    *opt++ = DHCP_OPT_END;
    struct netif *nif = ip_current_input_netif();
    dhcp_socket_sendto(&d->udp, nif, &dhcp_msg, opt - (uint8_t *)&dhcp_msg, 0xffffffff, PORT_DHCP_CLIENT);

ignore_request:
    pbuf_free(p);
}

/*******************************************************************************
 * @brief Initialize and bind the DHCP server.
 * @param d DHCP server context.
 * @param ip Server IP address.
 * @param nm Netmask.
 * @return void
 ******************************************************************************/
void dhcp_server_init(dhcp_server_t *d, ip_addr_t *ip, ip_addr_t *nm) {
    ip_addr_copy(d->ip, *ip);
    ip_addr_copy(d->nm, *nm);
    memset(d->lease, 0, sizeof(d->lease));
    if (dhcp_socket_new_dgram(&d->udp, d, dhcp_server_process) != 0) {
        return;
    }
    dhcp_socket_bind(&d->udp, PORT_DHCP_SERVER);
}

/*******************************************************************************
 * @brief Deinitialize the DHCP server and free resources.
 * @param d DHCP server context.
 * @return void
 ******************************************************************************/
void dhcp_server_deinit(dhcp_server_t *d) {
    dhcp_socket_free(&d->udp);
}
