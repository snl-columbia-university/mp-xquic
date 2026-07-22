#ifndef QUIC_API_H
#define QUIC_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct quic_endpoint quic_endpoint_t;

/* Callback function to deliver received payload data to the application */
typedef void (*quic_recv_cb)(const uint8_t *data, size_t len, void *user_data);

typedef struct {
    const char *local_ips[4];
    size_t num_local_addrs;
    
    const char *peer_ips[4];
    size_t num_peer_addrs;
    uint16_t peer_port;         /* Default: 8000 */

    int enable_datagram;        /* 1 = Datagram mode, 0 = Stream mode */
    int enable_redundancy;      /* 1 = Enable experimental redundancy */
    const char *scheduler;      /* "minrtt", "pmp", "psp", "rmp", "spmp" */

    quic_recv_cb recv_cb;       /* Application receive callback */
    void *user_data;            /* User pointer passed to recv_cb */
} quic_client_config_t;

typedef struct {
    uint16_t listen_port;       /* Default: 8000 */
    const char *cert_file;      /* Default: "server.crt" */
    const char *key_file;       /* Default: "server.key" */

    int enable_datagram;        /* 1 = Datagram mode, 0 = Stream mode */
    int enable_redundancy;      /* 1 = Enable experimental redundancy */
    const char *scheduler;      /* "minrtt", "pmp", "psp", "rmp", "spmp" */

    quic_recv_cb recv_cb;       /* Application receive callback */
    void *user_data;            /* User pointer passed to recv_cb */
} quic_server_config_t;

/**
 * Start QUIC Client in a background event loop thread.
 */
quic_endpoint_t *quic_client_start(const quic_client_config_t *config);

/**
 * Start QUIC Server in a background event loop thread.
 */
quic_endpoint_t *quic_server_start(const quic_server_config_t *config);

/**
 * Send data over QUIC (Datagram or Stream depending on mode).
 */
int quic_send(quic_endpoint_t *ep, const uint8_t *data, size_t len);

/**
 * Stop endpoint event loop and free resources.
 */
void quic_endpoint_stop(quic_endpoint_t *ep);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_API_H */