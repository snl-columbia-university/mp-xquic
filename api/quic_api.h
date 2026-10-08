#ifndef QUIC_API_H
#define QUIC_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNECTION_TIMEOUT 10000

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

    const char *congestion;      /* "cubic", "bbrv1", ""bbrv2", "reno"*/

    quic_recv_cb recv_cb;       /* Application receive callback */
    const char *qlog;                 /* Qlog file path */
    void *user_data;            /* User pointer passed to recv_cb */
    int rtp_encap;              /* 1 = wrap every UDP datagram in a 12 B RTP header
                                   (QUIC-in-RTP experiment); both ends must match */
    int rtp_pdu_set;            /* with rtp_encap: add a dummy 3GPP PDU Set marking RTP
                                   header extension (TS 26.522): 0 = off, 1 = E/D/PSI/
                                   PSSN/PSN, 2 = also PSSize and NPDS */
    int rtp_tag;                /* with rtp_encap: RTP header extension element ID 2 carries
                                   the first 4 B of the app payload + a packet counter;
                                   the receiver checks it against the decrypted datagram and
                                   writes rtp_check_<client|server>.csv */
} quic_client_config_t;

typedef struct {
    uint16_t listen_port;       /* Default: 8000 */
    const char *cert_file;      /* Default: "server.crt" */
    const char *key_file;       /* Default: "server.key" */

    const char *local_ips[4];
    size_t num_local_addrs;

    int enable_datagram;        /* 1 = Datagram mode, 0 = Stream mode */
    int enable_redundancy;      /* 1 = Enable experimental redundancy */
    const char *scheduler;      /* "minrtt", "pmp", "psp", "rmp", "spmp" */

    const char *congestion;      /* "cubic", "bbrv1", ""bbrv2", "reno"*/

    quic_recv_cb recv_cb;       /* Application receive callback */
    const char *qlog;                 /* Qlog file path */
    void *user_data;            /* User pointer passed to recv_cb */
    int rtp_encap;              /* 1 = wrap every UDP datagram in a 12 B RTP header
                                   (QUIC-in-RTP experiment); both ends must match */
    int rtp_pdu_set;            /* with rtp_encap: add a dummy 3GPP PDU Set marking RTP
                                   header extension (TS 26.522): 0 = off, 1 = E/D/PSI/
                                   PSSN/PSN, 2 = also PSSize and NPDS */
    int rtp_tag;                /* with rtp_encap: RTP header extension element ID 2 carries
                                   the first 4 B of the app payload + a packet counter;
                                   the receiver checks it against the decrypted datagram and
                                   writes rtp_check_<client|server>.csv */
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

/**
 * Run any pending network and timer work for this endpoint and return.
 */
void quic_endpoint_step(quic_endpoint_t *ep);

/**
 * 1 once the handshake has completed, 0 before that and after a close.
 */
int is_connected(quic_endpoint_t *ep);

#ifdef __cplusplus
}
#endif

#endif /* QUIC_API_H */