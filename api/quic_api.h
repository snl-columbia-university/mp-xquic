#ifndef QUIC_API_H
#define QUIC_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <xquic/xquic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNECTION_TIMEOUT 10000

#define MAX_PATHS 16
#define DGRAM_HEADER_WIN 16384

struct event_base;
struct event;

typedef struct quic_endpoint quic_endpoint_t;

/* Callback function to deliver received payload data to the application */
typedef void (*quic_recv_cb)(const uint8_t *data, size_t len, void *user_data);

typedef enum {
    QUIC_MODE_CLIENT,
    QUIC_MODE_SERVER
} quic_mode_t;

struct quic_endpoint {
    quic_mode_t mode;
    xqc_engine_t *engine;
    FILE *qlog_file;
    struct event_base *eb;
    struct event *timer_ev;
    struct event *quic_ev;

    int quic_fd;

    xqc_connection_t *conn;
    xqc_stream_t *stream;
    xqc_cid_t cid;

    struct sockaddr_in peer_addrs[MAX_PATHS];
    int num_peer_addrs;
    struct sockaddr_in local_addrs[MAX_PATHS];
    int num_local_addrs;
    int num_paths;

    uint16_t msg_id;
    uint64_t dgram_header_id;
    uint16_t max_dgram_header_id;
    uint64_t dgram_header_win[DGRAM_HEADER_WIN / 64];

    quic_recv_cb         app_recv_cb;
    void                *app_user_data;

    int connected;
    int path_idx;

    xqc_conn_settings_t ep_conn_settings;
    xqc_conn_ssl_config_t ep_ssl_config;

    int datagram_mode;

    int rtp_encap;
    int rtp_pdu_set;
    uint16_t rtp_seq[MAX_PATHS];
    uint16_t rtp_pssn[MAX_PATHS];
    uint64_t rtp_tx, rtp_rx, rtp_rx_plain, rtp_rx_pduset;

    int rtp_tag;
    int32_t tx_tag; int tx_tag_valid;
    uint32_t tx_pkt_ctr;
    int rx_has_elem, rx_tag_valid;
    uint32_t rx_ssrc, rx_pkt_ctr; uint16_t rx_seq; int32_t rx_tag;
    FILE *rtp_check;
    uint64_t chk_match, chk_mismatch, chk_untagged, chk_noelem;
};

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

    int sendmmsg_on;            /* 1 = Enable batch sending, 0 = disable batch sending*/
    
    quic_recv_cb recv_cb;       /* Application receive callback */
    const char *qlog;                 /* Qlog file path */
    void *user_data;            /* User pointer passed to recv_cb */
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

    int sendmmsg_on;            /* 1 = Enable batch sending, 0 = disable batch sending*/

    quic_recv_cb recv_cb;       /* Application receive callback */
    const char *qlog;                 /* Qlog file path */
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
 * Send batch data over QUIC (Datagram or Stream depending on mode).
 */
int quic_send_msg(quic_endpoint_t *ep, struct iovec *iov, size_t iov_size);

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