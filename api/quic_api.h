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


#ifndef ACTIVE_LOG_LEVEL
#define ACTIVE_LOG_LEVEL 4 /* 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=OFF */
#endif

#define MAX_DGRAM_SIZE 2000
#define DGRAM_HEADER_SIZE 2

typedef enum {
    QUIC_LOG_DEBUG,
    QUIC_LOG_INFO,
    QUIC_LOG_WARN,
    QUIC_LOG_ERROR
} quic_log_level_t;

void quic_log(quic_log_level_t level, const char *fmt, ...);

#define LOG_DEBUG(...) do { if (ACTIVE_LOG_LEVEL <= 0) quic_log(QUIC_LOG_DEBUG, __VA_ARGS__); } while(0)
#define LOG_INFO(...)  do { if (ACTIVE_LOG_LEVEL <= 1) quic_log(QUIC_LOG_INFO,  __VA_ARGS__); } while(0)
#define LOG_WARN(...)  do { if (ACTIVE_LOG_LEVEL <= 2) quic_log(QUIC_LOG_WARN,  __VA_ARGS__); } while(0)
#define LOG_ERROR(...) do { if (ACTIVE_LOG_LEVEL <= 3) quic_log(QUIC_LOG_ERROR, __VA_ARGS__); } while(0)

int is_new_datagram_win(uint16_t id, uint16_t *max_dgram_header_id, uint64_t *seen);

static inline uint64_t pack_dgram_id(uint16_t msg_id, uint8_t seq, uint8_t max_seq, uint16_t dgram_header_id) {
    return ((uint64_t)msg_id     << 48) |
           ((uint64_t)seq        << 40) |
           ((uint64_t)max_seq    << 32) |
           ((uint64_t)dgram_header_id << 16) |
           0x0000;
}

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

    int sendmmsg_on;            /* 1 = Enable batch sending, 0 = disable batch sending*/

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