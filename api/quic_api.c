#define _GNU_SOURCE

#ifndef ENABLE_DEBUG_LOGS
#define ENABLE_DEBUG_LOGS 0
#endif

#include "quic_api.h"
#define DGRAM_WIN 16384   /* datagram ids remembered by the duplicate filter (multiple of 64) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <endian.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>

// XR_KTS: log kernel-receive -> app-read delay for every packet (socket queueing).
static FILE *g_kts = NULL;
static long g_kts_n = 0;
static int kts_on(void) { static int v = -1; if (v < 0) v = getenv("XR_KTS") != NULL; return v; }
static void kts_log(const char *role, const struct timespec *kts, ssize_t len) {
    if (!g_kts) {
        char name[64]; snprintf(name, sizeof(name), "kts_%s.csv", role);
        g_kts = fopen(name, "w");
        if (!g_kts) return;
        setvbuf(g_kts, NULL, _IOFBF, 1 << 20);
        fprintf(g_kts, "mono_ms,wait_us,len\n");
    }
    struct timespec rt, mono;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    double wait_us = (rt.tv_sec - kts->tv_sec) * 1e6 + (rt.tv_nsec - kts->tv_nsec) / 1e3;
    fprintf(g_kts, "%.3f,%.1f,%zd\n", mono.tv_sec * 1e3 + mono.tv_nsec / 1e6, wait_us, len);
    if (++g_kts_n % 4096 == 0) fflush(g_kts);
}
#include <event2/event.h>
#include <xquic/xquic.h>
#include <sys/socket.h>

#define MAX_PATHS 16

#ifndef XQC_SOCKET_ERROR
#define XQC_SOCKET_ERROR -1
#endif
#ifndef XQC_SOCKET_EAGAIN
#define XQC_SOCKET_EAGAIN -2
#endif

typedef union {
    struct cmsghdr cm;
    char buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
} cmsg_pktinfo_t;

typedef enum {
    QUIC_LOG_DEBUG,
    QUIC_LOG_INFO,
    QUIC_LOG_WARN,
    QUIC_LOG_ERROR
} quic_log_level_t;

/* XR_MIN_LOG=1: bare-minimum logging -- drop DEBUG/INFO lines and the qlog */
static int quic_min_log(void) {
    static int v = -1;
    if (v < 0) v = getenv("XR_MIN_LOG") != NULL;
    return v;
}

static void quic_log(quic_log_level_t level, const char *fmt, ...) {
    if (quic_min_log() && level < QUIC_LOG_WARN) return;
    const char *level_strs[] = { "DEBUG", "INFO", "WARN", "ERROR" };
    struct timeval tv;
    gettimeofday(&tv, NULL);
    
    struct tm tm_info;
    localtime_r(&tv.tv_sec, &tm_info);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    FILE *stream = (level == QUIC_LOG_ERROR) ? stderr : stdout;

    fprintf(stream, "[%s.%03d] [%s] ", time_buf, (int)(tv.tv_usec / 1000), level_strs[level]);

    va_list args;
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
}

#define LOG_DEBUG(...) quic_log(QUIC_LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  quic_log(QUIC_LOG_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  quic_log(QUIC_LOG_WARN,  __VA_ARGS__)
#define LOG_ERROR(...) quic_log(QUIC_LOG_ERROR, __VA_ARGS__)

/* --- DATA STRUCTURES & DEFINITIONS --- */

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

    uint64_t quic_dgram_id;
    uint64_t client_dgram_id;
    uint64_t server_dgram_id;
    uint64_t max_dgram_id;
    uint64_t dgram_id_mask;          // unused since the windowed filter, kept for layout
    uint64_t dgram_seen[DGRAM_WIN / 64]; // ring bitmap of ids within DGRAM_WIN of max_dgram_id

    quic_recv_cb         app_recv_cb;
    void                *app_user_data;

    int connected;
    int path_idx;

    xqc_conn_settings_t ep_conn_settings;
    xqc_conn_ssl_config_t ep_ssl_config;

    int datagram_mode;

    /* QUIC-in-RTP: per-path RTP sequence numbers and counters */
    int rtp_encap;
    int rtp_pdu_set;                       /* 0 off, 1 basic, 2 + PSSize/NPDS */
    uint16_t rtp_seq[MAX_PATHS];
    uint16_t rtp_pssn[MAX_PATHS];          /* 10-bit PDU Set sequence number */
    uint64_t rtp_tx, rtp_rx, rtp_rx_plain, rtp_rx_pduset;

    /* end-to-end tag check (rtp_tag) */
    int rtp_tag;
    int32_t tx_tag; int tx_tag_valid;      /* set while quic_send() runs */
    uint32_t tx_pkt_ctr;
    int rx_has_elem, rx_tag_valid;         /* element of the UDP packet being processed */
    uint32_t rx_ssrc, rx_pkt_ctr; uint16_t rx_seq; int32_t rx_tag;
    FILE *rtp_check;
    uint64_t chk_match, chk_mismatch, chk_untagged, chk_noelem;
};

void quic_endpoint_step(quic_endpoint_t *ep) {
    if (ep && ep->eb) {
        event_base_loop(ep->eb, EVLOOP_NONBLOCK);
    }
}

int is_connected(quic_endpoint_t *ep) {
    return ep ? ep->connected : 0;
}

static xqc_usec_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static xqc_scheduler_callback_t get_scheduler_cb(const char *name) {
    if (!name) return xqc_minrtt_scheduler_cb;
    if (strcmp(name, "pmp") == 0) return xqc_proactive_multipath_scheduler_cb;
    if (strcmp(name, "psp") == 0) return xqc_proactive_singlepath_scheduler_cb;
    if (strcmp(name, "rmp") == 0) return xqc_reactive_multipath_scheduler_cb;
    if (strcmp(name, "spmp") == 0) return xqc_smart_proactive_multipath_scheduler_cb;
    if (strcmp(name, "bi") == 0) return xqc_biphony_scheduler_cb;
    return xqc_minrtt_scheduler_cb;
}

static xqc_cong_ctrl_callback_t get_cong_ctrl_cb(const char *name) {
    if (!name) return xqc_cubic_cb;
    if (strcmp(name, "cubic") == 0) return xqc_cubic_cb;
    if (strcmp(name, "bbrv1") == 0) return xqc_bbr_cb;
    if (strcmp(name, "bbrv2") == 0) return xqc_bbr2_cb;
    if (strcmp(name, "reno") == 0) return xqc_reno_cb;
    return xqc_cubic_cb;
}

// Duplicate filter for redundant (multipath) datagram copies: remembers the last DGRAM_WIN
// ids. It used to be a single 64-bit mask -- ~20 ms at ~3200 datagrams/s -- so any cross-path
// reordering larger than that dropped *first* copies as duplicates (minrtt path switches,
// start-up while paths come up). Ids older than the window are still treated as duplicates.
static int is_new_datagram_win(uint64_t id, uint64_t *max_dgram_id, uint64_t *seen) {
#define SEEN_BIT(i) (seen[((i) % DGRAM_WIN) / 64] & (1ULL << ((i) % 64)))
#define SEEN_SET(i) (seen[((i) % DGRAM_WIN) / 64] |= (1ULL << ((i) % 64)))
#define SEEN_CLR(i) (seen[((i) % DGRAM_WIN) / 64] &= ~(1ULL << ((i) % 64)))
    if (id > *max_dgram_id) {
        uint64_t diff = id - *max_dgram_id;
        if (diff >= DGRAM_WIN) {
            memset(seen, 0, DGRAM_WIN / 8);
        } else {
            for (uint64_t i = *max_dgram_id + 1; i < id; i++) SEEN_CLR(i);
        }
        SEEN_SET(id);
        *max_dgram_id = id;
        return 1;
    }
    if (*max_dgram_id - id >= DGRAM_WIN) return 0;
    if (SEEN_BIT(id)) return 0;
    SEEN_SET(id);
    return 1;
#undef SEEN_BIT
#undef SEEN_SET
#undef SEEN_CLR
}

static int is_new_datagram(uint64_t id, uint64_t *max_dgram_id, uint64_t *dgram_id_mask) {
    if (id > *max_dgram_id) {
        uint64_t diff = id - *max_dgram_id;
        if (diff >= 64) {
            *dgram_id_mask = 1;
        } else {
            *dgram_id_mask = (*dgram_id_mask << diff) | 1;
        }
        *max_dgram_id = id;
        return 1;
    } else {
        uint64_t diff = *max_dgram_id - id;
        if (diff >= 64) {
            return 0;
        }
        if (*dgram_id_mask & (1ULL << diff)) {
            return 0;
        } else {
            *dgram_id_mask |= (1ULL << diff);
            return 1;
        }
    }
}

// QUIC logging callback
static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) { 
    if (quic_min_log()) { LOG_WARN("%.*s", (int)size, (char*)buf); return; }   /* engine logs WARN+ only */
    LOG_DEBUG("%.*s", (int)size, (char*)buf); 
}
static void qlog_event_write(qlog_event_importance_t imp, const void *buf, 
                             size_t size, void *user_data) 
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (ep && ep->qlog_file && buf && size > 0) {
        fwrite(buf, 1, size, ep->qlog_file);
        fputc('\n', ep->qlog_file);
        fflush(ep->qlog_file);
    }
}

// QUIC-in-RTP. Every UDP datagram gets an RFC 3550 header in front:
// V=2, no padding/CSRC, M=0, PT=96 (dynamic), a sequence number per path,
// a 90 kHz timestamp, SSRC per path. The receiver tells RTP (first byte
// 128-191) from bare QUIC (64-127 / 192-255, RFC 9443) and strips the header.
#define RTP_HDR_LEN 12
#define RTP_PT 96
#define RTP_SSRC_BASE 0x51554900u   /* "QUI" + path index */
#define RTP_MAX_HDR 64

/* Write the RTP header (+ extension) for one QUIC packet into out; returns its length. */
static size_t rtp_header(quic_endpoint_t *ep, unsigned path_idx, size_t size, unsigned char *out) {
    /* PDU Set marking extension (TS 26.522 cl. 4.2.2, RFC 8285 one-byte form):
       0xBEDE | length(words) | ID=1,len | E R R D PSI(4) | PSSN(10) PSN(6)
       [| PSSize(24) | NPDS(16)] | zero padding to a 32-bit boundary.
       Dummy marking: every RTP packet is its own PDU Set (E=1, PSN=0, NPDS=1),
       PSI=0 (importance unknown), D=0, PSSN counts packets per path. */
    size_t ext_data = ep->rtp_pdu_set == 0 ? 0 : (ep->rtp_pdu_set == 1 ? 3 : 8);
    size_t tag_data = ep->rtp_tag ? 9 : 0;           /* element ID 2 */
    size_t ext_bytes = (ext_data ? 1 + ext_data : 0) + (tag_data ? 1 + tag_data : 0);
    size_t ext_words = (ext_bytes + 3) / 4;
    size_t hdr = RTP_HDR_LEN + (ext_bytes ? 4 + 4 * ext_words : 0);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint32_t rtp_ts = (uint32_t)((uint64_t)ts.tv_sec * 90000u + (uint64_t)ts.tv_nsec / 11111u);
    uint16_t seq = ep->rtp_seq[path_idx % MAX_PATHS]++;
    uint32_t ssrc = RTP_SSRC_BASE | (path_idx & 0xff);

    out[0] = ext_bytes ? 0x90 : 0x80;    /* V=2, X=1 when the extension is present */
    out[1] = RTP_PT;                     /* M=0, PT */
    out[2] = seq >> 8;        out[3] = seq & 0xff;
    out[4] = rtp_ts >> 24;    out[5] = (rtp_ts >> 16) & 0xff;
    out[6] = (rtp_ts >> 8) & 0xff;       out[7] = rtp_ts & 0xff;
    out[8] = ssrc >> 24;      out[9] = (ssrc >> 16) & 0xff;
    out[10] = (ssrc >> 8) & 0xff;        out[11] = ssrc & 0xff;
    unsigned char *e = out + RTP_HDR_LEN + 4;           /* next free element byte */
    if (ext_bytes) {
        unsigned char *x = out + RTP_HDR_LEN;
        memset(x, 0, 4 + 4 * ext_words);
        x[0] = 0xBE; x[1] = 0xDE;
        x[2] = ext_words >> 8; x[3] = ext_words & 0xff;
    }
    if (ext_data) {
        e[0] = (1 << 4) | (unsigned char)(ext_data - 1);        /* ID=1, len-1 */
        uint16_t pssn = ep->rtp_pssn[path_idx % MAX_PATHS]++ & 0x3FF;
        uint8_t psi = 0, psn = 0;
        e[1] = (1 << 7) | (0 << 4) | (psi & 0x0F);              /* E=1, R=00, D=0, PSI */
        e[2] = pssn >> 2;
        e[3] = (unsigned char)(((pssn & 0x3) << 6) | (psn & 0x3F));
        if (ext_data == 8) {
            uint32_t pssize = (uint32_t)(hdr + size + 28);      /* incl. RTP/UDP/IPv4 */
            e[4] = (pssize >> 16) & 0xff; e[5] = (pssize >> 8) & 0xff; e[6] = pssize & 0xff;
            e[7] = 0; e[8] = 1;                                  /* NPDS = 1 */
        }
        e += 1 + ext_data;
    }
    if (tag_data) {                                      /* ID=2: ctr | flags | tag */
        uint32_t ctr = ++ep->tx_pkt_ctr;
        uint32_t tag = (uint32_t)ep->tx_tag;
        e[0] = (2 << 4) | (unsigned char)(tag_data - 1);
        e[1] = ctr >> 24; e[2] = (ctr >> 16) & 0xff; e[3] = (ctr >> 8) & 0xff; e[4] = ctr & 0xff;
        e[5] = ep->tx_tag_valid ? 1 : 0;
        e[6] = tag >> 24; e[7] = (tag >> 16) & 0xff; e[8] = (tag >> 8) & 0xff; e[9] = tag & 0xff;
    }
    return hdr;
}

/* Strip the RTP header of a received UDP packet; returns the QUIC payload length
   (*pkt points at it) or -1 for a malformed packet. Bare QUIC passes through. */
static ssize_t rtp_strip(quic_endpoint_t *ep, unsigned char *buf, ssize_t n, unsigned char **pkt) {
    *pkt = buf;
    if (n < RTP_HDR_LEN || (buf[0] & 0xC0) != 0x80) {   /* not RTP v2 */
        ep->rtp_rx_plain++;
        return n;
    }
    ssize_t h = RTP_HDR_LEN + 4 * (buf[0] & 0x0F);      /* + CSRCs */
    ep->rx_has_elem = 0;
    ep->rx_ssrc = ((uint32_t)buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
    ep->rx_seq = (buf[2] << 8) | buf[3];
    if ((buf[0] & 0x10) && n >= h + 4) {                /* X: extension block */
        ssize_t end = h + 4 + 4 * ((buf[h + 2] << 8) | buf[h + 3]);
        if (buf[h] == 0xBE && buf[h + 1] == 0xDE && end <= n) {
            ep->rtp_rx_pduset++;
            for (ssize_t i = h + 4; i < end; ) {         /* RFC 8285 one-byte elements */
                int id = buf[i] >> 4, len = (buf[i] & 0x0F) + 1;
                if (id == 0) { i++; continue; }          /* padding */
                if (id == 15 || i + 1 + len > end) break;
                if (id == 2 && len == 9) {
                    const unsigned char *d = buf + i + 1;
                    ep->rx_has_elem = 1;
                    ep->rx_pkt_ctr = ((uint32_t)d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
                    ep->rx_tag_valid = d[4] & 1;
                    ep->rx_tag = (int32_t)(((uint32_t)d[5] << 24) | (d[6] << 16) | (d[7] << 8) | d[8]);
                }
                i += 1 + len;
            }
        }
        h = end;
    }
    if (h > n) return -1;
    *pkt = buf + h;
    ep->rtp_rx++;
    return n - h;
}

// QUIC socket callbacks
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) 
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0) return XQC_SOCKET_ERROR;

    ssize_t res;
    if (ep->rtp_encap) {
        unsigned char hbuf[RTP_MAX_HDR];
        size_t hdr = rtp_header(ep, 0, size, hbuf);
        struct iovec iov[2] = { { hbuf, hdr }, { (void *)buf, size } };
        struct msghdr msg = { .msg_name = (void *)peer_addr, .msg_namelen = peer_addrlen,
                              .msg_iov = iov, .msg_iovlen = 2 };
        res = sendmsg(ep->quic_fd, &msg, 0);
        if (res >= 0) { ep->rtp_tx++; res = res >= (ssize_t)hdr ? res - (ssize_t)hdr : 0; }
    } else {
        res = sendto(ep->quic_fd, buf, size, 0, peer_addr, peer_addrlen);
    }
    if (res < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    return res;   /* xquic expects its own byte count */
}

static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                               void *user_data) 
{ 
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0) return XQC_SOCKET_ERROR;

    struct sockaddr_in *peer_addr = (ep->mode == QUIC_MODE_CLIENT) 
        ? &ep->peer_addrs[(path_id + ep->path_idx) % ep->num_peer_addrs] 
        : (struct sockaddr_in *)_peer_addr;

    struct sockaddr_in *local_addr = (ep->mode == QUIC_MODE_CLIENT) 
        ? &ep->local_addrs[(path_id / ep->num_peer_addrs) % ep->num_local_addrs] 
        : &ep->local_addrs[path_id % ep->num_local_addrs];

    const socklen_t namelen = (ep->mode == QUIC_MODE_CLIENT) ? sizeof(*peer_addr) : _peer_addrlen;

    unsigned char hbuf[RTP_MAX_HDR];
    size_t hdr = ep->rtp_encap ? rtp_header(ep, (unsigned)path_id, size, hbuf) : 0;
    struct iovec iov[2] = { { hbuf, hdr }, { (void *)buf, size } };
    cmsg_pktinfo_t cbuf = {0};

    struct msghdr msg = {
        .msg_name       = (void *)peer_addr,
        .msg_namelen    = namelen,
        .msg_iov        = hdr ? iov : iov + 1,
        .msg_iovlen     = hdr ? 2 : 1,
        .msg_control    = cbuf.buf,
        .msg_controllen = sizeof(cbuf.buf)
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type  = IP_PKTINFO;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
    ((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = local_addr->sin_addr;
#if ENABLE_DEBUG_LOGS
    LOG_DEBUG("[%s-quic] write_socket_ex: calling write_socket for path_id %lu\n",
            ep->mode == QUIC_MODE_SERVER ? "server" : "client",
            (unsigned long)path_id);
#endif
    ssize_t res = sendmsg(ep->quic_fd, &msg, 0);
    if (res < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    if (hdr) { ep->rtp_tx++; res = res >= (ssize_t)hdr ? res - (ssize_t)hdr : 0; }
    return res;   /* xquic expects its own byte count */
}

// QUIC mmsg callbacks
static ssize_t write_mmsg(const struct iovec *msg_iov, unsigned int vlen,
                          const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                          void *user_data) 
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0 || vlen == 0 || !msg_iov) {
        return XQC_SOCKET_ERROR;
    }

    struct mmsghdr msgs[vlen];
    struct iovec iovs[vlen][2];
    unsigned char hbufs[ep->rtp_encap ? vlen : 1][RTP_MAX_HDR];
    memset(msgs, 0, sizeof(msgs));

    for (unsigned int i = 0; i < vlen; i++) {
        msgs[i].msg_hdr.msg_name    = (void *)peer_addr;
        msgs[i].msg_hdr.msg_namelen = peer_addrlen;
        msgs[i].msg_hdr.msg_iov     = (struct iovec *)&msg_iov[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        if (ep->rtp_encap) {         /* RTP header in front of each QUIC packet */
            iovs[i][0].iov_base = hbufs[i];
            iovs[i][0].iov_len  = rtp_header(ep, 0, msg_iov[i].iov_len, hbufs[i]);
            iovs[i][1] = msg_iov[i];
            msgs[i].msg_hdr.msg_iov    = iovs[i];
            msgs[i].msg_hdr.msg_iovlen = 2;
        }
    }

    int sent = sendmmsg(ep->quic_fd, msgs, vlen, 0);
    if (sent < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    if (ep->rtp_encap) ep->rtp_tx += sent;
    return sent;
}

static ssize_t write_mmsg_ex(uint64_t path_id,
                             const struct iovec *msg_iov, unsigned int vlen,
                             const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                             void *user_data) 
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0 || vlen == 0 || !msg_iov) {
        return XQC_SOCKET_ERROR;
    }

    struct sockaddr_in *peer_addr = (ep->mode == QUIC_MODE_CLIENT) 
        ? &ep->peer_addrs[(path_id + ep->path_idx) % ep->num_peer_addrs] 
        : (struct sockaddr_in *)_peer_addr;

    struct sockaddr_in *local_addr = (ep->mode == QUIC_MODE_CLIENT) 
        ? &ep->local_addrs[(path_id / ep->num_peer_addrs) % ep->num_local_addrs] 
        : &ep->local_addrs[path_id % ep->num_local_addrs];

    const socklen_t namelen = (ep->mode == QUIC_MODE_CLIENT) ? sizeof(*peer_addr) : _peer_addrlen;

    struct mmsghdr msgs[vlen];
    cmsg_pktinfo_t cbufs[vlen];
    struct iovec iovs[vlen][2];
    unsigned char hbufs[ep->rtp_encap ? vlen : 1][RTP_MAX_HDR];

    memset(msgs, 0, sizeof(msgs));
    memset(cbufs, 0, sizeof(cbufs));

    for (unsigned int i = 0; i < vlen; i++) {
        struct msghdr *hdr = &msgs[i].msg_hdr;

        hdr->msg_name       = (void *)peer_addr;
        hdr->msg_namelen    = namelen;
        hdr->msg_iov        = (struct iovec *)&msg_iov[i];
        hdr->msg_iovlen     = 1;
        if (ep->rtp_encap) {         /* RTP header in front of each QUIC packet */
            iovs[i][0].iov_base = hbufs[i];
            iovs[i][0].iov_len  = rtp_header(ep, (unsigned)path_id, msg_iov[i].iov_len, hbufs[i]);
            iovs[i][1] = msg_iov[i];
            hdr->msg_iov    = iovs[i];
            hdr->msg_iovlen = 2;
        }
        hdr->msg_control    = cbufs[i].buf;
        hdr->msg_controllen = sizeof(cbufs[i].buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(hdr);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type  = IP_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
        ((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = local_addr->sin_addr;
    }
#if ENABLE_DEBUG_LOGS
    LOG_DEBUG("[%s-quic] write_mmsg_ex: calling sendmmsg for path_id %lu (batch of %u datagrams)\n",
             ep->mode == QUIC_MODE_SERVER ? "server" : "client",
             (unsigned long)path_id, vlen);
#endif
    int sent = sendmmsg(ep->quic_fd, msgs, vlen, 0);
    if (sent < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    if (ep->rtp_encap) ep->rtp_tx += sent;
    return sent;
}

// QUIC certificate callback
static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *conn_user_data) { 
    return 1; 
}

static void save_token_cb(const unsigned char *token, unsigned int token_len, void *user_data) { return; }
static void save_session_cb(const char *data, size_t data_len, void *user_data) { return; }

// QUIC connection id callback
static ssize_t cid_generate_cb(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
                               size_t cid_buflen, void *engine_user_data) {
    for (size_t i = 0; i < 8 && i < cid_buflen; i++) {
        cid_buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 8;
}

// QUIC stream callbacks
static int stream_create_notify(xqc_stream_t *strm, void *user_data) {
    quic_endpoint_t *ep = (quic_endpoint_t *)xqc_get_conn_alp_user_data_by_stream(strm);
    if (ep) {
        xqc_stream_set_user_data(strm, ep);
        ep->stream = strm;
    }
    LOG_INFO("[%s-quic] stream %lu created\n", ep && ep->mode == QUIC_MODE_SERVER ? "server" : "client", (unsigned long)xqc_stream_id(strm));
    return 0;
}
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { 
    LOG_INFO("[quic] stream %lu closed\n", (unsigned long)xqc_stream_id(strm));
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (ep && ep->stream == strm) {
        ep->stream = NULL;
    }
    return 0; 
}
static int stream_read_notify(xqc_stream_t *strm, void *user_data) {
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return -1;

    unsigned char buf[2000];
    uint8_t fin = 0;
    while (1) {
        ssize_t n = xqc_stream_recv(strm, buf, sizeof(buf), &fin);
#if ENABLE_DEBUG_LOGS
        LOG_DEBUG("[quic] stream_read_notify called for stream %lu, received %zd bytes\n", (unsigned long)xqc_stream_id(strm), n);
#endif
        if (n > 0) {
            if (ep->app_recv_cb) {
                ep->app_recv_cb(buf, (size_t)n, ep->app_user_data);
            }
        } else if (fin) {
            LOG_INFO("[quic] stream %lu finished\n", (unsigned long)xqc_stream_id(strm));
            break;
        } else if (n == -XQC_EAGAIN) {
            break;
        } else {
            LOG_ERROR("[quic] xqc_stream_read error: %zd\n", n);
            break;
        }
    }
    return 0;
}
static int stream_write_notify(xqc_stream_t *strm, void *user_data) { 
#if ENABLE_DEBUG_LOGS
    LOG_DEBUG("[quic] stream %lu write notify\n", (unsigned long)xqc_stream_id(strm)); 
#endif
    return 0; 
}

// QUIC connection callbacks
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    LOG_INFO("[quic] connection created\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return -1;
    ep->conn = conn;
    ep->max_dgram_id = 0;
    memset(ep->dgram_seen, 0, sizeof(ep->dgram_seen));
    ep->dgram_id_mask = 0;
    ep->server_dgram_id = 0;
    ep->quic_dgram_id = 1;
    xqc_datagram_set_user_data(conn, ep);
    xqc_conn_set_alp_user_data(conn, ep);
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return 0;

    if (ep->mode == QUIC_MODE_CLIENT && !ep->connected
        && ep->path_idx + 1 < ep->num_peer_addrs)
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ep->peer_addrs[ep->path_idx].sin_addr, ip, sizeof(ip));
        LOG_INFO("[quic] connection failed to establish with %s:%u, trying next peer addr\n", ip, ntohs(ep->peer_addrs[ep->path_idx].sin_port));
        ep->path_idx++;
        const xqc_cid_t *cidp = xqc_connect(ep->engine, &ep->ep_conn_settings, NULL, 0, "localhost", 0,
                                            &ep->ep_ssl_config,
                                            (struct sockaddr*)&ep->peer_addrs[ep->path_idx], sizeof(ep->peer_addrs[ep->path_idx]),
                                            "raw", ep);
        if (cidp) {
            memcpy(&ep->cid, cidp, sizeof(ep->cid));
            return 0;
        }
        LOG_ERROR("[client-quic] retry connect failed\n");
    }

    LOG_INFO("[quic] connection closed\n");
    ep->conn = NULL;
    ep->stream = NULL;
    ep->connected = 0;
    return 0; 
}
static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    LOG_INFO("[quic] handshake finished\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return;
    ep->conn = conn;
    ep->connected = 1;
    if (ep->mode == QUIC_MODE_CLIENT && !ep->quic_dgram_id) {
        ep->stream = xqc_stream_create(ep->engine, &ep->cid, NULL, user_data);
        if (ep->stream) {
            LOG_INFO("[client-quic] stream %lu created\n", (unsigned long)xqc_stream_id(ep->stream));
        } else {
            LOG_ERROR("[client-quic] stream creation failed\n");
        }
    }
}

// QUIC server accept callback
static int server_accept(xqc_engine_t *eng, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data) {
    LOG_INFO("[server-quic] new connection accepted\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return -1;
    ep->conn = conn;
    ep->max_dgram_id = 0;
    memset(ep->dgram_seen, 0, sizeof(ep->dgram_seen));
    xqc_conn_set_alp_user_data(conn, ep);
    xqc_datagram_set_user_data(conn, ep);
    return 0;
}

// QUIC multipath callbacks
void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->mode != QUIC_MODE_CLIENT) return;
    LOG_INFO("[client-multipath] ready to create new path\n");
    while(ep->num_paths < ep->num_local_addrs * ep->num_peer_addrs && ep->num_paths < MAX_PATHS) {
        uint64_t new_path_id = 0;
        int ret = xqc_conn_create_path(ep->engine, cid, &new_path_id, 0);
        if (ret == XQC_OK) {
            LOG_INFO("[client-multipath] created path %lu\n", new_path_id);
            ep->num_paths++;
        } else {
            LOG_ERROR("[client-multipath] failed to create path for address %d: %d\n", ep->num_paths, ret);
            break;
        }
    }
}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data) { 
    LOG_INFO("[multipath] sub-path %lu established successfully.\n", path_id);
    return 0; 
}

// QUIC datagram callbacks
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || data_len <= 8) return;

    uint64_t net_val;
    memcpy(&net_val, data, sizeof(uint64_t));
    uint64_t remote_dgram_id = be64toh(net_val);

    int is_new = is_new_datagram_win(remote_dgram_id, &ep->max_dgram_id, ep->dgram_seen);

    if (ep->rtp_tag && ep->rtp_check) {
        int32_t app_tag = 0;
        if (data_len >= 12) memcpy(&app_tag, (const uint8_t *)data + 8, sizeof(app_tag));
        const char *res;
        if (!ep->rx_has_elem)            { res = "no_elem";  ep->chk_noelem++; }
        else if (!ep->rx_tag_valid)      { res = "untagged"; ep->chk_untagged++; }
        else if (ep->rx_tag == app_tag)  { res = "match";    ep->chk_match++; }
        else                             { res = "MISMATCH"; ep->chk_mismatch++; }
        fprintf(ep->rtp_check, "%08x,%u,%u,%d,%d,%lu,%d,%s,%d\n", ep->rx_ssrc, ep->rx_seq,
                ep->rx_pkt_ctr, ep->rx_tag_valid ? ep->rx_tag : 0, ep->rx_tag_valid,
                (unsigned long)remote_dgram_id, app_tag, res, !is_new);
    }

    if (!is_new) {
#if ENABLE_DEBUG_LOGS
        LOG_DEBUG("[quic] duplicate datagram %ld (<=%ld) recv\n", remote_dgram_id, ep->max_dgram_id);
#endif
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + 8;
    size_t payload_len = data_len - 8;

    if (ep->app_recv_cb) {
        ep->app_recv_cb(payload, payload_len, ep->app_user_data);
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) { 
#if ENABLE_DEBUG_LOGS
    LOG_DEBUG("[quic] datagram sent to peer\n");
#endif
}
static void datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { 
#if ENABLE_DEBUG_LOGS
    LOG_DEBUG("[quic] datagram %lu acked\n", dgram_id); 
#endif
}
static xqc_int_t datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { 
    LOG_WARN("[quic] datagram %lu lost\n", dgram_id); 
    return 0;
}

static void set_event_timer(xqc_usec_t wake_after, void *user_data) {
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return;
    struct timeval tv = { .tv_sec = wake_after / 1000000, .tv_usec = wake_after % 1000000 };
    event_add(ep->timer_ev, &tv);
}

static void engine_timer_cb(int fd, short what, void *arg) {
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    if (!ep) return;
    xqc_engine_main_logic(ep->engine);
}

// QUIC packet read callback
// QUIC packet read callback
// XR_RECV_ONE=1: read one datagram per callback (old behaviour), for A/B tests
static int recv_one(void) { static int v = -1; if (v < 0) v = getenv("XR_RECV_ONE") != NULL; return v; }
#define RECV_BATCH_MAX 64   /* datagrams per callback; libevent calls again if more are queued */

static void packet_read_cb(int fd, short what, void *arg) {
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    if (!ep) return;

    unsigned char buf[2000];
    struct sockaddr_in peer_addr, local_addr;
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) < 0) {
        return;
    }
    const struct sockaddr_in bound = local_addr;
    const int max_batch = recv_one() ? 1 : RECV_BATCH_MAX;
    int got = 0;

    /* drain the socket (up to max_batch), then run the engine once for the batch */
    while (got < max_batch) {
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(struct timespec))];
        struct msghdr msg = {
            .msg_name       = &peer_addr,
            .msg_namelen    = sizeof(peer_addr),
            .msg_iov        = &iov,
            .msg_iovlen     = 1,
            .msg_control    = cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf)
        };

        ssize_t n = recvmsg(fd, &msg, 0);
        if (n <= 0) {   /* EAGAIN: socket empty (or an empty datagram) */
            break;
        }
        got++;

        local_addr = bound;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
                local_addr.sin_addr = pi->ipi_spec_dst;
            } else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS) {
                kts_log(ep->mode == QUIC_MODE_CLIENT ? "client" : "server",
                        (const struct timespec *)CMSG_DATA(cmsg), n);
            }
        }
#if ENABLE_DEBUG_LOGS
        LOG_DEBUG("[%s-quic] packet_read_cb received %zd bytes\n",
                  ep->mode == QUIC_MODE_CLIENT ? "client" : "server", n);
#endif
        unsigned char *pkt = buf;
        if (ep->rtp_encap && (n = rtp_strip(ep, buf, n, &pkt)) < 0) {
            continue;                                   /* malformed RTP: drop */
        }

        xqc_engine_packet_process(ep->engine, pkt, n,
                                  (struct sockaddr *)&local_addr, sizeof(local_addr),
                                  (struct sockaddr *)&peer_addr, msg.msg_namelen,
                                  get_timestamp(), ep);
    }

    if (got) {
        xqc_engine_finish_recv(ep->engine);
    }
}

quic_endpoint_t *quic_client_start(const quic_client_config_t *config) {
    if (!config) return NULL;

    quic_endpoint_t *ep = calloc(1, sizeof(quic_endpoint_t));
    if (!ep) return NULL;

    ep->mode = QUIC_MODE_CLIENT;
    ep->rtp_tag = config->rtp_tag;
    if (ep->rtp_tag) {
        ep->rtp_check = fopen("rtp_check_client.csv", "w");
        if (ep->rtp_check) setvbuf(ep->rtp_check, NULL, _IOLBF, 0);   /* server is killed, not stopped */
        if (ep->rtp_check) fprintf(ep->rtp_check,
            "rtp_ssrc,rtp_seq,rtp_pkt_ctr,he_tag,he_tag_valid,dgram_id,quic_app_tag,result,dup\n");
    }
    ep->rtp_encap = config->rtp_encap || config->rtp_pdu_set || config->rtp_tag;
    ep->rtp_pdu_set = config->rtp_pdu_set;
    if (config->qlog && config->qlog[0] != '\0' && !quic_min_log()) {
        ep->qlog_file = fopen(config->qlog, "wb");
    } else {
        ep->qlog_file = NULL;
    }
    ep->app_recv_cb = config->recv_cb;
    ep->app_user_data = config->user_data;
    ep->datagram_mode = config->enable_datagram;

    xqc_conn_settings_t conn_settings = {
        .proto_version = XQC_VERSION_V1,
        .ping_on = 1,
        .standby_path_probe_timeout = 500,
        .init_idle_time_out = CONNECTION_TIMEOUT,
        .idle_time_out = CONNECTION_TIMEOUT,
        .enable_multipath = 1,
        .mp_enable_reinjection = 0,
        .mp_ping_on = 1,
        .mp_ack_on_any_path = 0,
        .init_max_path_id = MAX_PATHS,
        .max_streams_bidi = 32,
        .max_datagram_frame_size = config->enable_datagram ? 65535 : 0,
        .max_udp_payload_size = config->enable_datagram ? 65527 : 0,
        .max_pkt_out_size = config->enable_datagram ? 2000 : 0,
        .datagram_force_retrans_on = 0,
        .enable_experimental_redundancy = config->enable_redundancy,
        .scheduler_callback = get_scheduler_cb(config->scheduler),
        .cong_ctrl_callback = get_cong_ctrl_cb(config->congestion)
    };

    if (config->enable_datagram) {
        ep->quic_dgram_id = 1;
        ep->client_dgram_id = 0;
        ep->max_dgram_id = 0;
        memset(ep->dgram_seen, 0, sizeof(ep->dgram_seen));
        ep->dgram_id_mask = 0;
    }

    for (size_t i = 0; i < config->num_peer_addrs && i < MAX_PATHS; i++) {
        struct sockaddr_in *addr = &ep->peer_addrs[ep->num_peer_addrs++];
        addr->sin_family = AF_INET;
        addr->sin_port = htons(config->peer_port ? config->peer_port : 8000);
        inet_pton(AF_INET, config->peer_ips[i], &addr->sin_addr);
    }

    for (size_t i = 0; i < config->num_local_addrs && i < MAX_PATHS; i++) {
        struct sockaddr_in *addr = &ep->local_addrs[ep->num_local_addrs++];
        addr->sin_family = AF_INET;
        addr->sin_port = htons(0);
        inet_pton(AF_INET, config->local_ips[i], &addr->sin_addr);
    }
    if (ep->num_local_addrs == 0) ep->num_local_addrs = 1;
    if (ep->num_paths == 0) ep->num_paths = 1;

    ep->eb = event_base_new();
    
    xqc_config_t cfg;
    xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT);
    /* XR_SENDMMSG=0|1 overrides the app setting (A/B tests) */
    cfg.sendmmsg_on = getenv("XR_SENDMMSG") ? atoi(getenv("XR_SENDMMSG")) : config->sendmmsg_on;

    xqc_engine_callback_t eng_cb = {
        .set_event_timer = set_event_timer,
        .log_callbacks = { 
            .xqc_log_write_err = log_write, 
            .xqc_log_write_stat = log_write,
            .xqc_qlog_event_write = qlog_event_write 
        }
    };

    xqc_transport_callbacks_t trans_cb = {
        .write_socket = write_socket,
        .write_socket_ex = write_socket_ex,
        .write_mmsg = write_mmsg,
        .write_mmsg_ex = write_mmsg_ex,
        .cert_verify_cb = cert_verify_cb,
        .save_token = save_token_cb,
        .save_session_cb = save_session_cb,
        .ready_to_create_path_notify = ready_to_create_path_notify,
        .path_created_notify = path_created_notify
    };

    xqc_engine_ssl_config_t ssl_cfg = {
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS
    };

    ep->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &cfg, &ssl_cfg, &eng_cb, &trans_cb, ep);
    if (!ep->engine) { free(ep); return NULL; }

    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = conn_create_notify,
            .conn_close_notify = conn_close_notify,
            .conn_handshake_finished = conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_create_notify = stream_create_notify,
            .stream_close_notify = stream_close_notify,
            .stream_read_notify = stream_read_notify,
            .stream_write_notify = stream_write_notify,
        },
        .dgram_cbs = {
            .datagram_read_notify = datagram_read_notify,
            .datagram_write_notify = datagram_write_notify,
            .datagram_lost_notify = datagram_lost_notify,
            .datagram_acked_notify = datagram_acked_notify,
        }
    };
    // alp_ctx is owned (freed) by xquic in xqc_engine_destroy(); ep reaches the callbacks
    // through the engine / connection user data instead, so pass no context here.
    xqc_engine_register_alpn(ep->engine, "raw", 3, &ap_cbs, NULL);

    ep->quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(ep->quic_fd, F_SETFL, O_NONBLOCK);
    if (kts_on()) { int on = 1; setsockopt(ep->quic_fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on)); }
    int reuse = 1;
    setsockopt(ep->quic_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int pktinfo = 1;
    setsockopt(ep->quic_fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(0)
    };
    bind(ep->quic_fd, (struct sockaddr*)&addr, sizeof(addr));

    ep->quic_ev = event_new(ep->eb, ep->quic_fd, EV_READ | EV_PERSIST, packet_read_cb, ep);
    event_add(ep->quic_ev, NULL);

    ep->timer_ev = event_new(ep->eb, -1, 0, engine_timer_cb, ep);
    struct timeval tv = {0, 10000};
    event_add(ep->timer_ev, &tv);

    xqc_conn_ssl_config_t conn_ssl_config = {0};

    ep->path_idx = 0;
    ep->ep_conn_settings = conn_settings;
    ep->ep_ssl_config = conn_ssl_config;

    const xqc_cid_t *cidp = xqc_connect(ep->engine, &ep->ep_conn_settings, NULL, 0, "localhost", 0,
                                        &ep->ep_ssl_config, 
                                        (struct sockaddr*)&ep->peer_addrs[ep->path_idx], sizeof(ep->peer_addrs[ep->path_idx]),
                                        "raw", ep);
    if (!cidp) { free(ep); return NULL; }
    memcpy(&ep->cid, cidp, sizeof(ep->cid));

    return ep;
}

quic_endpoint_t *quic_server_start(const quic_server_config_t *config) {
    if (!config) return NULL;

    quic_endpoint_t *ep = calloc(1, sizeof(quic_endpoint_t));
    if (!ep) return NULL;

    ep->mode = QUIC_MODE_SERVER;
    ep->rtp_tag = config->rtp_tag;
    if (ep->rtp_tag) {
        ep->rtp_check = fopen("rtp_check_server.csv", "w");
        if (ep->rtp_check) setvbuf(ep->rtp_check, NULL, _IOLBF, 0);   /* server is killed, not stopped */
        if (ep->rtp_check) fprintf(ep->rtp_check,
            "rtp_ssrc,rtp_seq,rtp_pkt_ctr,he_tag,he_tag_valid,dgram_id,quic_app_tag,result,dup\n");
    }
    ep->rtp_encap = config->rtp_encap || config->rtp_pdu_set || config->rtp_tag;
    ep->rtp_pdu_set = config->rtp_pdu_set;
    if (config->qlog && config->qlog[0] != '\0' && !quic_min_log()) {
        ep->qlog_file = fopen(config->qlog, "wb");
    } else {
        ep->qlog_file = NULL;
    }
    ep->app_recv_cb = config->recv_cb;
    ep->app_user_data = config->user_data;
    ep->datagram_mode = config->enable_datagram;

    ep->eb = event_base_new();

    xqc_config_t cfg;
    xqc_engine_get_default_config(&cfg, XQC_ENGINE_SERVER);
    /* XR_SENDMMSG=0|1 overrides the app setting (A/B tests) */
    cfg.sendmmsg_on = getenv("XR_SENDMMSG") ? atoi(getenv("XR_SENDMMSG")) : config->sendmmsg_on;

    xqc_engine_callback_t eng_cb = {
        .set_event_timer = set_event_timer,
        .cid_generate_cb = cid_generate_cb,
        .log_callbacks = { 
            .xqc_log_write_err = log_write, 
            .xqc_log_write_stat = log_write,
            .xqc_qlog_event_write = qlog_event_write 
        }
    };

    xqc_transport_callbacks_t trans_cb = {
        .server_accept = server_accept,
        .write_socket = write_socket,
        .write_socket_ex = write_socket_ex,
        .write_mmsg = write_mmsg,
        .write_mmsg_ex = write_mmsg_ex,
        .cert_verify_cb = cert_verify_cb,
        .ready_to_create_path_notify = ready_to_create_path_notify,
        .path_created_notify = path_created_notify
    };

    xqc_engine_ssl_config_t ssl_cfg = {
        .private_key_file = (char *)(config->key_file ? config->key_file : "server.key"),
        .cert_file = (char *)(config->cert_file ? config->cert_file : "server.crt"),
        .ciphers = XQC_TLS_CIPHERS,
        .groups = XQC_TLS_GROUPS
    };

    xqc_conn_settings_t conn_settings = {
        .proto_version = XQC_VERSION_V1,
        .ping_on = 1,
        .init_idle_time_out = CONNECTION_TIMEOUT,
        .idle_time_out = CONNECTION_TIMEOUT,
        .standby_path_probe_timeout = 500,
        .enable_multipath = 1,
        .mp_enable_reinjection = 0,
        .mp_ping_on = 1,
        .mp_ack_on_any_path = 0,
        .init_max_path_id = MAX_PATHS,
        .least_available_cid_count = MAX_PATHS,
        .max_streams_bidi = 32,
        .max_datagram_frame_size = config->enable_datagram ? 65535 : 0,
        .max_udp_payload_size = config->enable_datagram ? 65527 : 0,
        .max_pkt_out_size = config->enable_datagram ? 2000 : 0,
        .datagram_force_retrans_on = 0,
        .enable_experimental_redundancy = config->enable_redundancy,
        .scheduler_callback = get_scheduler_cb(config->scheduler),
        .cong_ctrl_callback = get_cong_ctrl_cb(config->congestion)
    };

    for (size_t i = 0; i < config->num_local_addrs && i < MAX_PATHS; i++) {
        struct sockaddr_in *addr = &ep->local_addrs[ep->num_local_addrs++];
        addr->sin_family = AF_INET;
        addr->sin_port = htons(0);
        inet_pton(AF_INET, config->local_ips[i], &addr->sin_addr);
    }

    if (config->enable_datagram) {
        ep->quic_dgram_id = 1;
        ep->server_dgram_id = 0;
        ep->max_dgram_id = 0;
        memset(ep->dgram_seen, 0, sizeof(ep->dgram_seen));
        ep->dgram_id_mask = 0;
    }
    if (ep->num_paths == 0) ep->num_paths = 1;

    ep->engine = xqc_engine_create(XQC_ENGINE_SERVER, &cfg, &ssl_cfg, &eng_cb, &trans_cb, ep);
    if (!ep->engine) { free(ep); return NULL; }

    xqc_server_set_conn_settings(ep->engine, &conn_settings);

    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = {
            .conn_create_notify = conn_create_notify,
            .conn_close_notify = conn_close_notify,
            .conn_handshake_finished = conn_handshake_finished,
        },
        .stream_cbs = {
            .stream_create_notify = stream_create_notify,
            .stream_close_notify = stream_close_notify,
            .stream_read_notify = stream_read_notify,
            .stream_write_notify = stream_write_notify,
        },
        .dgram_cbs = {
            .datagram_read_notify = datagram_read_notify,
            .datagram_write_notify = datagram_write_notify,
            .datagram_lost_notify = datagram_lost_notify,
            .datagram_acked_notify = datagram_acked_notify,
        }
    };
    // alp_ctx is owned (freed) by xquic in xqc_engine_destroy(); ep reaches the callbacks
    // through the engine / connection user data instead, so pass no context here.
    xqc_engine_register_alpn(ep->engine, "raw", 3, &ap_cbs, NULL);

    ep->quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(ep->quic_fd, F_SETFL, O_NONBLOCK);
    if (kts_on()) { int on = 1; setsockopt(ep->quic_fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on)); }
    int reuse = 1;
    setsockopt(ep->quic_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int pktinfo = 1;
    setsockopt(ep->quic_fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(config->listen_port ? config->listen_port : 8000)
    };
    bind(ep->quic_fd, (struct sockaddr*)&addr, sizeof(addr));

    ep->quic_ev = event_new(ep->eb, ep->quic_fd, EV_READ | EV_PERSIST, packet_read_cb, ep);
    event_add(ep->quic_ev, NULL);

    ep->timer_ev = event_new(ep->eb, -1, 0, engine_timer_cb, ep);
    struct timeval tv = {0, 10000};
    event_add(ep->timer_ev, &tv);

    return ep;
}

int quic_send(quic_endpoint_t *ep, const uint8_t *data, size_t len) {
    if (!ep || !ep->conn) return -1;

    if (ep->datagram_mode) {
        uint8_t buf[2000];
        if (len + 8 > sizeof(buf)) return -1;

        uint64_t dgram_id = (ep->mode == QUIC_MODE_CLIENT) ? ep->client_dgram_id++ : ep->server_dgram_id++;
        uint64_t net_val = htobe64(dgram_id);
        memcpy(buf, &net_val, sizeof(uint64_t));
        memcpy(buf + 8, data, len);

        if (!ep->rtp_tag) {
            return xqc_datagram_send(ep->conn, buf, len + 8, &ep->quic_dgram_id, 1);
        }
        /* tag = first 4 B of the app payload; packets are normally written on the next
           engine tick, so with rtp_tag write them now, while the tag is set */
        ep->tx_tag_valid = len >= 4;
        if (ep->tx_tag_valid) memcpy(&ep->tx_tag, data, sizeof(ep->tx_tag));
        int ret = xqc_datagram_send(ep->conn, buf, len + 8, &ep->quic_dgram_id, 1);
        if (ret >= 0 && ep->engine) xqc_engine_main_logic(ep->engine);
        ep->tx_tag_valid = 0;            /* packets written later are untagged */
        return ret;
    } else if (ep->stream) {
        return (int)xqc_stream_send(ep->stream, (unsigned char *)data, len, 0);
    }
    return -1;
}

void quic_endpoint_stop(quic_endpoint_t *ep) {
    if (!ep) return;

    if (ep->rtp_encap) {
        printf("[rtp] %s: sent %lu RTP datagrams (PDU Set ext %d), received %lu RTP "
               "(%lu with BEDE ext) + %lu bare QUIC\n",
               ep->mode == QUIC_MODE_CLIENT ? "client" : "server", (unsigned long)ep->rtp_tx,
               ep->rtp_pdu_set, (unsigned long)ep->rtp_rx, (unsigned long)ep->rtp_rx_pduset,
               (unsigned long)ep->rtp_rx_plain);
        fflush(stdout);
    }
    if (ep->rtp_tag) {
        printf("[rtp-check] %s: datagrams %lu  match %lu  MISMATCH %lu  untagged %lu  no_elem %lu\n",
               ep->mode == QUIC_MODE_CLIENT ? "client" : "server",
               (unsigned long)(ep->chk_match + ep->chk_mismatch + ep->chk_untagged + ep->chk_noelem),
               (unsigned long)ep->chk_match, (unsigned long)ep->chk_mismatch,
               (unsigned long)ep->chk_untagged, (unsigned long)ep->chk_noelem);
        fflush(stdout);
        if (ep->rtp_check) { fflush(ep->rtp_check); fclose(ep->rtp_check); ep->rtp_check = NULL; }
    }

    if (ep->engine && ep->conn) {
        xqc_conn_close(ep->engine, &ep->cid);
        ep->conn = NULL;
        xqc_engine_main_logic(ep->engine);
    }

    if (ep->eb) {
        event_base_loopbreak(ep->eb);
    }

    if (ep->qlog_file) {
        fclose(ep->qlog_file);
        ep->qlog_file = NULL;
    }

    if (ep->engine) {
        xqc_engine_destroy(ep->engine);
        ep->engine = NULL;
    }

    if (ep->quic_ev) {
        event_free(ep->quic_ev);
        ep->quic_ev = NULL;
    }

    if (ep->timer_ev) {
        event_free(ep->timer_ev);
        ep->timer_ev = NULL;
    }

    if (ep->quic_fd >= 0) {
        close(ep->quic_fd);
        ep->quic_fd = -1;
    }

    if (ep->eb) {
        event_base_free(ep->eb);
        ep->eb = NULL;
    }

    free(ep);
}