#define _GNU_SOURCE

#include "quic_api.h"
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
#include <event2/event.h>
#include <xquic/xquic.h>
#include <sys/socket.h>

#ifndef ACTIVE_LOG_LEVEL
#define ACTIVE_LOG_LEVEL 4 /* 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR, 4=OFF */
#endif

#define MAX_PATHS 16
#define MAX_BATCH_SIZE 64
#define MAX_DGRAM_SIZE 2000
#define DGRAM_HEADER_SIZE 2
#define DGRAM_HEADER_WIN 2048

#define XQC_SOCKET_ERROR -1
#define XQC_SOCKET_EAGAIN -2

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

static void quic_log(quic_log_level_t level, const char *fmt, ...) {
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

#define LOG_DEBUG(...) do { if (ACTIVE_LOG_LEVEL <= 0) quic_log(QUIC_LOG_DEBUG, __VA_ARGS__); } while(0)
#define LOG_INFO(...)  do { if (ACTIVE_LOG_LEVEL <= 1) quic_log(QUIC_LOG_INFO,  __VA_ARGS__); } while(0)
#define LOG_WARN(...)  do { if (ACTIVE_LOG_LEVEL <= 2) quic_log(QUIC_LOG_WARN,  __VA_ARGS__); } while(0)
#define LOG_ERROR(...) do { if (ACTIVE_LOG_LEVEL <= 3) quic_log(QUIC_LOG_ERROR, __VA_ARGS__); } while(0)

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

static int is_new_datagram_win(uint16_t id, uint16_t *max_dgram_header_id, uint64_t *seen) {
#define SEEN_BIT(i) (seen[((i) % DGRAM_HEADER_WIN) / 64] & (1ULL << ((i) % 64)))
#define SEEN_SET(i) (seen[((i) % DGRAM_HEADER_WIN) / 64] |= (1ULL << ((i) % 64)))
#define SEEN_CLR(i) (seen[((i) % DGRAM_HEADER_WIN) / 64] &= ~(1ULL << ((i) % 64)))

    int16_t diff = (int16_t)(id - *max_dgram_header_id);

    if (diff > 0) {
        if (diff >= DGRAM_HEADER_WIN) {
            memset(seen, 0, DGRAM_HEADER_WIN / 8);
        } else {
            for (uint16_t i = *max_dgram_header_id + 1; i != id; i++) {
                SEEN_CLR(i);
            }
        }
        SEEN_SET(id);
        *max_dgram_header_id = id;
        return 1;
    }

    if (-diff >= DGRAM_HEADER_WIN) return 0;
    
    if (SEEN_BIT(id)) return 0;
    
    SEEN_SET(id);
    return 1;

#undef SEEN_BIT
#undef SEEN_SET
#undef SEEN_CLR
}

// QUIC logging callback
static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) { 
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

// QUIC socket helper
static inline void resolve_path_addrs(quic_endpoint_t *ep, uint64_t path_id, 
                                      const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                                      struct sockaddr_in **peer_addr, struct sockaddr_in **local_addr, 
                                      socklen_t *namelen) 
{
    if (ep->mode == QUIC_MODE_CLIENT) {
        *peer_addr = &ep->peer_addrs[(path_id + ep->path_idx) % ep->num_peer_addrs];
        *local_addr = &ep->local_addrs[(path_id / ep->num_peer_addrs) % ep->num_local_addrs];
        *namelen = sizeof(struct sockaddr_in);
    } else {
        *peer_addr = (struct sockaddr_in *)_peer_addr;
        *local_addr = &ep->local_addrs[path_id % ep->num_local_addrs];
        *namelen = _peer_addrlen;
    }
}

// QUIC socket callbacks
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) 
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0) return XQC_SOCKET_ERROR;

    ssize_t res = sendto(ep->quic_fd, buf, size, 0, peer_addr, peer_addrlen);
    if (res < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    return res;
}
static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                               void *user_data) 
{ 
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd < 0) return XQC_SOCKET_ERROR;

    struct sockaddr_in *peer_addr, *local_addr;
    socklen_t namelen;
    resolve_path_addrs(ep, path_id, _peer_addr, _peer_addrlen, &peer_addr, &local_addr, &namelen);

    struct iovec iov = { (void *)buf, size };
    cmsg_pktinfo_t cbuf = {0};

    struct msghdr msg = {
        .msg_name       = (void *)peer_addr,
        .msg_namelen    = namelen,
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cbuf.buf,
        .msg_controllen = sizeof(cbuf.buf)
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type  = IP_PKTINFO;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
    ((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = local_addr->sin_addr;
    LOG_DEBUG("[%s-quic] write_socket_ex: calling write_socket for path_id %lu\n",
            ep->mode == QUIC_MODE_SERVER ? "server" : "client",
            (unsigned long)path_id);
    ssize_t res = sendmsg(ep->quic_fd, &msg, 0);
    if (res < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
    return res;
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
    memset(msgs, 0, sizeof(msgs));

    for (unsigned int i = 0; i < vlen; i++) {
        msgs[i].msg_hdr.msg_name    = (void *)peer_addr;
        msgs[i].msg_hdr.msg_namelen = peer_addrlen;
        msgs[i].msg_hdr.msg_iov     = (struct iovec *)&msg_iov[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
    }

    int sent = sendmmsg(ep->quic_fd, msgs, vlen, 0);
    if (sent < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
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

    struct sockaddr_in *peer_addr, *local_addr;
    socklen_t namelen;
    resolve_path_addrs(ep, path_id, _peer_addr, _peer_addrlen, &peer_addr, &local_addr, &namelen);

    struct mmsghdr msgs[vlen];
    cmsg_pktinfo_t cbufs[vlen];

    memset(msgs, 0, sizeof(msgs));
    memset(cbufs, 0, sizeof(cbufs));

    for (unsigned int i = 0; i < vlen; i++) {
        struct msghdr *hdr = &msgs[i].msg_hdr;

        hdr->msg_name       = (void *)peer_addr;
        hdr->msg_namelen    = namelen;
        hdr->msg_iov        = (struct iovec *)&msg_iov[i];
        hdr->msg_iovlen     = 1;
        hdr->msg_control    = cbufs[i].buf;
        hdr->msg_controllen = sizeof(cbufs[i].buf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(hdr);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type  = IP_PKTINFO;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
        ((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = local_addr->sin_addr;
    }
    
    LOG_DEBUG("[%s-quic] write_mmsg_ex: calling sendmmsg for path_id %lu (batch of %u datagrams)\n",
             ep->mode == QUIC_MODE_SERVER ? "server" : "client",
             (unsigned long)path_id, vlen);
                      
    int sent = sendmmsg(ep->quic_fd, msgs, vlen, 0);
    if (sent < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
    }
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
        
        LOG_DEBUG("[quic] stream_read_notify called for stream %lu, received %zd bytes\n", (unsigned long)xqc_stream_id(strm), n);

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
    ep->msg_id = 0;
    ep->dgram_header_id = 0;
    ep->max_dgram_header_id = 0;
    memset(ep->dgram_header_win, 0, sizeof(ep->dgram_header_win));
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
    if (ep->mode == QUIC_MODE_CLIENT && !ep->datagram_mode) {
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
    ep->max_dgram_header_id = 0;
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
    if (!ep || data_len <= DGRAM_HEADER_SIZE) return;

    uint16_t net_val;
    memcpy(&net_val, data, DGRAM_HEADER_SIZE);
    uint16_t dgram_header_id = ntohs(net_val);

    if (!is_new_datagram_win(dgram_header_id, &ep->max_dgram_header_id, ep->dgram_header_win)) {
        LOG_DEBUG("[quic] duplicate datagram %u (<=%u) recv\n", dgram_header_id, ep->max_dgram_header_id);
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + DGRAM_HEADER_SIZE;
    size_t payload_len = data_len - DGRAM_HEADER_SIZE;

    if (ep->app_recv_cb) {
        ep->app_recv_cb(payload, payload_len, ep->app_user_data);
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) { 
    LOG_DEBUG("[quic] datagram sent to peer\n");
}
static void datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { 
    LOG_DEBUG("[quic] datagram %lu acked\n", dgram_id); 
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
static void packet_read_cb(int fd, short what, void *arg) {
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    if (!ep) return;

    unsigned char buf[2000];
    struct sockaddr_in peer_addr, local_addr;
    socklen_t local_len = sizeof(local_addr);

    if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) < 0) {
        return;
    }
    in_port_t bound_port = local_addr.sin_port;

    while (1) {
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

        struct msghdr msg = {
            .msg_name       = &peer_addr,
            .msg_namelen    = sizeof(peer_addr),
            .msg_iov        = &iov,
            .msg_iovlen     = 1,
            .msg_control    = cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf)
        };

        ssize_t n = recvmsg(fd, &msg, 0);
        if (n <= 0) {
            break;
        }

        local_addr.sin_port = bound_port;
        struct in_addr hdr_dst = local_addr.sin_addr;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
                local_addr.sin_addr = pi->ipi_spec_dst; 
                hdr_dst = pi->ipi_addr;
                break;
            }
        }

        if (ACTIVE_LOG_LEVEL <= QUIC_LOG_DEBUG) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN], hdr_dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &local_addr.sin_addr, dst_ip, sizeof(dst_ip));
            inet_ntop(AF_INET, &hdr_dst, hdr_dst_ip, sizeof(hdr_dst_ip));

            LOG_DEBUG("[%s-quic] packet_read_cb received %zd bytes from %s:%d to %s:%d (header dst %s)\n",
                    ep->mode == QUIC_MODE_CLIENT ? "client" : "server", n,
                    src_ip, ntohs(peer_addr.sin_port),
                    dst_ip, ntohs(local_addr.sin_port), hdr_dst_ip);
        }

        xqc_engine_packet_process(ep->engine, buf, n,
                                  (struct sockaddr *)&local_addr, sizeof(local_addr),
                                  (struct sockaddr *)&peer_addr, msg.msg_namelen,
                                  get_timestamp(), ep);
    }

    xqc_engine_finish_recv(ep->engine);
}

// External QUIC Endpoint Initialization
static int init_quic_socket_and_events(quic_endpoint_t *ep, uint16_t port) {
    ep->quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ep->quic_fd < 0) return -1;

    fcntl(ep->quic_fd, F_SETFL, O_NONBLOCK);
    int reuse = 1;
    setsockopt(ep->quic_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int pktinfo = 1;
    setsockopt(ep->quic_fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port)
    };
    if (bind(ep->quic_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return -1;

    ep->quic_ev = event_new(ep->eb, ep->quic_fd, EV_READ | EV_PERSIST, packet_read_cb, ep);
    event_add(ep->quic_ev, NULL);

    ep->timer_ev = event_new(ep->eb, -1, 0, engine_timer_cb, ep);
    struct timeval tv = {0, 10000};
    event_add(ep->timer_ev, &tv);

    return 0;
}
quic_endpoint_t *quic_client_start(const quic_client_config_t *config) {
    if (!config) return NULL;

    quic_endpoint_t *ep = calloc(1, sizeof(quic_endpoint_t));
    if (!ep) return NULL;

    ep->mode = QUIC_MODE_CLIENT;
    if (config->qlog && config->qlog[0] != '\0') {
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
        ep->msg_id = 0;
        ep->dgram_header_id = 0;
        ep->max_dgram_header_id = 0;
        memset(ep->dgram_header_win, 0, sizeof(ep->dgram_header_win));
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
    cfg.sendmmsg_on = config->sendmmsg_on;

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
    xqc_engine_register_alpn(ep->engine, "raw", 3, &ap_cbs, ep);

    if (init_quic_socket_and_events(ep, 0) < 0) {
        free(ep);
        return NULL;
    }

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
    if (config->qlog && config->qlog[0] != '\0') {
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
    cfg.sendmmsg_on = config->sendmmsg_on;

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
        ep->msg_id = 0;
        ep->dgram_header_id = 0;
        ep->max_dgram_header_id = 0;
        memset(ep->dgram_header_win, 0, sizeof(ep->dgram_header_win));
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
    xqc_engine_register_alpn(ep->engine, "raw", 3, &ap_cbs, ep);

    uint16_t listen_port = config->listen_port ? config->listen_port : 8000;
    if (init_quic_socket_and_events(ep, listen_port) < 0) {
        free(ep);
        return NULL;
    }

    return ep;
}

// External QUIC send helper
static inline uint64_t pack_dgram_id(uint16_t msg_id, uint8_t seq, uint8_t max_seq, uint16_t dgram_header_id) {
    return ((uint64_t)msg_id     << 48) | 
           ((uint64_t)seq        << 40) |
           ((uint64_t)max_seq    << 32) | 
           ((uint64_t)dgram_header_id << 16) |  
           0x0000;
}

// External QUIC send endpoints
int quic_send(quic_endpoint_t *ep, const uint8_t *data, size_t len) {
    if (!ep || !ep->conn) return -1;

    if (ep->datagram_mode) {
        uint8_t buf[MAX_DGRAM_SIZE];
        if (len + DGRAM_HEADER_SIZE > sizeof(buf)) return -1;

        uint16_t dgram_header_id = ep->dgram_header_id++;
        uint64_t dgram_id = pack_dgram_id(ep->msg_id++, 0, 0, dgram_header_id);

        uint16_t net_header_id = htons(dgram_header_id);
        memcpy(buf, &net_header_id, DGRAM_HEADER_SIZE);
        memcpy(buf + DGRAM_HEADER_SIZE, data, len);

        LOG_DEBUG("[quic] packed dgram: msg_id=%u, seq=0, max_seq=0, wire_id=%u, full_dgram_id=%lu\n", 
            ep->msg_id - 1, dgram_header_id, (unsigned long)dgram_id);

        return xqc_datagram_send(ep->conn, buf, len + DGRAM_HEADER_SIZE, &dgram_id, 1);
    } else if (ep->stream) {
        return (int)xqc_stream_send(ep->stream, (unsigned char *)data, len, 0);
    }
    return -1;
}
int quic_send_msg(quic_endpoint_t *ep, struct iovec *iov, size_t iov_size) {
    if (!ep || !ep->conn || !iov || iov_size == 0) return -1;

    if (ep->datagram_mode) {
        if (iov_size > MAX_BATCH_SIZE) return -1;

        struct iovec batch_iov[MAX_BATCH_SIZE];
        uint64_t out_dgram_ids[MAX_BATCH_SIZE];
        static __thread uint8_t buf[MAX_BATCH_SIZE][MAX_DGRAM_SIZE]; 

        uint16_t batch_msg_id = ep->msg_id++;
        uint8_t max_seq = (uint8_t)(iov_size - 1);

        for (size_t i = 0; i < iov_size; i++) {
            size_t len = iov[i].iov_len;
            if (len + DGRAM_HEADER_SIZE > MAX_DGRAM_SIZE) return -1;

            uint16_t dgram_header_id = ep->dgram_header_id++;
            out_dgram_ids[i] = pack_dgram_id(batch_msg_id, (uint8_t)i, max_seq, dgram_header_id);

            uint16_t net_wire_id = htons(dgram_header_id);
            memcpy(buf[i], &net_wire_id, DGRAM_HEADER_SIZE);
            memcpy(buf[i] + DGRAM_HEADER_SIZE, iov[i].iov_base, len);

            LOG_DEBUG("[quic] packed dgram: msg_id=%u, seq=%u, max_seq=%u, wire_id=%u, full_dgram_id=%lu\n", 
                batch_msg_id, (unsigned int)i, (unsigned int)(iov_size - 1), dgram_header_id, (unsigned long)out_dgram_ids[i]);

            batch_iov[i].iov_base = buf[i];
            batch_iov[i].iov_len  = len + DGRAM_HEADER_SIZE;
        }

        size_t sent_cnt = 0;
        size_t sent_bytes = 0;
        
        return xqc_datagram_send_multiple(ep->conn, batch_iov, out_dgram_ids, iov_size, &sent_cnt, &sent_bytes, 1);

    } else if (ep->stream) {
        int ret = 0;
        for (size_t i = 0; i < iov_size; i++) {
            ret = (int)xqc_stream_send(ep->stream, iov[i].iov_base, iov[i].iov_len, 0);
            if (ret < 0) break;
        }
        return ret;
    }

    return -1;
}

void quic_endpoint_stop(quic_endpoint_t *ep) {
    if (!ep) return;

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