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

#define MAX_PATHS 4
#define API_QUEUE_CAPACITY 4096
#define API_MAX_PAYLOAD 2000

typedef struct {
    uint8_t data[API_MAX_PAYLOAD];
    size_t len;
} api_queue_item_t;

typedef struct {
    api_queue_item_t items[API_QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} api_queue_t;

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
    pthread_t thread;

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
    uint64_t dgram_id_mask;

    api_queue_t          rx_queue;
    pthread_t            worker_thread;
    int                  worker_running;

    quic_recv_cb         app_recv_cb;
    void                *app_user_data;
    
    int datagram_mode;
};

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

//App queue functions
static void api_enqueue_rx(quic_endpoint_t *ep, const uint8_t *data, size_t len) {
    if (!ep || len > API_MAX_PAYLOAD) return;

    pthread_mutex_lock(&ep->rx_queue.lock);
    if (ep->rx_queue.count >= API_QUEUE_CAPACITY) {
        pthread_mutex_unlock(&ep->rx_queue.lock);
        fprintf(stderr, "[QUIC API WARNING] RX Queue Full! Dropping packet.\n");
        return;
    }

    memcpy(ep->rx_queue.items[ep->rx_queue.tail].data, data, len);
    ep->rx_queue.items[ep->rx_queue.tail].len = len;
    ep->rx_queue.tail = (ep->rx_queue.tail + 1) % API_QUEUE_CAPACITY;
    ep->rx_queue.count++;

    pthread_cond_signal(&ep->rx_queue.cond);
    pthread_mutex_unlock(&ep->rx_queue.lock);
}
static void *api_rx_worker_thread(void *arg) {
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    uint8_t buffer[API_MAX_PAYLOAD];
    size_t len;

    while (ep->worker_running) {
        pthread_mutex_lock(&ep->rx_queue.lock);

        while (ep->rx_queue.count == 0 && ep->worker_running) {
            pthread_cond_wait(&ep->rx_queue.cond, &ep->rx_queue.lock);
        }

        if (!ep->worker_running && ep->rx_queue.count == 0) {
            pthread_mutex_unlock(&ep->rx_queue.lock);
            break;
        }

        /* Pop item */
        api_queue_item_t *item = &ep->rx_queue.items[ep->rx_queue.head];
        memcpy(buffer, item->data, item->len);
        len = item->len;

        ep->rx_queue.head = (ep->rx_queue.head + 1) % API_QUEUE_CAPACITY;
        ep->rx_queue.count--;

        pthread_mutex_unlock(&ep->rx_queue.lock);

        /* Invoke application callback safely on worker thread */
        if (ep->app_recv_cb) {
            ep->app_recv_cb(buffer, len, ep->app_user_data);
        }
    }
    return NULL;
}
static void init_rx_worker(quic_endpoint_t *ep) {
    pthread_mutex_init(&ep->rx_queue.lock, NULL);
    pthread_cond_init(&ep->rx_queue.cond, NULL);
    ep->worker_running = 1;
    pthread_create(&ep->worker_thread, NULL, api_rx_worker_thread, ep);
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

// QUIC socket callbacks
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) {
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd <= 0) return -1;
    return sendto(ep->quic_fd, buf, size, 0, peer_addr, peer_addrlen);
}
static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                               void *user_data) { 
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || ep->quic_fd <= 0) return -1;

    struct sockaddr_in *peer_addr = ep->mode == QUIC_MODE_CLIENT ? &ep->peer_addrs[path_id % ep->num_peer_addrs] : (struct sockaddr_in *)_peer_addr;
    struct sockaddr_in *local_addr = ep->mode == QUIC_MODE_CLIENT ? &ep->local_addrs[(path_id / ep->num_peer_addrs) % ep->num_local_addrs] : &ep->local_addrs[path_id % ep->num_local_addrs]; 

    char local_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr->sin_addr, local_ip, sizeof(local_ip));
    inet_ntop(AF_INET, &peer_addr->sin_addr, peer_ip, sizeof(peer_ip));
    
    LOG_DEBUG("[%s-quic] write_socket_ex called for path_id %lu from %s:%d to %s:%d\n", 
                ep->mode == QUIC_MODE_CLIENT ? "client" : "server", path_id, 
                local_ip, ntohs(local_addr->sin_port),
                peer_ip, ntohs(peer_addr->sin_port));


    struct iovec iov = { (void *)buf, size };
    char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0};
    struct msghdr msg = {
        .msg_name = (void *)peer_addr,
        .msg_namelen = sizeof(*peer_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf)
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type  = IP_PKTINFO;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(struct in_pktinfo));
    ((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst = local_addr->sin_addr;

    return sendmsg(ep->quic_fd, &msg, 0);
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
            api_enqueue_rx(ep, buf, (size_t)n);
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
    LOG_DEBUG("[quic] stream %lu write notify\n", (unsigned long)xqc_stream_id(strm)); 
    return 0; 
}

// QUIC connection callbacks
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    LOG_INFO("[quic] connection created\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return -1;
    ep->conn = conn;
    ep->max_dgram_id = 0;
    ep->dgram_id_mask = 0;
    ep->server_dgram_id = 0;
    ep->quic_dgram_id = 1;
    xqc_datagram_set_user_data(conn, ep);
    xqc_conn_set_alp_user_data(conn, ep);
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    LOG_INFO("[quic] connection closed\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (ep) {
        ep->conn = NULL;
        ep->stream = NULL;
    }
    return 0; 
}
static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    LOG_INFO("[quic] handshake finished\n");
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep) return;
    ep->conn = conn;
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

    LOG_DEBUG("[quic] datagram recv from peer\n");

    uint64_t net_val;
    memcpy(&net_val, data, sizeof(uint64_t));
    uint64_t remote_dgram_id = be64toh(net_val);

    if (!is_new_datagram(remote_dgram_id, &ep->max_dgram_id, &ep->dgram_id_mask)) {
        LOG_WARN("[quic] duplicate datagram %ld (<=%ld) recv\n", remote_dgram_id, ep->max_dgram_id);
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + 8;
    size_t payload_len = data_len - 8;

    api_enqueue_rx(ep, payload, payload_len);
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
    unsigned char buf[2000];
    struct sockaddr_in peer_addr, local_addr;
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    if (!ep) return;

    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct msghdr msg = {
        .msg_name = &peer_addr,
        .msg_namelen = sizeof(peer_addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };

    socklen_t local_len = sizeof(local_addr);
    ssize_t n = recvmsg(fd, &msg, 0);

    if (n > 0) {
        getsockname(fd, (struct sockaddr*)&local_addr, &local_len);

        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
                local_addr.sin_addr = pi->ipi_spec_dst; 
                break;
            }
        }

        xqc_engine_packet_process(ep->engine, buf, n,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, msg.msg_namelen,
                                  get_timestamp(), ep);
        xqc_engine_finish_recv(ep->engine);
    }
}

static void *event_loop_worker(void *arg) {
    quic_endpoint_t *ep = (quic_endpoint_t *)arg;
    event_base_dispatch(ep->eb);
    return NULL;
}

quic_endpoint_t *quic_client_start(const quic_client_config_t *config) {
    if (!config) return NULL;

    quic_endpoint_t *ep = calloc(1, sizeof(quic_endpoint_t));
    if (!ep) return NULL;

    ep->mode = QUIC_MODE_CLIENT;
    ep->qlog_file = fopen("client.qlog", "wb");
    ep->app_recv_cb = config->recv_cb;
    ep->app_user_data = config->user_data;
    ep->datagram_mode = config->enable_datagram;

    init_rx_worker(ep);

    xqc_conn_settings_t conn_settings = {
        .proto_version = XQC_VERSION_V1,
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

    ep->quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(ep->quic_fd, F_SETFL, O_NONBLOCK);
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
    const xqc_cid_t *cidp = xqc_connect(ep->engine, &conn_settings, NULL, 0, "localhost", 0,
                                        &conn_ssl_config, 
                                        (struct sockaddr*)&ep->peer_addrs[0], sizeof(ep->peer_addrs[0]),
                                        "raw", ep);
    if (!cidp) { free(ep); return NULL; }
    memcpy(&ep->cid, cidp, sizeof(ep->cid));

    pthread_create(&ep->thread, NULL, event_loop_worker, ep);
    return ep;
}

quic_endpoint_t *quic_server_start(const quic_server_config_t *config) {
    if (!config) return NULL;

    quic_endpoint_t *ep = calloc(1, sizeof(quic_endpoint_t));
    if (!ep) return NULL;

    ep->mode = QUIC_MODE_SERVER;
    ep->qlog_file = fopen("server.qlog", "wb");
    ep->app_recv_cb = config->recv_cb;
    ep->app_user_data = config->user_data;
    ep->datagram_mode = config->enable_datagram;

    /* Initialize RX worker thread on server */
    init_rx_worker(ep);

    ep->eb = event_base_new();

    xqc_config_t cfg;
    xqc_engine_get_default_config(&cfg, XQC_ENGINE_SERVER);

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
        .enable_multipath = 1,
        .mp_enable_reinjection = 0,
        .mp_ping_on = 1,
        .mp_ack_on_any_path = 0,
        .init_max_path_id = 4,
        .least_available_cid_count = 4,
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
    xqc_engine_register_alpn(ep->engine, "raw", 3, &ap_cbs, ep);

    ep->quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(ep->quic_fd, F_SETFL, O_NONBLOCK);
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

    pthread_create(&ep->thread, NULL, event_loop_worker, ep);
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

        return xqc_datagram_send(ep->conn, buf, len + 8, &ep->quic_dgram_id, 1);
    } else if (ep->stream) {
        return (int)xqc_stream_send(ep->stream, (unsigned char *)data, len, 0);
    }
    return -1;
}

void quic_endpoint_stop(quic_endpoint_t *ep) {
    if (!ep) return;

    ep->worker_running = 0;
    pthread_mutex_lock(&ep->rx_queue.lock);
    pthread_cond_broadcast(&ep->rx_queue.cond);
    pthread_mutex_unlock(&ep->rx_queue.lock);

    pthread_join(ep->worker_thread, NULL);
    pthread_mutex_destroy(&ep->rx_queue.lock);
    pthread_cond_destroy(&ep->rx_queue.cond);

    if (ep->eb) {
        event_base_loopbreak(ep->eb);
    }
    if (ep->thread) {
        pthread_join(ep->thread, NULL);
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
    if (ep->quic_fd >= 0) {
        close(ep->quic_fd);
        ep->quic_fd = -1;
    }

    if (ep->timer_ev) {
        event_free(ep->timer_ev);
        ep->timer_ev = NULL;
    }
    if (ep->eb) {
        event_base_free(ep->eb);
        ep->eb = NULL;
    }

    free(ep);
}