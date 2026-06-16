#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <event2/event.h>
#include <xquic/xquic.h>

#define PORT 8443
#define MAX_MSG 1024

/* Target configuration for the hardcoded backend service */
#define BACKEND_IP "127.0.0.1"
#define BACKEND_PORT 7778

#define QUIC_PORT 8000

static struct event_base *eb = NULL;
static xqc_engine_t *engine = NULL;
static struct event *timer_ev = NULL;
static int listen_fd = -1;

typedef struct {
    xqc_engine_t *engine;
    int quic_fd;
    xqc_connection_t *conn;
    int udp_fd;
    struct sockaddr_in udp_client;
} quic_ctx_t;

/* Global reference pointer to track active proxy context across data-plane handlers */
static quic_ctx_t *g_proxy_ctx = NULL;

static xqc_usec_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Asynchronous handler for incoming third-party UDP traffic from backend service */
static void proxy_udp_read_cb(int fd, short what, void *arg) {
    quic_ctx_t *ctx = (quic_ctx_t *)arg;
    unsigned char buf[1500];
    struct sockaddr_in src_addr;

    // Drain the local UDP socket
    while (1) {
        socklen_t src_len = sizeof(src_addr);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) {
            break; 
        }

        // If the MPQUIC path tunnel is established, pipe it straight out
        if (ctx->conn) {
            xqc_datagram_send(ctx->conn, buf, n, NULL, 1);
        }
    }
}

static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) {
    printf("%.*s", (int)size, (char*)buf);
}

static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) {
    return sendto(listen_fd, buf, size, 0, peer_addr, peer_addrlen);
}

static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                               void *user_data) {
    return write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}

static int server_accept(xqc_engine_t *eng, xqc_connection_t *conn,
                         const xqc_cid_t *cid, void *user_data) {
    printf("[server] New connection accepted\n");

    // Instantiation: Allocate memory for context on new client tunnel connection
    quic_ctx_t *ctx = malloc(sizeof(quic_ctx_t));
    if (!ctx) {
        return -1;
    }
    memset(ctx, 0, sizeof(quic_ctx_t));
    ctx->engine = eng;
    ctx->conn = conn;

    ctx->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->udp_fd >= 0) {
        fcntl(ctx->udp_fd, F_SETFL, O_NONBLOCK);
        struct sockaddr_in proxy_local_addr;
        memset(&proxy_local_addr, 0, sizeof(proxy_local_addr));
        proxy_local_addr.sin_family = AF_INET;
        proxy_local_addr.sin_port = htons(0); 
        proxy_local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        
        if (bind(ctx->udp_fd, (struct sockaddr *)&proxy_local_addr, sizeof(proxy_local_addr)) < 0) {
            perror("[server-proxy] bind backend proxy port failed");
        }

        // Add back to event base to capture incoming backend traffic
        struct event *proxy_ev = event_new(eb, ctx->udp_fd, EV_READ | EV_PERSIST, proxy_udp_read_cb, ctx);
        event_add(proxy_ev, NULL);
        printf("[server-proxy] Listening for external backend traffic on port 6000...\n");
    }

    /* FIX: Explicitly hardcode the default backend target address variables here */
    memset(&ctx->udp_client, 0, sizeof(ctx->udp_client));
    ctx->udp_client.sin_family = AF_INET;
    ctx->udp_client.sin_port = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &ctx->udp_client.sin_addr);
    printf("[server-proxy] Hardcoded backend target set to %s:%d\n", BACKEND_IP, BACKEND_PORT);

    // Cache to global reference to safeguard layer callbacks
    g_proxy_ctx = ctx;

    // Bind instance inside connection's internal ALPN layer data structures
    xqc_conn_set_alp_user_data(conn, ctx);

    return 0;
}

static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                          size_t certs_len, void *conn_user_data) {
    return 1;
}

static int stream_create_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_read_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_write_notify(xqc_stream_t *strm, void *user_data) { return 0; }

static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { return 0; }
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[server] Connection closed\n");
    quic_ctx_t *ctx = g_proxy_ctx;
    if (ctx) {
        if (ctx->udp_fd >= 0) close(ctx->udp_fd);
        free(ctx);
    }
    if (g_proxy_ctx == ctx) {
        g_proxy_ctx = NULL;
    }
    return 0; 
}

static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    printf("[server] Handshake finished\n");
}

/* Forwards packet payload received over QUIC straight to your hardcoded Netcat backend */
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    printf("[server] Received %zd bytes over MPQUIC tunnel: %.*s\n", data_len, (int)data_len, (char*)data);
    
    // Read from the active cached proxy context pointer safely
    quic_ctx_t *ctx = g_proxy_ctx;

    if (ctx == NULL) {
        fprintf(stderr, "[server-proxy] Error: Global target proxy context is uninitialized!\n");
        return;
    }

    // Forward down to backend target structure initialized in server_accept
    if (ctx->udp_client.sin_port != 0) {
        printf("[server-proxy] Routing reply back out through UDP port 6000 to hardcoded backend target port %d...\n", 
               ntohs(ctx->udp_client.sin_port));
        
        ssize_t sent = sendto(ctx->udp_fd, data, data_len, 0, 
                              (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client));
        if (sent < 0) {
            fprintf(stderr, "[server-proxy] sendto failed with error: %s\n", strerror(errno));
        }
    } else {
        printf("[server-proxy] Warning: No proxy target destination structure active.\n");
    }
}

static void datagram_write_notify(xqc_connection_t *conn, void *user_data) {}

void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data){  
    printf("[multipath] Sub-path %lu established successfully.\n", path_id);
    return 0;
}

static int register_alpn(xqc_engine_t *eng) {
    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = conn_create_notify,
        .conn_close_notify = conn_close_notify,
        .conn_handshake_finished = conn_handshake_finished,
    };
    xqc_stream_callbacks_t stream_cbs = {
        .stream_create_notify = stream_create_notify,
        .stream_close_notify = stream_close_notify,
        .stream_read_notify = stream_read_notify,
        .stream_write_notify = stream_write_notify,
    };
    xqc_datagram_callbacks_t dgram_cbs = {
        .datagram_read_notify = datagram_read_notify,
        .datagram_write_notify = datagram_write_notify,
    };
    xqc_app_proto_callbacks_t ap_cbs = {
        .conn_cbs = conn_cbs,
        .stream_cbs = stream_cbs,
        .dgram_cbs = dgram_cbs,
    };
    const char *alpn = "raw";
    return xqc_engine_register_alpn(eng, alpn, strlen(alpn), &ap_cbs, NULL);
}

static void set_event_timer(xqc_usec_t wake_after, void *user_data) {
    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(timer_ev, &tv);
}

static void engine_timer_cb(int fd, short what, void *arg) {
    xqc_engine_main_logic(engine);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);
}

static void packet_read_cb(int fd, short what, void *arg) {
    unsigned char buf[1500];
    struct sockaddr_in peer_addr, local_addr;
    socklen_t local_len = sizeof(local_addr);

    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &peer_addr;
    msg.msg_namelen = sizeof(peer_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

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

        xqc_engine_packet_process(engine, buf, n,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, msg.msg_namelen,
                                  get_timestamp(), NULL);
        xqc_engine_finish_recv(engine);
    }
}

int main(void) {
    xqc_config_t cfg;
    xqc_conn_settings_t conn_settings = {0};
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_engine_callback_t eng_cb = {0};
    xqc_transport_callbacks_t trans_cb = {0};
    struct sockaddr_in addr;

    printf("[server] Starting\n");
    eb = event_base_new();
    if (!eb) return -1;

    xqc_engine_get_default_config(&cfg, XQC_ENGINE_SERVER);
    cfg.cfg_log_level = XQC_LOG_INFO;
    eng_cb.set_event_timer = set_event_timer;
    eng_cb.log_callbacks.xqc_log_write_err = log_write;
    eng_cb.log_callbacks.xqc_log_write_stat = log_write;

    trans_cb.server_accept = server_accept;
    trans_cb.write_socket = write_socket;
    trans_cb.write_socket_ex = write_socket_ex;
    trans_cb.cert_verify_cb = cert_verify_cb;
    trans_cb.ready_to_create_path_notify = ready_to_create_path_notify;
    trans_cb.path_created_notify = path_created_notify;

    ssl_cfg.private_key_file = "server.key";
    ssl_cfg.cert_file = "server.crt";
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.mp_enable_reinjection = 7;
    conn_settings.reinj_ctl_callback = xqc_dgram_reinj_ctl_cb;
    conn_settings.mp_ping_on = 1;

    engine = xqc_engine_create(XQC_ENGINE_SERVER, &cfg, &ssl_cfg, &eng_cb, &trans_cb, NULL);
    if (!engine) { fprintf(stderr, "Engine creation failed\n"); return -1; }
    printf("Engine created\n");

    xqc_server_set_conn_settings(engine, &conn_settings);

    if (register_alpn(engine) != 0) { fprintf(stderr, "ALPN registration failed\n"); return -1; }

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) return -1;
    fcntl(listen_fd, F_SETFL, O_NONBLOCK);
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int opt = 1;
    setsockopt(listen_fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(QUIC_PORT);
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return -1; }
    printf("Listening on port %d\n", QUIC_PORT);

    struct event *sock_ev = event_new(eb, listen_fd, EV_READ | EV_PERSIST, packet_read_cb, NULL);
    event_add(sock_ev, NULL);
    timer_ev = event_new(eb, -1, 0, engine_timer_cb, NULL);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);

    event_base_dispatch(eb);

    xqc_engine_destroy(engine);
    close(listen_fd);
    event_base_free(eb);
    return 0;
}