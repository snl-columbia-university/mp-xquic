#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <event2/event.h>
#include <xquic/xquic.h>

// config
#define BACKEND_IP "127.0.0.1"
#define BACKEND_PORT 7779

static struct event_base *eb = NULL;
static struct event *timer_ev = NULL;

// ctx structure
typedef struct {
    xqc_engine_t *engine;
    int quic_fd;
    xqc_connection_t *conn;
    int udp_fd;
    struct sockaddr_in udp_client;
    int datagram;
    xqc_stream_t *stream;
} quic_ctx_t;
static quic_ctx_t *g_proxy_ctx = NULL;

static xqc_usec_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

// UDP socket callback
static void proxy_udp_read_cb(int fd, short what, void *arg) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    unsigned char buf[1500];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) break;

        if (ctx->conn) {
            if (ctx->stream) {
                ssize_t sent = xqc_stream_send(ctx->stream, buf, n, 0);
                if (sent < 0) {
                    fprintf(stderr, "[server-proxy] xqc_stream_send failed: %zd\n", sent);
                }
            } else {
                xqc_datagram_send(ctx->conn, buf, n, NULL, 1);
            }
        }
    }
}

// QUIC logging callback
static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) {
    printf("%.*s", (int)size, (char*)buf);
}

// QUIC socket callbacks
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    return sendto(ctx->quic_fd, buf, size, 0, peer_addr, peer_addrlen);
}

static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                               void *user_data) {
    printf("[server] write_socket_ex called for path_id %lu to %s:%d\n", path_id, 
           inet_ntoa(((struct sockaddr_in*)peer_addr)->sin_addr), ntohs(((struct sockaddr_in*)peer_addr)->sin_port));
    return write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}

// QUIC server accept callback
static int server_accept(xqc_engine_t *eng, xqc_connection_t *conn,
                         const xqc_cid_t *cid, void *user_data) {
    
    printf("[server] new connection accepted\n");
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    if (!ctx) {
        return -1;
    }
    ctx->conn = conn;

    // create UDP socket
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

        // add UDP socket to libevent loop
        struct event *proxy_ev = event_new(eb, ctx->udp_fd, EV_READ | EV_PERSIST, proxy_udp_read_cb, ctx);
        event_add(proxy_ev, NULL);
        printf("[server-proxy] listening for external backend traffic on port 6000...\n");
    }
    memset(&ctx->udp_client, 0, sizeof(ctx->udp_client));
    ctx->udp_client.sin_family = AF_INET;
    ctx->udp_client.sin_port = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &ctx->udp_client.sin_addr);

    // save global ctx
    g_proxy_ctx = ctx;

    xqc_conn_set_alp_user_data(conn, ctx);

    return 0;
}

static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                          size_t certs_len, void *conn_user_data) {
    return 1;
}

// QUIC stream callbacks
static int stream_create_notify(xqc_stream_t *strm, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    if (ctx) {
        xqc_stream_set_user_data(strm, ctx);
        ctx->stream = strm;           // remember this stream for sending replies
        printf("[client] stream %lu created by peer\n", (unsigned long)xqc_stream_id(strm));
    }
    return 0;
}
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_read_notify(xqc_stream_t *strm, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    if (!ctx) return 0;

    unsigned char buf[1500];
    uint8_t fin = 0;
    while (1) {
        ssize_t n = xqc_stream_recv(strm, buf, sizeof(buf), &fin);
        if (n > 0) {
            if (ctx->udp_client.sin_port != 0) {
                sendto(ctx->udp_fd, buf, n, 0,
                       (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client));
            }
        } else if (fin) {          // FIN received
            printf("[client] stream %lu closed by peer\n", (unsigned long)xqc_stream_id(strm));
            break;
        } else if (n == -XQC_EAGAIN) {
            break;                    // no more data for now
        } else {
            fprintf(stderr, "[client] xqc_stream_read error: %zd\n", n);
            break;
        }
    }
    return 0;
}
static int stream_write_notify(xqc_stream_t *strm, void *user_data) { return 0; }

// QUIC connection callbacks
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    ctx->conn = conn;
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[server] connection closed\n");
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
    printf("[server] handshake finished\n");
}

// QUIC datagram callbacks
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    quic_ctx_t *ctx = g_proxy_ctx;
    if (ctx == NULL) {
        fprintf(stderr, "[server-proxy] Error: Global target proxy context is uninitialized!\n");
        return;
    }

    // if udp client, forward datagram
    if (ctx->udp_client.sin_port != 0) {
        ssize_t sent = sendto(ctx->udp_fd, data, data_len, 0, 
                              (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client));
        if (sent < 0) {
            fprintf(stderr, "[server-proxy] sendto failed with error: %s\n", strerror(errno));
        }
    } else {
        printf("[server-proxy] warning: No proxy target destination structure active.\n");
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) {}

// QUIC multipath callbacks
void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data){  
    printf("[multipath] sub-path %lu established successfully.\n", path_id);
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
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    xqc_engine_main_logic(ctx->engine);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);
}

// QUIC packet read callback
static void packet_read_cb(int fd, short what, void *arg) {
    unsigned char buf[1500];
    struct sockaddr_in peer_addr, local_addr;
    socklen_t local_len = sizeof(local_addr);
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;

    // parse dst addr of incoming packet
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

        xqc_engine_packet_process(ctx->engine, buf, n,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, msg.msg_namelen,
                                  get_timestamp(), NULL);
        xqc_engine_finish_recv(ctx->engine);
    }
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -d            Enable datagram mode (sets max_datagram_frame_size)\n"
        "  -r            Enable experimental redundancy\n"
        "  -s <sched>    Select scheduler: pmp (proactive multipath),\n"
        "                psp (proactive singlepath), minrtt (default)\n"
        "  -h            Show this help\n"
        "\n"
        "Example:\n"
        "  %s -d -r -s pmp\n",
        progname, progname
    );
}

int main(int argc, char *argv[]) {
    xqc_config_t cfg;
    xqc_conn_settings_t conn_settings = {0};
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_engine_callback_t eng_cb = {0};
    xqc_transport_callbacks_t trans_cb = {0};
    struct sockaddr_in addr;

    // initialize global QUIC context
    quic_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    g_proxy_ctx = &ctx;

    // default configs
    conn_settings.max_datagram_frame_size = 0;
    conn_settings.datagram_force_retrans_on = 0;
    conn_settings.enable_experimental_redundancy = 0;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;


    if (argc == 1) {
        usage(argv[0]);
        return 1;
    }

    int opt;
    while ((opt = getopt(argc, argv, "drs:h:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                return 0; 
            case 'd': 
                conn_settings.max_datagram_frame_size = 65535; 
                conn_settings.datagram_force_retrans_on = 0; 
                break;
            case 'r': conn_settings.enable_experimental_redundancy = 1; break;
            case 's': 
                if (strcmp(optarg, "pmp") == 0) {
                    conn_settings.scheduler_callback = xqc_proactive_multipath_scheduler_cb;
                } else if (strcmp(optarg, "psp") == 0) {
                    conn_settings.scheduler_callback = xqc_proactive_singlepath_scheduler_cb;
                } else {
                    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
                }
                break;
            default:
                usage(argv[0]);
                return 0;
        }
    }

    printf("[server] starting\n");
    eb = event_base_new();
    if (!eb) return -1;

    xqc_engine_get_default_config(&cfg, XQC_ENGINE_SERVER);
    cfg.cfg_log_level = XQC_LOG_INFO;
    eng_cb.set_event_timer = set_event_timer;

    // define QUIC engine callbacks
    eng_cb.log_callbacks.xqc_log_write_err = log_write;
    eng_cb.log_callbacks.xqc_log_write_stat = log_write;

    // define QUIC transport callbacks
    trans_cb.server_accept = server_accept;
    trans_cb.write_socket = write_socket;
    trans_cb.write_socket_ex = write_socket_ex;
    trans_cb.cert_verify_cb = cert_verify_cb;
    trans_cb.ready_to_create_path_notify = ready_to_create_path_notify;
    trans_cb.path_created_notify = path_created_notify;

    // define SSL config
    ssl_cfg.private_key_file = "server.key";
    ssl_cfg.cert_file = "server.crt";
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    // define QUIC connection settings
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_enable_reinjection = 0;
    conn_settings.mp_ping_on = 1;

    // create QUIC engine
    ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &cfg, &ssl_cfg, &eng_cb, &trans_cb, NULL);
    if (!ctx.engine) { fprintf(stderr, "Engine creation failed\n"); return -1; }
    printf("engine created\n");
    xqc_server_set_conn_settings(ctx.engine, &conn_settings);
    if (register_alpn(ctx.engine) != 0) { fprintf(stderr, "ALPN registration failed\n"); return -1; }

    // create QUIC socket
    ctx.quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.quic_fd < 0) return -1;
    fcntl(ctx.quic_fd, F_SETFL, O_NONBLOCK);
    int reuse = 1;
    setsockopt(ctx.quic_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int pktinfo = 1;
    setsockopt(ctx.quic_fd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8000);
    if (bind(ctx.quic_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return -1; }
    printf("listening on port %d\n", 8000);

    // add QUIC socket to libevent loop
    struct event *sock_ev = event_new(eb, ctx.quic_fd, EV_READ | EV_PERSIST, packet_read_cb, NULL);
    event_add(sock_ev, NULL);

    // add engine timer to libevent loop
    timer_ev = event_new(eb, -1, 0, engine_timer_cb, NULL);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    close(ctx.quic_fd);
    close(ctx.udp_fd);
    event_base_free(eb);
    return 0;
}