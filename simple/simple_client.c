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

#define MAX_PATHS 2

static struct event_base *eb = NULL;
static xqc_engine_t *engine = NULL;
static struct event *timer_ev = NULL;
static int sock_fd = -1;
static xqc_cid_t cid;
static xqc_stream_t *stream = NULL;

// ctx structure
typedef struct {
    xqc_engine_t *engine;
    int quic_fd;
    xqc_connection_t *conn;
    struct sockaddr_in path_addrs[MAX_PATHS];
    int num_paths;
    int next_path_idx;
    int udp_fd;
    int udp_port;
    struct sockaddr_in udp_client;
    int datagram;
    xqc_stream_t *stream;   // reusable stream for all UDP packets
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

    // recv from UDP socket
    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) {
            break;
        }
        ctx->udp_client = src_addr;
        // send to QUIC datagram API
        if (ctx->conn) {
            if (ctx->stream) {
                ssize_t sent = xqc_stream_send(ctx->stream, buf, n, 0);
                if (sent < 0) {
                    fprintf(stderr, "[client] xqc_stream_send failed: %zd\n", sent);
                }
            } else {
                // Datagram mode: send as datagram
                xqc_datagram_send(ctx->conn, buf, n, NULL, 1);
            }
        }
    }
}

// QUIC logging callback
static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) { printf("%.*s", (int)size, (char*)buf); }

// QUIC socket callbacks
static ssize_t write_socket(const unsigned char *buf, size_t size,
                            const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                            void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    return sendto(ctx->quic_fd, buf, size, 0, peer_addr, peer_addrlen);
}
static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                               void *user_data) { 
    printf("[client] write_socket_ex called for path_id %lu to %s:%d\n", path_id, 
           inet_ntoa(((struct sockaddr_in*)peer_addr)->sin_addr), ntohs(((struct sockaddr_in*)peer_addr)->sin_port));
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;  
    struct sockaddr_in *path_addr;
    // ignore QUIC provided addr, forward to correct path
    path_addr = &ctx->path_addrs[path_id];      
    return write_socket(buf, size, (const struct sockaddr *)path_addr, sizeof(*path_addr), user_data);
}

/* Certificate verification (accept self-signed) */
static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *conn_user_data) { return 1; }

// QUIC stream callbacks
static int stream_create_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_read_notify(xqc_stream_t *strm, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
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
    printf("[client] connection created\n");
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[client] connection closed\n");
    return 0; 
}
static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    printf("[client] handshake finished, proxy routing is now active.\n");
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    ctx->conn = conn;
    if (!ctx->datagram) {
        // Create a bidirectional stream (or unidirectional if you prefer)
        ctx->stream = xqc_stream_create(ctx->engine, &cid, NULL, user_data);
        if (ctx->stream) {
            printf("[client] stream %lu created \n", (unsigned long)xqc_stream_id(ctx->stream));
        } else {
            printf("[client] stream creation failed\n");
        }
    }
}

static void save_token_cb(const unsigned char *token, unsigned int token_len, void *user_data) { return; }
static void save_session_cb(const  char *data, size_t data_len, void *user_data) { return; }

// QUIC multipath callbacks
void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (ctx->next_path_idx < ctx->num_paths) {
        uint64_t new_path_id = 0;
        int ret = xqc_conn_create_path(ctx->engine, cid, &new_path_id, 0);
        if (ret == XQC_OK) {
            printf("[multipath] created path %lu for address %d\n", new_path_id, ctx->next_path_idx);
            ctx->next_path_idx++;
        } else {
            printf("[multipath] failed to create path for address %d: %d\n", ctx->next_path_idx, ret);
        }
    }
}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data) { return 0; }

// QUIC datagram callbacks
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    quic_ctx_t *ctx = g_proxy_ctx;
    if (ctx == NULL) {
        fprintf(stderr, "[proxy] Error: Global proxy context memory block is uninitialized!\n");
        return;
    }

    // if udp client, forward datagram
    if (ctx->udp_client.sin_port != 0) {
        // Push the payload back out to your local UDP client ('nc')
        sendto(ctx->udp_fd, data, data_len, 0, 
               (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client));
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) {}

static int register_alpn(xqc_engine_t *eng, quic_ctx_t *ctx) {
    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = conn_create_notify,
        .conn_close_notify = conn_close_notify,
        .conn_handshake_finished = conn_handshake_finished,
        /* Other fields are NULL (they exist but we don't set them) */
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
    return xqc_engine_register_alpn(eng, alpn, strlen(alpn), &ap_cbs, ctx);
}
static void set_event_timer(xqc_usec_t wake_after, void *user_data) {
    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(timer_ev, &tv);
}
static void engine_timer_cb(int fd, short what, void *arg) {
    quic_ctx_t *ctx = (quic_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);
}

// QUIC packet read callback
static void packet_read_cb(int fd, short what, void *arg) {
    unsigned char buf[1500];
    struct sockaddr_in peer_addr, local_addr;
    quic_ctx_t *ctx = (quic_ctx_t *)arg;
    socklen_t peer_len = sizeof(peer_addr), local_len = sizeof(local_addr);
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer_addr, &peer_len);
    if (n > 0) {
        getsockname(fd, (struct sockaddr*)&local_addr, &local_len);
        xqc_engine_packet_process(ctx->engine, buf, n,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, peer_len,
                                  get_timestamp(), NULL);
        xqc_engine_finish_recv(ctx->engine);
    }
}

int main(int argc, char *argv[]) {
    xqc_config_t cfg;
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_conn_settings_t conn_settings = {0};
    xqc_conn_ssl_config_t conn_ssl_config = {0};
    xqc_engine_callback_t eng_cb = {0};
    xqc_transport_callbacks_t trans_cb = {0};
    
    // initialize global QUIC context
    quic_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    g_proxy_ctx = &ctx;

    // default configs
    conn_settings.max_datagram_frame_size = 0;
    conn_settings.datagram_force_retrans_on = 0;
    conn_settings.enable_experimental_redundancy = 0;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    ctx.num_paths = 0;
    ctx.next_path_idx = 1;
    ctx.udp_port = 7778;

    int opt;
    while ((opt = getopt(argc, argv, "u:d:r:s:p:")) != -1) {
        switch (opt) {
            case 'u':
                ctx.udp_port = atoi(optarg);
                break;
            case 'd': 
                conn_settings.max_datagram_frame_size = 65535; 
                conn_settings.datagram_force_retrans_on = 0; 
                ctx.datagram = 1;
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
            case 'p': 
                if (ctx.num_paths < MAX_PATHS) {
                    struct sockaddr_in *addr = &ctx.path_addrs[ctx.num_paths++];
                    memset(addr, 0, sizeof(*addr));
                    addr->sin_family = AF_INET;
                    addr->sin_port = htons(8000);   // port is fixed (8000)
                    if (inet_pton(AF_INET, optarg, &addr->sin_addr) <= 0) {
                        fprintf(stderr, "Invalid address: %s\n", optarg);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "Too many addresses, max %d\n", MAX_PATHS);
                    return 1;
                }
                break;
        }
    }

    printf("[client] starting\n");
    eb = event_base_new();
    if (!eb) return -1;

    xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT);
    cfg.cfg_log_level = XQC_LOG_INFO;

    // define QUIC engine callbacks
    eng_cb.set_event_timer = set_event_timer;
    eng_cb.log_callbacks.xqc_log_write_err = log_write;
    eng_cb.log_callbacks.xqc_log_write_stat = log_write;

    // define QUIC transport callbacks
    trans_cb.write_socket = write_socket;
    trans_cb.write_socket_ex = write_socket_ex;
    trans_cb.cert_verify_cb = cert_verify_cb;
    trans_cb.save_token = save_token_cb;
    trans_cb.save_session_cb = save_session_cb;
    trans_cb.ready_to_create_path_notify = ready_to_create_path_notify;
    trans_cb.path_created_notify = path_created_notify;

    // define SSL/TLS settings
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    // create QUIC engine
    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &cfg, &ssl_cfg, &eng_cb, &trans_cb, &ctx);
    if (!ctx.engine) { fprintf(stderr, "Engine creation failed\n"); return -1; }
    printf("quic engine created\n");
    if (register_alpn(ctx.engine, &ctx) != 0) { fprintf(stderr, "ALPN registration failed\n"); return -1; }

    // create QUIC socket
    ctx.quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.quic_fd < 0) return -1;
    fcntl(ctx.quic_fd, F_SETFL, O_NONBLOCK);

    // add QUIC socket to libevent loop
    struct event *sock_ev = event_new(eb, ctx.quic_fd, EV_READ | EV_PERSIST, packet_read_cb, &ctx);
    event_add(sock_ev, NULL);
    
    // create UDP socket
    ctx.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.udp_fd < 0) return -1;
    fcntl(ctx.udp_fd, F_SETFL, O_NONBLOCK);
    memset(&ctx.udp_client, 0, sizeof(ctx.udp_client));
    struct sockaddr_in proxy_local_addr;
    memset(&proxy_local_addr, 0, sizeof(proxy_local_addr));
    proxy_local_addr.sin_family = AF_INET;
    proxy_local_addr.sin_port = htons(ctx.udp_port);
    proxy_local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(ctx.udp_fd, (struct sockaddr *)&proxy_local_addr, sizeof(proxy_local_addr));

    // add UDP socket to libevent loop
    struct event *proxy_ev = event_new(eb, ctx.udp_fd, EV_READ | EV_PERSIST, proxy_udp_read_cb, &ctx);
    event_add(proxy_ev, NULL);
    printf("[proxy] Listening for external UDP traffic on port %d...\n", ctx.udp_port);

    // add QUIC engine timer to libevent loop
    timer_ev = event_new(eb, -1, 0, engine_timer_cb, &ctx);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);

    // define QUIC connection settings
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_enable_reinjection = 0;
    conn_settings.mp_ping_on = 1;

    // connect to QUIC server
    const xqc_cid_t *cidp = xqc_connect(ctx.engine, &conn_settings, NULL, 0, "localhost", 0,
                                        &conn_ssl_config, 
                                        (struct sockaddr*)&ctx.path_addrs[0], sizeof(ctx.path_addrs[0]),
                                        "raw", &ctx);
    if (!cidp) {
        fprintf(stderr, "xqc_connect failed\n");
        return -1;
    }
    memcpy(&cid, cidp, sizeof(cid));
    printf("Connection initiated\n");

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    close(ctx.quic_fd);
    close(ctx.udp_fd);
    event_base_free(eb);
    return 0;
}