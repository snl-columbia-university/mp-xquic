#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <endian.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <event2/event.h>
#include <xquic/xquic.h>

#define MAX_PATHS 4

static struct event_base *eb = NULL;
static struct event *timer_ev = NULL;
static xqc_cid_t cid;

// ctx structure
typedef struct {
    xqc_engine_t *engine;
    int quic_fds[MAX_PATHS];
    xqc_connection_t *conn;
    struct sockaddr_in peer_addrs[MAX_PATHS];
    int num_peer_addrs;
    struct sockaddr_in local_addrs[MAX_PATHS];
    int num_local_addrs;
    int num_paths;
    int udp_fd;
    int udp_port;
    struct sockaddr_in udp_client;
    uint64_t quic_dgram_id;
    uint64_t client_dgram_id;
    uint64_t max_dgram_id;
    uint64_t dgram_id_mask;
    xqc_stream_t *stream;
} quic_ctx_t;

static xqc_usec_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

// UDP socket callback
static void proxy_udp_read_cb(int fd, short what, void *arg) {
    quic_ctx_t *ctx = (quic_ctx_t *)arg;
    if (!ctx) {return;}
    unsigned char buf[2000];
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
                    fprintf(stderr, "[client-quic] xqc_stream_send failed: %zd\n", sent);
                }
            } else {
                printf("[client-proxy] datagram recieved over udp\n");
                memmove(buf + 8, buf, n);
                uint64_t net_val = htobe64(ctx->client_dgram_id);
                memcpy(buf, &net_val, sizeof(uint64_t));
                int err = xqc_datagram_send(ctx->conn, buf, n + sizeof(uint64_t), &ctx->quic_dgram_id, 1);
                if (err < 0){ printf("[client-quic] datagram send error %i, %ld\n", err, xqc_datagram_get_mss(ctx->conn)); return;};
                printf("[client-quic] datagram quic=%ld, server=%ld forwarded over quic\n", ctx->quic_dgram_id, ctx->client_dgram_id);
                ctx->client_dgram_id++;
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
    int quic_fd = *((int *)user_data);
    return sendto(quic_fd, buf, size, 0, peer_addr, peer_addrlen);
}
static ssize_t write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                               const struct sockaddr *_peer_addr, socklen_t _peer_addrlen,
                               void *user_data) { 
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (!ctx) {return -1;}
    struct sockaddr_in *peer_addr;
    struct sockaddr_in *local_addr;
    int *quic_fd;

    peer_addr = &ctx->peer_addrs[(path_id / ctx->num_local_addrs) % ctx->num_peer_addrs];
    local_addr = &ctx->local_addrs[path_id % ctx->num_local_addrs];
    quic_fd = &ctx->quic_fds[path_id % ctx->num_local_addrs];

    char local_ip[INET_ADDRSTRLEN];
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr->sin_addr, local_ip, sizeof(local_ip));
    inet_ntop(AF_INET, &peer_addr->sin_addr, peer_ip, sizeof(peer_ip));

    printf("[client-quic] write_socket_ex called for path_id %lu from %s:%d to %s:%d\n", 
           path_id, 
           local_ip, ntohs(local_addr->sin_port),
           peer_ip, ntohs(peer_addr->sin_port));
    return write_socket(buf, size, (const struct sockaddr *)peer_addr, sizeof(*peer_addr), quic_fd);
}

/* Certificate verification (accept self-signed) */
static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *conn_user_data) { return 1; }

// QUIC stream callbacks
static int stream_create_notify(xqc_stream_t *strm, void *user_data) { printf("[client-quic] stream %lu created\n", (unsigned long)xqc_stream_id(strm)); return 0; }
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { printf("[client-quic] stream %lu closed\n", (unsigned long)xqc_stream_id(strm)); return 0; }
static int stream_read_notify(xqc_stream_t *strm, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (!ctx) {return -1;}
    unsigned char buf[2000];
    uint8_t fin = 0;
    while (1) {
        ssize_t n = xqc_stream_recv(strm, buf, sizeof(buf), &fin);
        printf("[client-quic] stream_read_notify called for stream %lu, received %zd bytes\n", (unsigned long)xqc_stream_id(strm), n);
        if (n > 0) {
            if (ctx->udp_client.sin_port != 0) {
                sendto(ctx->udp_fd, buf, n, 0,
                       (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client));
            }
        } else if (fin) {          // FIN received
            printf("[client-quic] stream %lu closed by peer\n", (unsigned long)xqc_stream_id(strm));
            break;
        } else if (n == -XQC_EAGAIN) {
            break;                    // no more data for now
        } else {
            fprintf(stderr, "[client-quic] xqc_stream_read error: %zd\n", n);
            break;
        }
    }
    return 0;
}
static int stream_write_notify(xqc_stream_t *strm, void *user_data) { printf("[client-quic] stream %lu sent to server\n", (unsigned long)xqc_stream_id(strm)); return 0; }

// QUIC connection callbacks
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[client-quic] connection created\n");
    xqc_datagram_set_user_data(conn, user_data);
    xqc_conn_set_alp_user_data(conn, user_data);
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[client-quic] connection closed\n");
    return 0; 
}
static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    printf("[client-quic] handshake finished, proxy routing is now active.\n");
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (!ctx) {return;}
    ctx->conn = conn;
    if (!ctx->quic_dgram_id) {
        // Create a bidirectional stream (or unidirectional if you prefer)
        ctx->stream = xqc_stream_create(ctx->engine, &cid, NULL, user_data);
        if (ctx->stream) {
            printf("[client-quic] stream %lu created \n", (unsigned long)xqc_stream_id(ctx->stream));
        } else {
            printf("[client-quic] stream creation failed\n");
        }
    }
}

static void save_token_cb(const unsigned char *token, unsigned int token_len, void *user_data) { return; }
static void save_session_cb(const  char *data, size_t data_len, void *user_data) { return; }

// QUIC multipath callbacks
void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {
    printf("[client-multipath] ready to create new path\n");
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (!ctx) {return;}
    while(ctx->num_paths < ctx->num_local_addrs * ctx->num_peer_addrs && ctx->num_paths < MAX_PATHS) {
        uint64_t new_path_id = 0;
        int ret = xqc_conn_create_path(ctx->engine, cid, &new_path_id, 0);
        if (ret == XQC_OK) {
            printf("[client-multipath] created path %lu\n", new_path_id);
            ctx->num_paths++;
        } else {
            printf("[client-multipath] failed to create path for address %d: %d\n", ctx->num_paths, ret);
            break;
        }
    }
}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data) { return 0; }

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

// QUIC datagram callbacks
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    quic_ctx_t *ctx = (quic_ctx_t *)user_data;
    if (!ctx) {return;}

    // if udp client, forward datagram
    printf("[client-quic] datagram recv from server\n");
    if (ctx->udp_fd && ctx->udp_client.sin_port != 0) {
        // Push the payload back out to your local UDP client
        uint64_t net_val;
        memcpy(&net_val, data, sizeof(uint64_t));
        uint64_t server_datagram_id = be64toh(net_val);

        if (!is_new_datagram(server_datagram_id, &ctx->max_dgram_id, &ctx->dgram_id_mask)) {
            printf("[client-quic] duplicate datagram %ld (<=%ld) recv from server\n", server_datagram_id, ctx->max_dgram_id); 
            return;
        }

        if (sendto(ctx->udp_fd, (const unsigned char *)data + 8, data_len - 8, 0, (struct sockaddr*)&ctx->udp_client, sizeof(ctx->udp_client)) < 0) {
            printf("[client-proxy] sendto failed with error: %s\n", strerror(errno));   
        } else { 
            printf("[client-proxy] datagram %ld forwarded to udp\n", server_datagram_id); 
        }
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) {printf("[client-quic] datagram sent to server\n");}
static void datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { printf("[client-quic] datagram %ld acked\n", dgram_id);}
static xqc_int_t datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { 
    printf("[client-quic] datagram %ld lost\n", dgram_id); 
    return XQC_DGRAM_RETX_ASKED_BY_APP;
}

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
        .datagram_lost_notify = datagram_lost_notify,
        .datagram_acked_notify = datagram_acked_notify,
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
    if (!ctx) {return;}
    xqc_engine_main_logic(ctx->engine);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);
}

// QUIC packet read callback
static void packet_read_cb(int fd, short what, void *arg) {
    unsigned char buf[2000];
    struct sockaddr_in peer_addr, local_addr;
    quic_ctx_t *ctx = (quic_ctx_t *)arg;
    if (!ctx) {return;}
    socklen_t peer_len = sizeof(peer_addr), local_len = sizeof(local_addr);
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer_addr, &peer_len);
    if (n > 0) {
        getsockname(fd, (struct sockaddr*)&local_addr, &local_len);
        xqc_engine_packet_process(ctx->engine, buf, n,
                                  (struct sockaddr*)&local_addr, local_len,
                                  (struct sockaddr*)&peer_addr, peer_len,
                                  get_timestamp(), ctx);
        xqc_engine_finish_recv(ctx->engine);
    }
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -u <port>     Set local UDP port (client only, default 7778)\n"
        "  -d            Enable datagram mode (sets max_datagram_frame_size)\n"
        "  -r            Enable experimental redundancy\n"
        "  -s <sched>    Select scheduler: pmp (proactive multipath),\n"
        "                psp (proactive singlepath), minrtt (default)\n"
        "  -l <ip>       Set local address (can be repeated, client only)\n"
        "  -p <ip>       Add peer address (can be repeated, client only)\n"
        "  -h            Show this help\n"
        "\n"
        "Example:\n"
        "  %s -d -r -s pmp -p 127.0.0.1 -p 127.0.0.2\n",
        progname, progname
    );
}

int main(int argc, char *argv[]) {
    xqc_config_t cfg;
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_conn_settings_t conn_settings = {0};
    xqc_conn_ssl_config_t conn_ssl_config = {0};
    xqc_engine_callback_t eng_cb = {0};
    xqc_transport_callbacks_t trans_cb = {0};
    
    // initialize QUIC context
    quic_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    // define QUIC connection settings
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_enable_reinjection = 0;
    conn_settings.mp_ping_on = 1;
    conn_settings.init_max_path_id = MAX_PATHS;
    conn_settings.max_datagram_frame_size = 0;
    conn_settings.datagram_force_retrans_on = 0;
    conn_settings.enable_experimental_redundancy = 0;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    ctx.num_local_addrs = 0;
    ctx.num_peer_addrs = 0;
    ctx.num_paths = 1;
    ctx.udp_port = 7778;

    int opt;
    while ((opt = getopt(argc, argv, "u:drs:l:p:h")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
            return 0;
            case 'u':
                ctx.udp_port = atoi(optarg);
                break;
            case 'd': 
                conn_settings.max_datagram_frame_size = 65535; 
                conn_settings.max_udp_payload_size = 65527;
                conn_settings.max_pkt_out_size = 2000;
                conn_settings.datagram_force_retrans_on = 0; 
                ctx.quic_dgram_id = 1;
                ctx.client_dgram_id = 0;
                ctx.max_dgram_id = 0;
                break;
            case 'r': conn_settings.enable_experimental_redundancy = 1; break;
            case 's': 
                if (strcmp(optarg, "pmp") == 0) {
                    conn_settings.scheduler_callback = xqc_proactive_multipath_scheduler_cb;
                } else if (strcmp(optarg, "psp") == 0) {
                    conn_settings.scheduler_callback = xqc_proactive_singlepath_scheduler_cb;
                } else if (strcmp(optarg, "rmp") == 0) {
                    conn_settings.scheduler_callback = xqc_reactive_multipath_scheduler_cb;
                } else if (strcmp(optarg, "spmp") == 0) {
                    conn_settings.scheduler_callback = xqc_smart_proactive_multipath_scheduler_cb;
                } else {
                    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
                }
                break;
            case 'l': 
                if (ctx.num_local_addrs < MAX_PATHS) {
                    struct sockaddr_in *addr = &ctx.local_addrs[ctx.num_local_addrs++];
                    memset(addr, 0, sizeof(*addr));
                    addr->sin_family = AF_INET;
                    addr->sin_port = htons(0);
                    if (inet_pton(AF_INET, optarg, &addr->sin_addr) <= 0) {
                        fprintf(stderr, "[client-quic] invalid address: %s\n", optarg);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "[client-quic] too many addresses, max %d\n", MAX_PATHS);
                    return 1;
                }
                break;
            case 'p': 
                if (ctx.num_peer_addrs < MAX_PATHS) {
                    struct sockaddr_in *addr = &ctx.peer_addrs[ctx.num_peer_addrs++];
                    memset(addr, 0, sizeof(*addr));
                    addr->sin_family = AF_INET;
                    addr->sin_port = htons(8000);
                    if (inet_pton(AF_INET, optarg, &addr->sin_addr) <= 0) {
                        fprintf(stderr, "[client-quic] invalid address: %s\n", optarg);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "[client-quic] too many addresses, max %d\n", MAX_PATHS);
                    return 1;
                }
                break;
            default:
                usage(argv[0]);
                return 0;
        }
    }
    printf("[client-quic] starting\n");
    eb = event_base_new();
    if (!eb) return -1;

    xqc_engine_get_default_config(&cfg, XQC_ENGINE_CLIENT);
    //cfg.cfg_log_level = XQC_LOG_INFO;

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
    if (!ctx.engine) { fprintf(stderr, "[client-quic] engine creation failed\n"); return -1; }
    printf("[client-quic] quic engine created\n");
    if (register_alpn(ctx.engine, &ctx) != 0) { fprintf(stderr, "[client-quic] ALPN registration failed\n"); return -1; }

    // create QUIC socket
    for (int i = 0; i < ctx.num_local_addrs; i++) {
        ctx.quic_fds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (ctx.quic_fds[i] < 0) return -1;
        fcntl(ctx.quic_fds[i], F_SETFL, O_NONBLOCK);
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == 0) {
            for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                // Check if interface has an IPv4 address and matches our current local target IP
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ctx.local_addrs[i].sin_addr.s_addr) {
                    if (setsockopt(ctx.quic_fds[i], SOL_SOCKET, SO_BINDTODEVICE, ifa->ifa_name, strlen(ifa->ifa_name)) < 0) {
                        perror("[client-quic] SO_BINDTODEVICE failed");
                    } else {
                        printf("[client-quic] Bound socket %d to interface device: %s\n", i, ifa->ifa_name);
                    }
                    break;
                }
            }
            freeifaddrs(ifaddr);
        }
        if (bind(ctx.quic_fds[i], (struct sockaddr*)&ctx.local_addrs[i], sizeof(ctx.local_addrs[i])) < 0) {
            fprintf(stderr, "[client-quic] bind failed for local address %d\n", i);
            return -1;
        } else {
            char local_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ctx.local_addrs[i].sin_addr, local_ip, sizeof(local_ip));
            printf("[client-quic] bound to local address %s:%d\n", local_ip, ntohs(ctx.local_addrs[i].sin_port));
        }
        struct event *sock_ev = event_new(eb, ctx.quic_fds[i], EV_READ | EV_PERSIST, packet_read_cb, &ctx);
        event_add(sock_ev, NULL);
    }
    
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
    printf("[client-proxy] listening for external UDP traffic on port %d...\n", ctx.udp_port);

    // add QUIC engine timer to libevent loop
    timer_ev = event_new(eb, -1, 0, engine_timer_cb, &ctx);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);

    // connect to QUIC server, using the first peer address as the initial path
    const xqc_cid_t *cidp = xqc_connect(ctx.engine, &conn_settings, NULL, 0, "localhost", 0,
                                        &conn_ssl_config, 
                                        (struct sockaddr*)&ctx.peer_addrs[0], sizeof(ctx.peer_addrs[0]),
                                        "raw", &ctx);
    if (!cidp) { fprintf(stderr, "[client-quic] quic connection failed\n"); return -1; }
    memcpy(&cid, cidp, sizeof(cid));
    printf("[client-quic] quic connection initiated\n");

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    for (int i = 0; i < ctx.num_local_addrs; i++) {
        close(ctx.quic_fds[i]);
    }
    close(ctx.udp_fd);
    event_base_free(eb);
    return 0;
}