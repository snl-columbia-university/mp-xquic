#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <event2/event.h>
#include <xquic/xquic.h>

#define LOG(fmt, ...) printf("[%ld] " fmt "\n", (long)time(NULL), ##__VA_ARGS__)

// quic config
#define MAX_PATHS 4

static struct event_base *eb = NULL;
static struct event *timer_ev = NULL;
static xqc_cid_t cid;

// quic ctx structure
typedef struct {
    xqc_engine_t *engine;
    int quic_fd;
    xqc_connection_t *conn;
    xqc_conn_settings_t *conn_settings;
    xqc_conn_ssl_config_t *conn_ssl_config;
    struct sockaddr_in path_addrs[MAX_PATHS];
    int num_paths;
    int next_path_idx;
    uint64_t quic_dgram_id;
    uint64_t client_dgram_id;
    uint64_t max_dgram_id;
    uint64_t dgram_id_mask;
    xqc_stream_t *stream;
} quic_ctx_t;
static quic_ctx_t *g_proxy_ctx = NULL;

// citm config
#define CMD_SET_TARGET 0x01  // cloud->citm: "stm_ip:stm_port,game_ip:game_port"
#define CMD_TELEMETRY  0x04  // citm->cloud: {"client_id":..,"measurements":[..]}
#define CMD_REGISTER   0x06  // citm->cloud: client_id

// telemetry: DNS name of the game-server pool to ping and report RTTs for
static const char *servers_domain = "gameservers.xrnet-columbia.com";
static bool verbose = false;  // -v: log every per-server RTT sample

// citm state
typedef struct {
    char *id;
    int ready;
    int app_fd;
    struct sockaddr_in app_addr;
    struct sockaddr_in stm_addr;
    struct sockaddr_in game_addr;
    int ctl_fd;
    struct sockaddr_in ctl_addr;
    int multipath;
} citm_state;
static citm_state *g_citm_state = NULL;

static xqc_usec_t get_timestamp(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

// QUIC logging callback
static void log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *arg) { printf("%.*s", (int)size, (char*)buf); }

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
    /*
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;  
    struct sockaddr_in *path_addr;
    path_addr = &ctx->path_addrs[path_id];
    */
    citm_state *state = (citm_state *)g_citm_state;
    struct sockaddr_in *path_addr;
    path_addr = &state->stm_addr;
    printf("[client-quic] write_socket_ex called for path_id %lu to %s:%d\n", path_id, 
        inet_ntoa(((struct sockaddr_in*)path_addr)->sin_addr), ntohs(((struct sockaddr_in*)path_addr)->sin_port));
    return write_socket(buf, size, (const struct sockaddr *)path_addr, sizeof(*path_addr), user_data);
}

/* Certificate verification (accept self-signed) */
static int cert_verify_cb(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *conn_user_data) { return 1; }

// QUIC stream callbacks
static int stream_create_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_close_notify(xqc_stream_t *strm, void *user_data) { return 0; }
static int stream_read_notify(xqc_stream_t *strm, void *user_data) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    citm_state *state = (citm_state *)g_citm_state;
    if (!ctx) return 0;

    unsigned char buf[1500];
    uint8_t fin = 0;
    while (1) {
        ssize_t n = xqc_stream_recv(strm, buf, sizeof(buf), &fin);
        if (n > 0) {
            if (state->app_fd && state->app_addr.sin_port != 0) {
                sendto(state->app_fd, buf, n, 0,
                       (struct sockaddr*)&state->app_addr, sizeof(state->app_addr));
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
static int stream_write_notify(xqc_stream_t *strm, void *user_data) { return 0; }

// QUIC connection callbacks
static int conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[client-quic] connection created\n");
    return 0; 
}
static int conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *proto_data) { 
    printf("[client-quic] connection closed\n");
    return 0; 
}
static void conn_handshake_finished(xqc_connection_t *conn, void *user_data, void *proto_data) {
    printf("[client-quic] handshake finished, proxy routing is now active.\n");
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    ctx->conn = conn;
    if (!ctx->quic_dgram_id) {
        // Create a bidirectional stream (or unidirectional if you prefer)
        ctx->stream = xqc_stream_create(ctx->engine, &cid, NULL, user_data);
        if (ctx->stream) {
            printf("[client-quic] stream %lu created\n", (unsigned long)xqc_stream_id(ctx->stream));
        } else {
            printf("[client-quic] stream creation failed\n");
        }
    }
}

static void save_token_cb(const unsigned char *token, unsigned int token_len, void *user_data) { return; }
static void save_session_cb(const  char *data, size_t data_len, void *user_data) { return; }

// QUIC multipath callbacks
void ready_to_create_path_notify(const xqc_cid_t *cid, void *user_data) {
    /*
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    // Create all remaining paths in one go
    while (ctx->next_path_idx < ctx->num_paths) {
        uint64_t new_path_id = 0;
        int ret = xqc_conn_create_path(ctx->engine, cid, &new_path_id, 0);
        if (ret == XQC_OK) {
            printf("[client-multipath] created path %lu for address %d\n", new_path_id, ctx->next_path_idx);
            ctx->next_path_idx++;
        } else {
            printf("[client-multipath] failed to create path for address %d: %d\n", ctx->next_path_idx, ret);
            break;  // no more CIDs available (or other error)
        }
    }
    */
}
int path_created_notify(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id, void *user_data) { return 0; }

static int is_new_datagram(uint64_t id) {
    quic_ctx_t *ctx = g_proxy_ctx;
    if (id > ctx->max_dgram_id) {
        uint64_t diff = id - ctx->max_dgram_id;
        if (diff >= 64) {
            ctx->dgram_id_mask = 1;
        } else {
            ctx->dgram_id_mask = (ctx->dgram_id_mask << diff) | 1;
        }
        ctx->max_dgram_id = id;
        return 1;
    } else {
        uint64_t diff = ctx->max_dgram_id - id;
        if (diff >= 64) {
            return 0;
        }
        if (ctx->dgram_id_mask & (1ULL << diff)) {
            return 0;
        } else {
            ctx->dgram_id_mask |= (1ULL << diff);
            return 1;
        }
    }
}

// QUIC datagram callbacks
static void datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data, size_t data_len, uint64_t flags) {
    quic_ctx_t *ctx = g_proxy_ctx;
    citm_state *state = (citm_state *)g_citm_state;
    if (ctx == NULL) { return; }

    // if app socket and app client, forward datagram
    printf("[client-quic] datagram recv from server\n");

    if (state->app_fd && state->app_addr.sin_port != 0) {
        uint64_t net_val;
        memcpy(&net_val, data, sizeof(uint64_t));
        uint64_t server_datagram_id = be64toh(net_val);

        if (is_new_datagram(server_datagram_id)) {printf("[client-quic] duplicate datagram %ld (<=%ld) recv from server\n", server_datagram_id, ctx->max_dgram_id); return;}

        int sent = sendto(state->app_fd, (const unsigned char *)data + sizeof(uint64_t), data_len - sizeof(uint64_t), 0, (struct sockaddr*)&state->app_addr, sizeof(state->app_addr));
        if (sent < 0) {
            printf("[client-proxy] sendto failed with error: %s\n", strerror(errno));   
        } else { 
            printf("[client-proxy] datagram %ld forwarded to udp\n", server_datagram_id); 
        }
    }
}
static void datagram_write_notify(xqc_connection_t *conn, void *user_data) {printf("[client-quic] datagram sent to server\n");}
static void datagram_acked_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { printf("[client-quic] datagram %ld acked\n", dgram_id);}
static xqc_int_t datagram_lost_notify(xqc_connection_t *conn, uint64_t dgram_id, void *user_data) { printf("[client-quic] datagram %ld lost\n", dgram_id); return XQC_DGRAM_RETX_ASKED_BY_APP;}

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
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    xqc_engine_main_logic(ctx->engine);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);
}

// QUIC packet read callback
static void packet_read_cb(int fd, short what, void *arg) {
    unsigned char buf[1500];
    struct sockaddr_in peer_addr, local_addr;
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
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

// CITM app socket callback
static void citm_app_read_cb(int fd, short what, void *arg) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    citm_state *state = (citm_state *)g_citm_state;

    unsigned char buf[1500];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    // recv from stm socket
    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) {
            break;
        }
        state->app_addr = src_addr;
        // send to QUIC datagram API
        if (ctx->conn) {
            if (ctx->stream) {
                ssize_t sent = xqc_stream_send(ctx->stream, buf, n, 0);
                if (sent < 0) {
                    fprintf(stderr, "[client-quic] xqc_stream_send failed: %zd\n", sent);
                }
            } else {
                printf("[client-proxy] datagram recieved over udp\n");
                int header_len = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(u_int16_t);
                memmove(buf + header_len, buf, n);
                uint64_t net_val = htobe64(ctx->client_dgram_id);
                memcpy(buf, &net_val, sizeof(uint64_t));
                memcpy(buf + sizeof(uint64_t), &state->game_addr.sin_addr.s_addr, sizeof(u_int32_t));
                memcpy(buf + sizeof(uint64_t) + sizeof(uint32_t), &state->game_addr.sin_port, sizeof(u_int16_t));
                int err = xqc_datagram_send(ctx->conn, buf, n + header_len, &ctx->quic_dgram_id, 1);
                if (err < 0){ printf("[client-quic] datagram send error %i\n", err); return;};
                printf("[client-quic] datagram %ld forwarded over quic\n", ctx->quic_dgram_id);
            }
        }
    }
}

// CITM ctl set stm and game addrs
static void citm_ctl_set_target(const char *payload) {
    quic_ctx_t *ctx = (quic_ctx_t *)g_proxy_ctx;
    citm_state *state = (citm_state *)g_citm_state;
    char stm_ip[64], game_ip[64];
    int stm_port, game_port;
    if (sscanf(payload, "%63[^:]:%d,%63[^:]:%d", stm_ip, &stm_port, game_ip, &game_port) != 4) {printf("[client-citm] ctl set target error\n"); return;}

    if(!state->multipath && state->ready) { return; }

    memset(&state->stm_addr, 0, sizeof(state->stm_addr));
    state->stm_addr.sin_family = AF_INET;
    state->stm_addr.sin_port = htons(8000);
    if (inet_pton(AF_INET, stm_ip, &state->stm_addr.sin_addr) <= 0) { printf("[client-citm] invalid stm ip: %s\n", stm_ip); return; }

    memset(&state->game_addr, 0, sizeof(state->game_addr));
    state->game_addr.sin_family = AF_INET;
    state->game_addr.sin_port = htons(game_port);
    if (inet_pton(AF_INET, game_ip, &state->game_addr.sin_addr) <= 0) { printf("[client-citm] invalid game ip: %s\n", game_ip); return; }

    // connect to QUIC server
    const xqc_cid_t *cidp = xqc_connect(ctx->engine, ctx->conn_settings, NULL, 0, "localhost", 0,
                                        ctx->conn_ssl_config, 
                                        (struct sockaddr*)&state->stm_addr, sizeof(state->stm_addr),
                                        "raw", NULL);
    if (!cidp) { fprintf(stderr, "[client-quic] quic connection failed\n"); return; }
    memcpy(&cid, cidp, sizeof(cid));
    printf("[client-quic] quic connection initiated\n");

    // create, set-up, and add CITM app socket to libevent loop
    state->app_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->app_fd < 0) return;
    fcntl(state->app_fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in app_local_addr;
    memset(&app_local_addr, 0, sizeof(app_local_addr));
    app_local_addr.sin_family = AF_INET;
    app_local_addr.sin_port = state->game_addr.sin_port;
    app_local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(state->app_fd, (struct sockaddr *)&app_local_addr, sizeof(app_local_addr));
    struct event *app_ev = event_new(eb, state->app_fd, EV_READ | EV_PERSIST, citm_app_read_cb, NULL);
    event_add(app_ev, NULL);
    printf("[client-stm] listening for external UDP traffic on port %d...\n", state->game_addr.sin_port);

    state->ready = 1;
}

// CITM ctl socket callback
static void citm_ctl_read_cb(int fd, short what, void *arg) {
    citm_state *state = (citm_state *)g_citm_state;
    unsigned char buf[1500];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    // recv from citm ctl socket
    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) {
            break;
        }
        // send to QUIC datagram API
        const char *payload = (const char *)(buf + 1);  // NUL-terminated by caller
        switch (buf[0]) {
            case CMD_SET_TARGET: citm_ctl_set_target(payload); break;
            default:             LOG("unknown command 0x%02X", buf[0]); break;
    }
    }
}

// CITM ctl socket set-up
static int citm_ctl_setup() {
    citm_state *state = (citm_state *)g_citm_state;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", 5051);
    if (getaddrinfo("cloud-traffic-manager.xrnet-columbia.com", port_str, &hints, &res) != 0){ return 0; }
    else { state->ctl_addr = *(struct sockaddr_in *)res->ai_addr; }
    freeaddrinfo(res);

    state->ctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
    fcntl(state->ctl_fd, F_SETFL, O_NONBLOCK);
    if (state->ctl_fd < 0) return 0;

    char buf[256];
    int size = snprintf(buf, sizeof(buf), "%c%s\n", CMD_REGISTER, state->id);
    if (sendto(state->ctl_fd, buf, size, 0, (struct sockaddr *)&state->ctl_addr, sizeof(state->ctl_addr)) < 0) {printf("[client-citm] ctl registration error\n"); return 0;}
    else {printf("[client-citm] ctl registration\n");}

    return 1;

}

// Run one `ping` and parse the RTT in ms. Returns -1.0 on no reply or -2.0 
// if the ping command could not be spawned.
static double citm_ping_host(const char *ip) {
    char cmd[128], line[256];
    double rtt = -1.0;

    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s 2>/dev/null", ip);
    errno = 0;

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        LOG("ping: could not run ping for %s: %s", ip, strerror(errno));
        return -2.0;
    }
    while (fgets(line, sizeof(line), fp)) {
        char *t = strstr(line, "time=");
        if (t) { sscanf(t, "time=%lf", &rtt); break; }
    }
    pclose(fp);

    return rtt;
}

// dns resolver
static int citm_resolve_servers(char paths[64][64]) {
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res, *p;

    int rc = getaddrinfo(servers_domain, NULL, &hints, &res);
    if (rc != 0) {
        LOG("telemetry: DNS resolution of '%s' failed: %s", servers_domain, gai_strerror(rc));
        return 0;
    }

    int count = 0;
    for (p = res; p && count < 64; p = p->ai_next) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, paths[count++], 64);
    }
    freeaddrinfo(res);

    if (count == 0) LOG("telemetry: '%s' resolved to no IPv4 addresses", servers_domain);
    else            LOG("telemetry: resolved %d server(s) from '%s'", count, servers_domain);
    return count;
}

// pinger thread loop
static void *citm_measurement_thread(void *arg) {
    citm_state *state = (citm_state *)g_citm_state;
    bool reachable[64];
    char paths[64][64];

    int count;
    while ((count = citm_resolve_servers(paths)) == 0) {
        sleep(5);  // retry until the first lookup succeeds
    }
    for (int i = 0; i < count; i++) {
        reachable[i] = true;
    }

    while (1) {
        // Flat schema: {"client_id":..,"measurements":[{"server_ip":..,"rtt":..}, ..]}
        char json[4096];
        int len = snprintf(json, sizeof(json),
                           "{\"client_id\":\"%s\",\"measurements\":[", state->id);
        bool first = true;
        int ok = 0;
        for (int i = 0; i < count; i++) {
            double rtt = citm_ping_host(paths[i]);
            if (rtt < 0) {
                if (reachable[i]) {
                    LOG("[client-citm] telemetry server %s unreachable (%s)", paths[i],
                        rtt <= -2.0 ? "ping could not run" : "no reply");
                    reachable[i] = false;
                }
                continue;
            }
            if (verbose) LOG("telemetry: server %s rtt=%.2f ms", paths[i], rtt);
            if (!reachable[i]) {
                LOG("[client-citm] telemetry server %s reachable again (%.2f ms)", paths[i], rtt);
                reachable[i] = true;
            }
            ok++;
            len += snprintf(json + len, sizeof(json) - len,
                            "%s{\"server_ip\":\"%s\",\"rtt\":%.2f}",
                            first ? "" : ",", paths[i], rtt);
            first = false;
        }
        len += snprintf(json + len, sizeof(json) - len, "]}");
        if (len < 0) len = 0;
        if (len >= (int)sizeof(json)) len = sizeof(json) - 1;  // guard against truncation

        if (ok > 0) {  // nothing measured -> skip the empty report
            unsigned char msg[2 + sizeof(json)];
            msg[0] = CMD_TELEMETRY;
            memcpy(msg + 1, json, len);
            msg[1 + len] = '\n';
            if (sendto(state->ctl_fd, msg, len + 2, 0,
                       (struct sockaddr *)&state->ctl_addr, sizeof(state->ctl_addr)) < 0) {
                LOG("[client-citm] telemetry send failed: %s", strerror(errno));
            }
        }
        sleep(1);
    }
    return NULL;
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -d            Enable datagram mode (sets max_datagram_frame_size)\n"
        "  -r            Enable experimental redundancy\n"
        "  -s <sched>    Select scheduler: pmp (proactive multipath),\n"
        "                psp (proactive singlepath), minrtt (default)\n"
        "  -p <ip>       Add peer address (can be repeated, client only)\n"
        "  -i <id>       Sets client-id used for ctm registration"
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
    
    // initialize global quic context
    quic_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    g_proxy_ctx = &ctx;

    // default quic configs
    conn_settings.max_datagram_frame_size = 0;
    conn_settings.datagram_force_retrans_on = 0;
    conn_settings.enable_experimental_redundancy = 0;
    conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    ctx.num_paths = 0;
    ctx.next_path_idx = 1;

    // initialize global citm context
    citm_state state;
    memset(&state, 0, sizeof(state));
    g_citm_state = &state;

    // default citm configs
    state.id = "83760a4a23a04f4b8409d679fd6094bc";
    state.ready = 0;
    state.multipath = 1;

    int opt;
    while ((opt = getopt(argc, argv, "drs:p:i:hv")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
            return 0;
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
            case 'p': 
                if (ctx.num_paths < MAX_PATHS) {
                    struct sockaddr_in *addr = &ctx.path_addrs[ctx.num_paths++];
                    memset(addr, 0, sizeof(*addr));
                    addr->sin_family = AF_INET;
                    addr->sin_port = htons(8000);   // port is fixed (8000)
                    if (inet_pton(AF_INET, optarg, &addr->sin_addr) <= 0) {
                        fprintf(stderr, "[client-quic] invalid address: %s\n", optarg);
                        return 1;
                    }
                } else {
                    fprintf(stderr, "[client-quic] too many addresses, max %d\n", MAX_PATHS);
                    return 1;
                }
                break;
            case 'i':
                state.id = optarg;
                break;
            case 'v':
                verbose = true;
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
    ctx.quic_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.quic_fd < 0) return -1;
    fcntl(ctx.quic_fd, F_SETFL, O_NONBLOCK);

    // add QUIC socket to libevent loop
    struct event *sock_ev = event_new(eb, ctx.quic_fd, EV_READ | EV_PERSIST, packet_read_cb, NULL);
    event_add(sock_ev, NULL);

    // create, set-up, and add CITM ctl socket to libevent loop
    if (!citm_ctl_setup()) { printf("[client-citm] ctl set up error"); return -1; }
    struct event *citm_ctl_ev = event_new(eb, state.ctl_fd, EV_READ | EV_PERSIST, citm_ctl_read_cb, NULL);
    event_add(citm_ctl_ev, NULL);
    printf("[client-citm] ctl set up\n");

    pthread_t pinger_tid;
    if (pthread_create(&pinger_tid, NULL, citm_measurement_thread, NULL) != 0) {
        fprintf(stderr, "[client-citm] failed to start pinger thread: %s\n", strerror(errno));
        return -1;
    }
    printf("[client-citm] pinger thread started\n");

    // add QUIC engine timer to libevent loop
    timer_ev = event_new(eb, -1, 0, engine_timer_cb, &ctx);
    struct timeval tv = {0, 10000};
    event_add(timer_ev, &tv);

    // define QUIC connection settings
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_enable_reinjection = 0;
    conn_settings.mp_ping_on = 1;
    conn_settings.init_max_path_id = MAX_PATHS;

    ctx.conn_settings = &conn_settings;
    ctx.conn_ssl_config = &conn_ssl_config;

    event_base_dispatch(eb);

    xqc_engine_destroy(ctx.engine);
    close(ctx.quic_fd);
    close(state.app_fd);
    close(state.ctl_fd);
    event_base_free(eb);
    return 0;
}