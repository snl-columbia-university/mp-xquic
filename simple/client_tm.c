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
#include "api/quic_api.h"

#define LOG(fmt, ...) printf("[%ld] " fmt "\n", (long)time(NULL), ##__VA_ARGS__)

// quic config
#define MAX_PATHS 4

static struct event_base *eb = NULL;
static quic_client_config_t g_config;       // QUIC client config built from CLI; peer set once a game is chosen
static quic_endpoint_t *g_client = NULL;    // QUIC endpoint; created in citm_ctl_set_target after game selection
static const char *g_cli_peers[MAX_PATHS];  // optional -p peer overrides (testing)
static int g_num_cli_peers = 0;

// citm config
#define CMD_SET_TARGET 0x01  // cloud->citm: "stm_ip1:port,stm_ip2:port,...;game_ip:game_port"
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

// CITM app socket callback: forward local app UDP -> QUIC (to the STM).
//
// The STM needs the game target, so we prepend a 6-byte routing header
// ([game IP(4)][game port(2)]). quic_send() prepends the 8-byte datagram id
// itself, producing the wire format the STM expects:
//   [id(8)][game IP(4)][game port(2)][payload]
static void citm_app_read_cb(int fd, short what, void *arg) {
    citm_state *state = (citm_state *)g_citm_state;

    unsigned char buf[1500];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    const int hdr = sizeof(uint32_t) + sizeof(uint16_t);  // game IP + game port

    while (1) {
        // leave room at the front for the routing header
        ssize_t n = recvfrom(fd, buf + hdr, sizeof(buf) - hdr, 0,
                             (struct sockaddr*)&src_addr, &src_len);
        if (n <= 0) {
            break;
        }
        state->app_addr = src_addr;  // remember where to return downstream traffic

        if (!g_client) continue;     // QUIC not up yet (no game chosen)

        // prepend the [game IP][game port] routing header, then send as a datagram
        memcpy(buf, &state->game_addr.sin_addr.s_addr, sizeof(uint32_t));
        memcpy(buf + sizeof(uint32_t), &state->game_addr.sin_port, sizeof(uint16_t));
        int sent = quic_send(g_client, buf, hdr + n);

        if (sent < 0) {
            fprintf(stderr, "[client-quic] quic_send failed: %d\n", sent);
        } else if (verbose) {
            char game_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &state->game_addr.sin_addr, game_ip_str, sizeof(game_ip_str));
            printf("[client-quic] forwarded %zd bytes over quic -> %s:%d\n",
                   n, game_ip_str, ntohs(state->game_addr.sin_port));
        }
    }
}


static void citm_quic_recv_cb(const uint8_t *data, size_t len, void *user_data) {
    citm_state *state = (citm_state *)user_data;
    if (!state->ready || state->app_addr.sin_port == 0) return;  // no app socket / no peer yet
    if (sendto(state->app_fd, data, len, 0,
               (struct sockaddr *)&state->app_addr, sizeof(state->app_addr)) < 0) {
        if (verbose) LOG("[client-citm] app forward failed: %s", strerror(errno));
    }
}

static void citm_ctl_set_target(const char *payload) {
    citm_state *state = (citm_state *)g_citm_state;

    if (g_client) return;

    const char *semi = strrchr(payload, ';');
    if (!semi) { printf("[client-citm] ctl set target error\n"); return; }

    char game_ip[64];
    int game_port;
    if (sscanf(semi + 1, "%63[^:]:%d", game_ip, &game_port) != 2) { printf("[client-citm] ctl set target error\n"); return; }

    char stm_ips[MAX_PATHS][64];
    int stm_ports[MAX_PATHS];
    int num_stm = 0;
    const char *tok = payload;
    while (tok < semi && num_stm < MAX_PATHS) {
        const char *comma = strchr(tok, ',');
        const char *end = (comma && comma < semi) ? comma : semi;
        char entry[80];
        int elen = (int)(end - tok);
        if (elen <= 0 || elen >= (int)sizeof(entry)) break;
        memcpy(entry, tok, elen);
        entry[elen] = '\0';
        if (sscanf(entry, "%63[^:]:%d", stm_ips[num_stm], &stm_ports[num_stm]) != 2) {
            printf("[client-citm] ctl set target error\n"); return;
        }
        num_stm++;
        if (end == semi) break;
        tok = end + 1;
    }
    if (num_stm == 0) { printf("[client-citm] ctl set target error\n"); return; }

    memset(&state->game_addr, 0, sizeof(state->game_addr));
    state->game_addr.sin_family = AF_INET;
    state->game_addr.sin_port = htons(game_port);
    if (inet_pton(AF_INET, game_ip, &state->game_addr.sin_addr) <= 0) { printf("[client-citm] invalid game ip: %s\n", game_ip); return; }

    char game_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &state->game_addr.sin_addr, game_ip_str, sizeof(game_ip_str));
    printf("[client-citm] game target set to %s:%d (%d stm path(s), best %s:%d)\n",
           game_ip_str, game_port, num_stm, stm_ips[0], stm_ports[0]);

    g_config.num_peer_addrs = 0;
    if (g_num_cli_peers > 0) {
        for (int i = 0; i < g_num_cli_peers && i < MAX_PATHS; i++)
            g_config.peer_ips[g_config.num_peer_addrs++] = g_cli_peers[i];
    } else {
        for (int i = 0; i < num_stm; i++)
            g_config.peer_ips[g_config.num_peer_addrs++] = stm_ips[i];
        g_config.peer_port = stm_ports[0] ? stm_ports[0] : 8000;
    }

    g_client = quic_client_start(&g_config);
    if (!g_client) { fprintf(stderr, "[client-quic] quic_client_start failed\n"); return; }
    printf("[client-quic] quic client started -> %s:%d (%d path(s))\n", stm_ips[0], stm_ports[0], (int)g_config.num_peer_addrs);

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

static int citm_resolve_servers(const char *host, char out[][INET_ADDRSTRLEN], int max);

// pinger thread loop
static void *citm_measurement_thread(void *arg) {
    citm_state *state = (citm_state *)g_citm_state;
    bool reachable[64];
    char paths[64][INET_ADDRSTRLEN];

    int count;
    while ((count = citm_resolve_servers(servers_domain, paths, 64)) == 0) {
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
        fflush(stdout);  
        sleep(1);
    }
    return NULL;
}

static int citm_resolve_servers(const char *host, char out[][INET_ADDRSTRLEN], int max) {
    struct addrinfo hints = { .ai_family = AF_INET, .ai
_socktype = SOCK_DGRAM }, *res, *p;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        LOG("[client-quic] DNS resolution of '%s' failed: %s", host, gai_strerror(rc));
        return 0;
    }
    int count = 0;
    for (p = res; p && count < max; p = p->ai_next) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr, out[count++], INET_ADDRSTRLEN);
    }
    freeaddrinfo(res);
    return count;
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -r            Enable experimental redundancy\n"
        "  -s <sched>    Select scheduler: pmp (proactive multipath),\n"
        "                psp (proactive singlepath), minrtt (default)\n"
        "  -l <port>     STM peer port used with -p (default 8000; cloud sets it otherwise)\n"
        "  -p <ip>       Add peer address (can be repeated, client only)\n"
        "  -i <id>       Sets client-id used for ctm registration\n"
        "  -h            Show this help\n"
        "\n"
        "Example:\n"
        "  %s -r -s pmp -p 127.0.0.1 -p 127.0.0.2\n",
        progname, progname
    );
}

int main(int argc, char *argv[]) {
    citm_state state;
    memset(&state, 0, sizeof(state));
    g_citm_state = &state;
    state.id = "83760a4a23a04f4b8409d679fd6094bc";
    state.ready = 0;
    state.multipath = 1;

    memset(&g_config, 0, sizeof(g_config));
    g_config.peer_port      = 8000;
    g_config.scheduler      = "minrtt";
    g_config.enable_datagram = 1;  
    g_config.recv_cb        = citm_quic_recv_cb;  
    g_config.user_data      = &state;

    int opt;
    while ((opt = getopt(argc, argv, "l:rs:p:i:hv")) != -1) {
        switch (opt) {
            case 'l': g_config.peer_port = (uint16_t)atoi(optarg); break;
            case 'r': g_config.enable_redundancy = 1; break;
            case 's': g_config.scheduler = optarg; break;
            case 'p':
                if (g_num_cli_peers < MAX_PATHS) {
                    g_cli_peers[g_num_cli_peers++] = optarg;
                } else {
                    fprintf(stderr, "[client-quic] too many peers, max %d\n", MAX_PATHS);
                    return 1;
                }
                break;
            case 'i': state.id = optarg; break;
            case 'v': verbose = true; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    printf("[client-citm] starting\n");

    eb = event_base_new();
    if (!eb) return -1;

    // create, set-up, and add CITM ctl socket to libevent loop
    if (!citm_ctl_setup()) { printf("[client-citm] ctl set up error\n"); return -1; }
    struct event *citm_ctl_ev = event_new(eb, state.ctl_fd, EV_READ | EV_PERSIST, citm_ctl_read_cb, NULL);
    event_add(citm_ctl_ev, NULL);
    printf("[client-citm] ctl set up\n");

    pthread_t pinger_tid;
    if (pthread_create(&pinger_tid, NULL, citm_measurement_thread, NULL) != 0) {
        fprintf(stderr, "[client-citm] failed to start pinger thread: %s\n", strerror(errno));
        return -1;
    }
    printf("[client-citm] pinger thread started\n");

    event_base_dispatch(eb);

    if (g_client) quic_endpoint_stop(g_client);
    if (state.app_fd > 0) close(state.app_fd);
    if (state.ctl_fd > 0) close(state.ctl_fd);
    event_base_free(eb);
    return 0;
}