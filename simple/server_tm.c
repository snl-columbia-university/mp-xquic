#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event2/event.h>
#include "api/quic_api.h"

static struct event_base *eb = NULL;
static quic_endpoint_t *g_server = NULL;
static int g_game_fd = -1;

static void stm_quic_recv_cb(const uint8_t *data, size_t len, void *user_data) {
    const int hdr = sizeof(uint32_t) + sizeof(uint16_t);  // game IP + game port
    if (len < (size_t)hdr) return;

    uint32_t game_ip;
    uint16_t game_port;
    memcpy(&game_ip, data, sizeof(uint32_t));                    
    memcpy(&game_port, data + sizeof(uint32_t), sizeof(uint16_t)); 
    struct sockaddr_in game_addr;
    memset(&game_addr, 0, sizeof(game_addr));
    game_addr.sin_family = AF_INET;
    game_addr.sin_addr.s_addr = game_ip;
    game_addr.sin_port = game_port;

    ssize_t sent = sendto(g_game_fd, data + hdr, len - hdr, 0,
                          (struct sockaddr *)&game_addr, sizeof(game_addr));
    if (sent < 0) {
        fprintf(stderr, "[server-stm] sendto game failed: %s\n", strerror(errno));
    } else {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &game_ip, ip_str, sizeof(ip_str));
        printf("[server-stm] forwarded %zd bytes to game %s:%u\n",
               len - hdr, ip_str, ntohs(game_port));
    }
}

static void stm_game_read_cb(int fd, short what, void *arg) {
    unsigned char buf[2000];
    while (1) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) break;  // EAGAIN when drained
        int sent = quic_send(g_server, buf, n);
        if (sent < 0) fprintf(stderr, "[server-quic] quic_send failed: %d\n", sent);
    }
}

static void usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -l <port>     UDP port to listen on (default 8000)\n"
        "  -r            Enable experimental redundancy\n"
        "  -s <sched>    Select scheduler: pmp (proactive multipath),\n"
        "                psp (proactive singlepath), minrtt (default)\n"
        "  -h            Show this help\n"
        "\n"
        "Example:\n"
        "  %s -r -s pmp\n",
        progname, progname
    );
}

int main(int argc, char *argv[]) {
    quic_server_config_t config;
    memset(&config, 0, sizeof(config));
    config.listen_port     = 8000;
    config.cert_file       = "server.crt";
    config.key_file        = "server.key";
    config.scheduler       = "minrtt";
    config.enable_datagram = 1;   
    config.recv_cb         = stm_quic_recv_cb;
    config.user_data       = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "l:rs:h")) != -1) {
        switch (opt) {
            case 'l': config.listen_port = (uint16_t)atoi(optarg); break;
            case 'r': config.enable_redundancy = 1; break;
            case 's': config.scheduler = optarg; break;  
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    g_game_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_game_fd < 0) { perror("[server-stm] game socket"); return -1; }
    fcntl(g_game_fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in game_local;
    memset(&game_local, 0, sizeof(game_local));
    game_local.sin_family = AF_INET;
    game_local.sin_addr.s_addr = htonl(INADDR_ANY);
    game_local.sin_port = htons(0);
    if (bind(g_game_fd, (struct sockaddr *)&game_local, sizeof(game_local)) < 0) {
        perror("[server-stm] game socket bind"); return -1;
    }

    printf("[server-quic] starting\n");

    g_server = quic_server_start(&config);
    if (!g_server) { fprintf(stderr, "[server-quic] quic_server_start failed\n"); return -1; }
    printf("[server-quic] listening on port %d\n", config.listen_port);

    eb = event_base_new();
    if (!eb) return -1;
    struct event *game_ev = event_new(eb, g_game_fd, EV_READ | EV_PERSIST, stm_game_read_cb, NULL);
    event_add(game_ev, NULL);
    event_base_dispatch(eb);

    event_free(game_ev);
    quic_endpoint_stop(g_server);
    close(g_game_fd);
    event_base_free(eb);
    return 0;
}
