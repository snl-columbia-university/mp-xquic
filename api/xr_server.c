#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS 16
#define MAX_PENDING 4096

typedef struct __attribute__((packed)) {
    int32_t hit_id, client_id;
    float client_prep_ms, server_proc_ms;
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id, client_id;
    uint8_t status;
} hit_ack_t;

typedef struct {
    int active;
    hit_ack_t ack;
    double target_send_time_ms;
} pending_ack_t;

static quic_endpoint_t *g_server = NULL;
static pending_ack_t g_pending_acks[MAX_PENDING] = {0};
static int g_active_pending_count = 0;

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

static int parse_ips(char *str, const char *ips[MAX_IPS]) {
    int count = 0;
    for (char *tok = strtok(str, " ,"); tok && count < MAX_IPS; tok = strtok(NULL, " ,")) {
        ips[count++] = tok;
    }
    return count;
}

static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    if (len < sizeof(hit_request_t)) return;
    const hit_request_t *req = (const hit_request_t *)data;

    printf("<<< [SERVER RECV] hitId=%d from client_%d | delay: %.2f ms\n", req->hit_id, req->client_id, req->server_proc_ms);

    for (int i = 0; i < MAX_PENDING; i++) {
        if (!g_pending_acks[i].active) {
            g_pending_acks[i].ack = (hit_ack_t){.hit_id = req->hit_id, .client_id = req->client_id, .status = 1};
            g_pending_acks[i].target_send_time_ms = get_time_ms() + req->server_proc_ms;
            g_pending_acks[i].active = 1;
            g_active_pending_count++;
            return;
        }
    }
    
    fprintf(stderr, "[ERROR] Dropping ACK for hitId=%d: Pending queue is full!\n", req->hit_id);
}

int main(int argc, char *argv[]) {
    const char *scheduler = "pmp", *congestion = "cubic", *qlog = "server.qlog";
    char local_buf[1024] = "127.0.0.2,127.0.0.3";
    
    static struct option opts[] = {
        {"local-ips", 1, 0, 'l'}, {"scheduler", 1, 0, 's'}, 
        {"congestion", 1, 0, 'c'}, {"qlog", 1, 0, 'q'}, {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "l:s:c:q:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'l': strcpy(local_buf, optarg); break; case 's': scheduler = optarg; break;
            case 'c': congestion = optarg; break; case 'q': qlog = optarg; break;
            default: return EXIT_FAILURE;
        }
    }

    const char *local_ips[MAX_IPS];
    quic_server_config_t config = {
        .listen_port = 8000, .num_local_addrs = parse_ips(local_buf, local_ips),
        .enable_datagram = 1, .enable_redundancy = 1, .scheduler = scheduler,
        .congestion = congestion, .qlog = qlog, .recv_cb = on_server_recv
    };
    for (int i = 0; i < config.num_local_addrs; i++) {
        config.local_ips[i] = local_ips[i];
    }

    if (config.num_local_addrs == 0) return EXIT_FAILURE;

    printf("Starting QUIC Server on port %d...\n", config.listen_port);
    if (!(g_server = quic_server_start(&config))) return EXIT_FAILURE;

    while (1) {
        if (g_server) quic_endpoint_step(g_server);

        if (g_active_pending_count > 0) {
            double now = get_time_ms();
            for (int i = 0; i < MAX_PENDING; i++) {
                if (g_pending_acks[i].active && now >= g_pending_acks[i].target_send_time_ms) {
                    printf(">>> [SERVER ACK SEND] hitId=%d to client_%d\n", g_pending_acks[i].ack.hit_id, g_pending_acks[i].ack.client_id);
                    if (g_server) quic_send(g_server, (const uint8_t *)&g_pending_acks[i].ack, sizeof(hit_ack_t));
                    
                    g_pending_acks[i].active = 0;
                    g_active_pending_count--;
                }
            }
        }
        usleep(100);
    }

    quic_endpoint_stop(g_server);
    return EXIT_SUCCESS;
}