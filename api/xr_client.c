#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_HITS 4096

// --- Network Packet Payloads ---

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    float client_prep_ms;
    float server_proc_ms;  // Tell server how long to simulate processing
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    uint8_t status;
} hit_ack_t;

// --- RTT Tracking State ---

typedef struct {
    int hit_id;
    double send_time_ms;
} pending_hit_t;

static pending_hit_t g_pending[MAX_HITS];
static int g_pending_count = 0;

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// --- Receive Callback ---

static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    double recv_time = get_time_ms();

    // Check if received packet is a hit ACK
    if (len >= sizeof(hit_ack_t)) {
        const hit_ack_t *ack = (const hit_ack_t *)data;

        for (int i = 0; i < g_pending_count; i++) {
            if (g_pending[i].hit_id == ack->hit_id && g_pending[i].send_time_ms > 0) {
                double rtt = recv_time - g_pending[i].send_time_ms;
                printf(">>> [ACK RECV] hitId=%d | Measured RTT: %.2f ms\n", ack->hit_id, rtt);
                g_pending[i].send_time_ms = 0; // Mark received
                return;
            }
        }
    }

    // Fallback log for raw strings/other messages
    printf("\n>>> [CLIENT APP] Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);
}

int main(int argc, char *argv[]) {
    const char *trace_file = (argc > 1) ? argv[1] : "replay_trace.csv";
    const char *target_peer = (argc > 2) ? argv[2] : "client_1";

    quic_client_config_t config = {
        .peer_ips = { "45.63.15.235", "184.164.234.64" },
        .num_peer_addrs = 2,
        .local_ips = { "192.168.1.141"},
        .num_local_addrs = 1,
        .peer_port = 8000,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
        .scheduler = "pmp",
        .enable_redundancy = 1,
        .user_data = NULL
    };

    printf("Starting QUIC Client...\n");
    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) {
        fprintf(stderr, "Failed to start client!\n");
        return EXIT_FAILURE;
    }

    printf("Waiting for handshake...\n");
    sleep(1);

    // --- Trace Replay Engine ---

    FILE *f = fopen(trace_file, "r");
    if (!f) {
        perror("Failed to open CSV trace file");
        quic_endpoint_stop(client);
        return EXIT_FAILURE;
    }

    char line[256];
    // Skip CSV header line
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        quic_endpoint_stop(client);
        return EXIT_SUCCESS;
    }

    printf("Replaying trace '%s' for peer '%s'...\n", trace_file, target_peer);
    double test_start_ms = get_time_ms();

    char peer[32];
    int hit_id;
    double send_offset_ms, inter_send_delay_ms, client_prep_ms, server_proc_ms;

    // Read 6 CSV columns
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, " %31[^,],%d,%lf,%lf,%lf,%lf",
                   peer, &hit_id, &send_offset_ms,
                   &inter_send_delay_ms, &client_prep_ms, &server_proc_ms) == 6) {

            if (strcmp(peer, target_peer) != 0) {
                continue; // Skip records for other clients
            }

            // Sleep until scheduled send offset
            double target_time = test_start_ms + send_offset_ms;
            double now = get_time_ms();
            if (target_time > now) {
                usleep((useconds_t)((target_time - now) * 1000.0));
            }

            // Construct hit request payload
            hit_request_t req = {
                .hit_id = hit_id,
                .client_prep_ms = (float)client_prep_ms,
                .server_proc_ms = (float)server_proc_ms
            };

            // Store send timestamp for RTT calculation inside on_client_recv()
            if (g_pending_count < MAX_HITS) {
                g_pending[g_pending_count].hit_id = hit_id;
                g_pending[g_pending_count].send_time_ms = get_time_ms();
                g_pending_count++;
            }

            printf(">>> [CLIENT SEND] hitId=%d | prep=%.2fms | server_proc=%.2fms\n",
                   hit_id, client_prep_ms, server_proc_ms);

            // Send payload over QUIC
            quic_send(client, (const uint8_t *)&req, sizeof(req));
        }
    }

    fclose(f);

    /* Wait to receive remaining ACK responses */
    sleep(2);

    printf("Stopping client...\n");
    quic_endpoint_stop(client);
    printf("Client stopped successfully.\n");

    return EXIT_SUCCESS;
}