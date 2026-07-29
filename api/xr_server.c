#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

// --- Network Packet Structures ---

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    int32_t client_id;      // Numeric ID of origin client
    float client_prep_ms;
    float server_proc_ms;   // Exact delay recorded in trace
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    int32_t client_id;      // Origin client ID preserved
    uint8_t status;
} hit_ack_t;

static quic_endpoint_t *g_server1 = NULL;
static quic_endpoint_t *g_server2 = NULL;

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// --- Receive Callback ---

static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    // Retrieve the target server handle passed via user_data
    quic_endpoint_t *server = *(quic_endpoint_t **)user_data;

    if (len >= sizeof(hit_request_t)) {
        const hit_request_t *req = (const hit_request_t *)data;

        printf("<<< [SERVER RECV] hitId=%d from client_%d | Requested processing delay: %.2f ms\n",
               req->hit_id, req->client_id, req->server_proc_ms);

        // Simulate exact processing overhead from log trace
        if (req->server_proc_ms > 0.0f) {
            usleep((useconds_t)(req->server_proc_ms * 1000.0));
        }

        // Construct ACK response
        hit_ack_t ack = {
            .hit_id = req->hit_id,
            .client_id = req->client_id,
            .status = 1
        };

        printf(">>> [SERVER ACK SEND] hitId=%d to client_%d\n", req->hit_id, req->client_id);
        if (server) {
            quic_send(g_server1, (const uint8_t *)&ack, sizeof(ack));
            //quic_send(g_server2, (const uint8_t *)&ack, sizeof(ack));
        }
    }
}

int main(int argc, char *argv[]) {
    // --- Server Endpoint 1 Config (Port 8000) ---
    quic_server_config_t config1 = {
        .listen_port = 8000,
        .enable_datagram = 1,
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
        .scheduler = "pmp",
        .congestion = "cubic",
        .user_data = &g_server1
    };

    // --- Server Endpoint 2 Config (Port 8001) ---
    quic_server_config_t config2 = {
        .listen_port = 8001,
        .enable_datagram = 1,
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
        .scheduler = "pmp",
        .congestion = "cubic",
        .user_data = &g_server2
    };

    printf("Starting QUIC Replay Server 1 on port 8000...\n");
    g_server1 = quic_server_start(&config1);
    if (!g_server1) {
        fprintf(stderr, "Failed to start Server 1!\n");
        return EXIT_FAILURE;
    }

    printf("Starting QUIC Replay Server 2 on port 8001...\n");
    g_server2 = quic_server_start(&config2);
    if (!g_server2) {
        fprintf(stderr, "Failed to start Server 2!\n");
        quic_endpoint_stop(g_server1);
        return EXIT_FAILURE;
    }

    printf("Both servers running. Press Ctrl+C to stop.\n");
    while (1) {
        sleep(1);
    }

    quic_endpoint_stop(g_server1);
    quic_endpoint_stop(g_server2);
    return EXIT_SUCCESS;
}