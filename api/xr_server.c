#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "quic_api.h"

// --- Network Packet Payloads (Matching Client) ---

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    float client_prep_ms;
    float server_proc_ms;  // Processing time requested by replay trace
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    uint8_t status;
} hit_ack_t;

typedef struct {
    quic_endpoint_t *ep;
} server_app_ctx_t;

static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    server_app_ctx_t *ctx = (server_app_ctx_t *)user_data;

    // Process hit request packet
    if (len >= sizeof(hit_request_t)) {
        const hit_request_t *req = (const hit_request_t *)data;

        printf("\n>>> [SERVER APP] Received Hit %d | prep=%.2fms | target proc=%.2fms\n",
               req->hit_id, req->client_prep_ms, req->server_proc_ms);

        /* Simulate server processing delay specified in trace */
        if (req->server_proc_ms > 0) {
            usleep((useconds_t)(req->server_proc_ms * 1000.0));
        }

        /* Reply with hit ACK */
        if (ctx && ctx->ep) {
            hit_ack_t ack = {
                .hit_id = req->hit_id,
                .status = 1
            };
            printf(">>> [SERVER APP] Sending ACK for Hit %d\n", req->hit_id);
            quic_send(ctx->ep, (const uint8_t *)&ack, sizeof(ack));
        }
    } else {
        /* Fallback for standard text/ping messages */
        printf("\n>>> [SERVER APP] Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);

        if (ctx && ctx->ep) {
            const char *reply = "PONG from Server!";
            printf(">>> [SERVER APP] Echoing reply: %s\n", reply);
            quic_send(ctx->ep, (const uint8_t *)reply, strlen(reply));
        }
    }
}

int main(int argc, char *argv[]) {
    server_app_ctx_t app_ctx = {0};

    const char *scheduler   = (argc > 1) ? argv[1] : "pmp";
    const char *congestion  = (argc > 2) ? argv[2] : "cubic";
    const char *out_log_file = "rtt_results.csv";

    quic_server_config_t config = {
        .listen_port = 8000,
        .cert_file = "server.crt",
        .key_file = "server.key",
        .enable_datagram = 1,
        .scheduler = "pmp",
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
        .scheduler = scheduler,
        .congestion = congestion,      
        .user_data = &app_ctx
    };

    printf("Starting QUIC Server on port 8000...\n");
    quic_endpoint_t *server = quic_server_start(&config);
    if (!server) {
        fprintf(stderr, "Failed to start server!\n");
        return EXIT_FAILURE;
    }

    /* Assign handle to app context so callback can reply */
    app_ctx.ep = server;

    printf("Server is running. Press Ctrl+C to terminate.\n\n");
    while (1) {
        sleep(1);
    }

    quic_endpoint_stop(server);
    return EXIT_SUCCESS;
}