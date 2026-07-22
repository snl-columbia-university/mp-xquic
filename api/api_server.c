#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "quic_api.h"

typedef struct {
    quic_endpoint_t *ep;
} server_app_ctx_t;

static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    server_app_ctx_t *ctx = (server_app_ctx_t *)user_data;

    printf("\n>>> [SERVER APP] Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);

    /* Echo reply back to the client */
    if (ctx && ctx->ep) {
        const char *reply = "PONG from Server!";
        printf(">>> [SERVER APP] Echoing reply: %s\n", reply);
        quic_send(ctx->ep, (const uint8_t *)reply, strlen(reply));
    }
}

int main(void) {
    server_app_ctx_t app_ctx = {0};

    quic_server_config_t config = {
        .listen_port = 8000,
        .cert_file = "server.crt",
        .key_file = "server.key",
        .enable_datagram = 1,
        .scheduler = "pmp",
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
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