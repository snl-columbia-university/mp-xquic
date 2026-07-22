#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "quic_api.h"

static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    printf("\n>>> [CLIENT APP] Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);
}

int main(void) {
    quic_client_config_t config = {
        .peer_ips = { "127.0.0.1" },
        .num_peer_addrs = 1,
        .local_ips = { "127.0.0.1" },
        .num_local_addrs = 1,
        .peer_port = 8000,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
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

    const char *msg = "PING from Client!";
    printf(">>> [CLIENT APP] Sending message: %s\n", msg);
    quic_send(client, (const uint8_t *)msg, strlen(msg));

    /* Wait to process echo response */
    sleep(2);

    printf("Stopping client...\n");
    quic_endpoint_stop(client);
    printf("Client stopped successfully.\n");

    return EXIT_SUCCESS;
}