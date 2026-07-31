#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS 16

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

// --- IP Parser Helper ---

static int parse_ip_list(const char *str, char bufs[MAX_IPS][64], const char *ptrs[MAX_IPS]) {
    if (!str || !*str) return 0;
    
    char tmp[1024];
    strncpy(tmp, str, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    int count = 0;
    char *token = strtok(tmp, ",");
    while (token && count < MAX_IPS) {
        // Trim leading spaces
        while (*token == ' ') token++;
        // Trim trailing spaces
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { 
            *end = '\0'; 
            end--; 
        }

        strncpy(bufs[count], token, 63);
        bufs[count][63] = '\0';
        ptrs[count] = bufs[count];
        count++;
        token = strtok(NULL, ",");
    }
    return count;
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

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n\n", prog_name);
    printf("  -l, --local-ips IPS    Comma-separated local IPs to bind (default: 127.0.0.2,127.0.0.3)\n");
    printf("  -s, --scheduler ALG    Scheduler algorithm (default: pmp)\n");
    printf("  -c, --congestion ALG   Congestion algorithm (default: cubic)\n");
    printf("  -h, --help             Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *scheduler     = "pmp";
    const char *congestion    = "cubic";
    const char *raw_local_ips = "127.0.0.2,127.0.0.3";

    static struct option long_options[] = {
        {"local-ips",  required_argument, 0, 'l'},
        {"scheduler",  required_argument, 0, 's'},
        {"congestion", required_argument, 0, 'c'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "l:s:c:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l': raw_local_ips = optarg; break;
            case 's': scheduler     = optarg; break;
            case 'c': congestion    = optarg; break;
            case 'h': print_usage(argv[0]); return EXIT_SUCCESS;
            default:  print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    // Parse comma-separated local IPs
    char local_bufs[MAX_IPS][64];
    const char *local_ips[MAX_IPS];
    int num_local_addrs = parse_ip_list(raw_local_ips, local_bufs, local_ips);

    if (num_local_addrs == 0) {
        fprintf(stderr, "Error: Must specify at least one local IP address.\n");
        return EXIT_FAILURE;
    }

    printf("Starting QUIC Servers with %d local IP(s): ", num_local_addrs);
    for (int i = 0; i < num_local_addrs; i++) printf("%s ", local_ips[i]);
    printf("\n");
    fflush(stdout);

    // --- Server Endpoint 1 Config (Port 8000) ---
    quic_server_config_t config1 = {
        .listen_port = 8000,
        .num_local_addrs = num_local_addrs,
        .enable_datagram = 1,
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
        .scheduler = scheduler,
        .congestion = congestion,
        .user_data = &g_server1
    };

    // --- Server Endpoint 2 Config (Port 8001) ---
    quic_server_config_t config2 = {
        .listen_port = 8001,
        .num_local_addrs = num_local_addrs,
        .enable_datagram = 1,
        .enable_redundancy = 1,
        .recv_cb = on_server_recv,
        .scheduler = scheduler,
        .congestion = congestion,
        .user_data = &g_server2
    };

    for (int i = 0; i < num_local_addrs; i++) {
        config1.local_ips[i] = local_ips[i];
        config2.local_ips[i] = local_ips[i];
    }

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