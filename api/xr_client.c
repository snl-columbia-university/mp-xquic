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
    float server_proc_ms;
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    uint8_t status;
} hit_ack_t;

// --- RTT Tracking & Logging State ---

typedef struct {
    int hit_id;
    double send_time_ms;
    double recv_time_ms;
    double rtt_ms;
    int ack_received;
} hit_record_t;

static hit_record_t g_records[MAX_HITS];
static int g_record_count = 0;
static FILE *g_rtt_log_file = NULL;

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// --- Receive Callback ---

static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    double recv_time = get_time_ms();

    if (len >= sizeof(hit_ack_t)) {
        const hit_ack_t *ack = (const hit_ack_t *)data;

        for (int i = 0; i < g_record_count; i++) {
            if (g_records[i].hit_id == ack->hit_id && !g_records[i].ack_received) {
                g_records[i].recv_time_ms = recv_time;
                g_records[i].rtt_ms = recv_time - g_records[i].send_time_ms;
                g_records[i].ack_received = 1;

                printf(">>> [ACK RECV] hitId=%d | Measured RTT: %.2f ms\n", 
                       ack->hit_id, g_records[i].rtt_ms);

                if (g_rtt_log_file) {
                    fprintf(g_rtt_log_file, "%d,%.2f,%.2f,%.2f\n",
                            ack->hit_id,
                            g_records[i].send_time_ms,
                            g_records[i].recv_time_ms,
                            g_records[i].rtt_ms);
                    fflush(g_rtt_log_file);
                }
                return;
            }
        }
    }

    printf("\n>>> [CLIENT APP] Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);
}

// --- Summary Stats Helper ---

static int compare_doubles(const void *a, const void *b) {
    double arg1 = *(const double *)a;
    double arg2 = *(const double *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

static void print_rtt_summary(void) {
    double rtts[MAX_HITS];
    int count = 0;
    int lost = 0;

    for (int i = 0; i < g_record_count; i++) {
        if (g_records[i].ack_received) {
            rtts[count++] = g_records[i].rtt_ms;
        } else {
            lost++;
        }
    }

    printf("\n=========================================\n");
    printf(" RTT REPLAY LOG SUMMARY\n");
    printf("=========================================\n");
    printf(" Total Requests Sent : %d\n", g_record_count);
    printf(" ACKs Received       : %d\n", count);
    printf(" Unanswered / Lost   : %d\n", lost);

    if (count > 0) {
        qsort(rtts, count, sizeof(double), compare_doubles);
        double min_rtt = rtts[0];
        double max_rtt = rtts[count - 1];
        double median_rtt = rtts[count / 2];
        double p95_rtt = rtts[(int)(count * 0.95)];

        double sum = 0;
        for (int i = 0; i < count; i++) sum += rtts[i];
        double mean_rtt = sum / count;

        printf(" Min RTT             : %.2f ms\n", min_rtt);
        printf(" Median RTT          : %.2f ms\n", median_rtt);
        printf(" Mean RTT            : %.2f ms\n", mean_rtt);
        printf(" p95 RTT             : %.2f ms\n", p95_rtt);
        printf(" Max RTT             : %.2f ms\n", max_rtt);
    }
    printf("=========================================\n");
}

int main(int argc, char *argv[]) {
    // Command line arguments: [1] trace_file [2] target_peer [3] scheduler
    const char *trace_file  = (argc > 1) ? argv[1] : "replay_trace.csv";
    const char *target_peer = (argc > 2) ? argv[2] : "client_1";
    const char *scheduler   = (argc > 3) ? argv[3] : "pmp";
    const char *out_log_file = "rtt_results.csv";

    // Open output log file for RTT data
    g_rtt_log_file = fopen(out_log_file, "w");
    if (!g_rtt_log_file) {
        perror("Failed to create RTT log file");
        return EXIT_FAILURE;
    }
    fprintf(g_rtt_log_file, "hit_id,send_time_ms,recv_time_ms,rtt_ms\n");

    quic_client_config_t config = {
        .peer_ips = { "45.63.15.235", "184.164.234.64" },
        .num_peer_addrs = 2,
        .local_ips = { "192.168.1.141"},
        .num_local_addrs = 1,
        .peer_port = 8000,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
        .scheduler = scheduler, /* Passed dynamically from argv[3] */
        .enable_redundancy = 1,
        .user_data = NULL
    };

    printf("Starting QUIC Client [Scheduler: '%s']...\n", scheduler);
    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) {
        fprintf(stderr, "Failed to start client!\n");
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

    printf("Waiting for handshake...\n");
    sleep(1);

    FILE *f = fopen(trace_file, "r");
    if (!f) {
        perror("Failed to open CSV trace file");
        quic_endpoint_stop(client);
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

    char line[256];
    if (!fgets(line, sizeof(line), f)) { // Skip header
        fclose(f);
        quic_endpoint_stop(client);
        fclose(g_rtt_log_file);
        return EXIT_SUCCESS;
    }

    printf("Replaying trace '%s' for peer '%s' using scheduler '%s'...\n",
           trace_file, target_peer, scheduler);
    double test_start_ms = get_time_ms();

    char peer[32];
    int hit_id;
    double send_offset_ms, inter_send_delay_ms, client_prep_ms, server_proc_ms;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, " %31[^,],%d,%lf,%lf,%lf,%lf",
                   peer, &hit_id, &send_offset_ms,
                   &inter_send_delay_ms, &client_prep_ms, &server_proc_ms) == 6) {

            if (strcmp(peer, target_peer) != 0) {
                continue;
            }

            double target_time = test_start_ms + send_offset_ms;
            double now = get_time_ms();
            if (target_time > now) {
                usleep((useconds_t)((target_time - now) * 1000.0));
            }

            hit_request_t req = {
                .hit_id = hit_id,
                .client_prep_ms = (float)client_prep_ms,
                .server_proc_ms = (float)server_proc_ms
            };

            if (g_record_count < MAX_HITS) {
                g_records[g_record_count].hit_id = hit_id;
                g_records[g_record_count].send_time_ms = get_time_ms();
                g_records[g_record_count].ack_received = 0;
                g_record_count++;
            }

            printf(">>> [CLIENT SEND] hitId=%d | prep=%.2fms | server_proc=%.2fms\n",
                   hit_id, client_prep_ms, server_proc_ms);

            quic_send(client, (const uint8_t *)&req, sizeof(req));
        }
    }

    fclose(f);

    /* Wait to process remaining ACK responses */
    sleep(2);

    // Print summary stats and close log file
    print_rtt_summary();
    if (g_rtt_log_file) {
        fclose(g_rtt_log_file);
        printf("Logged RTT details to 'rtt_results.csv'\n");
    }

    printf("Stopping client...\n");
    quic_endpoint_stop(client);
    printf("Client stopped successfully.\n");

    return EXIT_SUCCESS;
}