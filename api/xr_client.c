#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_HITS 4096

// --- Network Packet Structures ---

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    int32_t client_id;
    float client_prep_ms;
    float server_proc_ms;
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id;
    int32_t client_id;
    uint8_t status;
} hit_ack_t;

// --- State Tracking ---

typedef struct {
    int hit_id;
    double send_time_ms;
    double recv_time_ms;
    double rtt_ms;
    int ack_received;
} hit_record_t;

static hit_record_t g_records[MAX_HITS];
static int g_record_count = 0;
static int g_remote_ack_count = 0;
static int g_my_client_id = 1;
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

        if (ack->client_id == g_my_client_id) {
            for (int i = 0; i < g_record_count; i++) {
                if (g_records[i].hit_id == ack->hit_id && !g_records[i].ack_received) {
                    g_records[i].recv_time_ms = recv_time;
                    g_records[i].rtt_ms = recv_time - g_records[i].send_time_ms;
                    g_records[i].ack_received = 1;

                    printf(">>> [LOCAL ACK RECV] hitId=%d | Measured RTT: %.2f ms\n", 
                           ack->hit_id, g_records[i].rtt_ms);
                    fflush(stdout);

                    if (g_rtt_log_file) {
                        fprintf(g_rtt_log_file, "%d,1,%.2f,%.2f,%.2f\n",
                                ack->hit_id,
                                g_records[i].send_time_ms,
                                g_records[i].recv_time_ms,
                                g_records[i].rtt_ms);
                        fflush(g_rtt_log_file);
                    }
                    return;
                }
            }
        } else {
            g_remote_ack_count++;
            printf(">>> [REMOTE ACK RECV] hitId=%d from client_%d | recv_time=%.2f ms\n",
                   ack->hit_id, ack->client_id, recv_time);
            fflush(stdout);

            if (g_rtt_log_file) {
                fprintf(g_rtt_log_file, "%d,0,0.0,%.2f,0.0\n",
                        ack->hit_id, recv_time);
                fflush(g_rtt_log_file);
            }
            return;
        }
    }
}

// --- Summary Helper ---

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
    printf(" REPLAY SUMMARY (Client ID: %d)\n", g_my_client_id);
    printf("=========================================\n");
    printf(" Local Hits Sent      : %d\n", g_record_count);
    printf(" Local ACKs Received  : %d\n", count);
    printf(" Unanswered / Lost    : %d\n", lost);
    printf(" Remote ACKs Received : %d\n", g_remote_ack_count);

    if (count > 0) {
        qsort(rtts, count, sizeof(double), compare_doubles);
        printf(" Min Local RTT        : %.2f ms\n", rtts[0]);
        printf(" Median Local RTT     : %.2f ms\n", rtts[count / 2]);
        printf(" p95 Local RTT        : %.2f ms\n", rtts[(int)(count * 0.95)]);
        printf(" Max Local RTT        : %.2f ms\n", rtts[count - 1]);
    }
    printf("=========================================\n");
    fflush(stdout);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n\n", prog_name);
    printf("  -t, --trace FILE       Trace CSV file (default: replay_trace.csv)\n");
    printf("  -p, --peer NAME        Target peer ID (default: client_1)\n");
    printf("  -s, --scheduler ALG    Scheduler algorithm (default: pmp)\n");
    printf("  -c, --congestion ALG   Congestion algorithm (default: cubic)\n");
    printf("  -o, --out FILE         Output log (default: rtt_results.csv)\n");
}

int main(int argc, char *argv[]) {
    const char *trace_file   = "replay_trace.csv";
    const char *target_peer  = "client_1";
    int peer_port     = 8000;
    const char *scheduler    = "pmp";
    const char *congestion   = "cubic";
    const char *out_log_file = "rtt_results.csv";

    static struct option long_options[] = {
        {"trace",      required_argument, 0, 't'},
        {"id",         required_argument, 0, 'i'},
        {"port",       required_argument, 0, 'p'},
        {"scheduler",  required_argument, 0, 's'},
        {"congestion", required_argument, 0, 'c'},
        {"out",        required_argument, 0, 'o'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:p:s:c:o:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't': trace_file   = optarg; break;
            case 'i': target_peer  = optarg; break;
            case 'p': peer_port    = atoi(optarg); break;
            case 's': scheduler    = optarg; break;
            case 'c': congestion   = optarg; break;
            case 'o': out_log_file = optarg; break;
            case 'h': print_usage(argv[0]); return EXIT_SUCCESS;
            default:  print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    if (sscanf(target_peer, "client_%d", &g_my_client_id) != 1) {
        g_my_client_id = atoi(target_peer);
        if (g_my_client_id <= 0) g_my_client_id = 1;
    }

    g_rtt_log_file = fopen(out_log_file, "w");
    if (!g_rtt_log_file) {
        perror("Failed to create output file");
        return EXIT_FAILURE;
    }
    fprintf(g_rtt_log_file, "hit_id,is_mine,send_time_ms,recv_time_ms,rtt_ms\n");

    quic_client_config_t config = {
        .peer_ips = { "127.0.0.2", "127.0.0.3" },
        .num_peer_addrs = 2,
        .local_ips = { "127.0.0.1" },
        .num_local_addrs = 1,
        .peer_port = peer_port,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
        .scheduler = scheduler,
        .congestion = congestion,
        .enable_redundancy = 1,
        .user_data = NULL
    };

    printf("Starting QUIC Client [ID: %d | Peer: '%s']...\n", g_my_client_id, target_peer);
    fflush(stdout);

    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) {
        fprintf(stderr, "Failed to start client!\n");
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

    sleep(1); // Wait for connection handshake

    FILE *f = fopen(trace_file, "r");
    if (!f) {
        perror("Failed to open trace CSV");
        quic_endpoint_stop(client);
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

    printf("Replaying trace '%s' for peer '%s'...\n", trace_file, target_peer);
    fflush(stdout);

    char line[2048];
    int parsed_lines = 0;
    int matched_lines = 0;

    int first_match = 1;
    double first_offset_ms = 0.0;
    double test_start_ms = 0.0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || strstr(line, "offset_ms") != NULL) continue;

        char line_copy[2048];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        // Parse 11 CSV columns:
        // 0:offset_ms, 1:inter_event_delay_ms, 2:peer, 3:sender, 4:event, 
        // 5:direction, 6:tick, 7:hitId, 8:client_prep_ms, 9:server_proc_ms, 10:payload
        char *cols[12];
        int col_count = 0;
        char *ptr = line_copy;
        char *token = NULL;

        while ((token = strsep(&ptr, ",")) != NULL && col_count < 12) {
            cols[col_count++] = token;
        }

        if (col_count < 8) continue;

        double send_offset_ms = atof(cols[0]);
        char *peer            = cols[2];
        char *event           = cols[4];
        char *direction       = cols[5];
        int hit_id            = atoi(cols[7]);

        float client_prep_ms = (col_count > 8 && strlen(cols[8]) > 0) ? (float)atof(cols[8]) : 10.0f;
        float server_proc_ms = (col_count > 9 && strlen(cols[9]) > 0) ? (float)atof(cols[9]) : 2.0f;

        parsed_lines++;

        if (strcmp(peer, target_peer) != 0) continue;
        if (strstr(event, "ApplyVelocity") == NULL && strstr(event, "hit") == NULL) continue;
        if (strcmp(direction, "send") != 0) continue;

        matched_lines++;

        // Zero-align the timer to the peer's FIRST event
        if (first_match) {
            first_offset_ms = send_offset_ms;
            test_start_ms = get_time_ms();
            first_match = 0;
        }

        // Relative offset from this peer's start
        double rel_offset_ms = send_offset_ms - first_offset_ms;
        double target_time = test_start_ms + rel_offset_ms;
        double now = get_time_ms();
        double delay_ms = target_time - now;

        // Safely sleep only if delay is positive (prevents unsigned long overflow)
        if (delay_ms > 0.1) {
            usleep((useconds_t)(delay_ms * 1000.0));
        }

        hit_request_t req = {
            .hit_id = hit_id,
            .client_id = g_my_client_id,
            .client_prep_ms = client_prep_ms,
            .server_proc_ms = server_proc_ms
        };

        if (g_record_count < MAX_HITS) {
            g_records[g_record_count].hit_id = hit_id;
            g_records[g_record_count].send_time_ms = get_time_ms();
            g_records[g_record_count].ack_received = 0;
            g_record_count++;
        }

        printf(">>> [CLIENT SEND] hitId=%d | rel_offset=%.2fms | prep=%.2fms | srv_proc=%.2fms\n",
               hit_id, rel_offset_ms, client_prep_ms, server_proc_ms);
        fflush(stdout);

        quic_send(client, (const uint8_t *)&req, sizeof(req));
    }

    fclose(f);

    if (matched_lines == 0) {
        printf("\n[WARNING] Parsed %d rows, but 0 matched peer '%s' + event 'send'!\n", 
               parsed_lines, target_peer);
        fflush(stdout);
    }

    sleep(3);
    print_rtt_summary();
    if (g_rtt_log_file) fclose(g_rtt_log_file);

    quic_endpoint_stop(client);
    return EXIT_SUCCESS;
}