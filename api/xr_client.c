#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS 16

typedef struct __attribute__((packed)) {
    int32_t hit_id, client_id;
    float client_prep_ms, server_proc_ms;
} hit_request_t;

typedef struct __attribute__((packed)) {
    int32_t hit_id, client_id;
    uint8_t status;
} hit_ack_t;

typedef struct {
    int hit_id;
    double send_time_ms, recv_time_ms, rtt_ms;
    int ack_received;
} hit_record_t;

static hit_record_t *g_records = NULL;
static int g_max_hits = 1024, g_record_count = 0, g_remote_ack_count = 0, g_my_client_id = 1;
static FILE *g_rtt_log_file = NULL;

/* --quiet: suppress per-packet send/ack logging at cloud-gaming packet rates */
static int g_quiet = 0;
/* --drop-on-unacked: frame-level backpressure. Datagrams have no delivery
   guarantee and xquic refuses them (-XQC_EAGAIN) when its send queue is full,
   so without this the sender fires into a void. Skip a frame outright if too
   many earlier frames are still unacknowledged, the way a real-time encoder
   would. */
static int g_drop_on_unacked = 0;
static int g_max_inflight    = 1;       /* --inflight: frames allowed outstanding */
static double g_ack_timeout_ms = 200.0; /* --ack-timeout-ms: write a frame off after this */
static int g_prev_frame_idx  = -1;      /* index in g_records of the last sent frame */
static int g_cur_frame_id    = -1;      /* frame currently being emitted */
static int g_skip_frame_id   = -2;      /* frame being skipped (-2 = none) */
static int g_frames_sent     = 0;
static int g_frames_skipped  = 0;

/* Frames sent, still unacked, and not yet past the timeout. Only the most
   recent 64 records can matter, so the scan is bounded. */
static int xr_frames_inflight(double now_ms) {
    int n = 0, lo = g_record_count - 64;
    if (lo < 0) lo = 0;
    for (int i = g_record_count - 1; i >= lo; i--) {
        if (!g_records[i].ack_received && (now_ms - g_records[i].send_time_ms) < g_ack_timeout_ms) n++;
    }
    return n;
}

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

static void wait_until(quic_endpoint_t *ep, double target_time_ms) {
    while (get_time_ms() < target_time_ms) {
        if (ep) quic_endpoint_step(ep);
        usleep(100);
    }
}

static int parse_ips(char *str, const char *ips[MAX_IPS]) {
    int count = 0;
    for (char *tok = strtok(str, " ,"); tok && count < MAX_IPS; tok = strtok(NULL, " ,")) {
        ips[count++] = tok;
    }
    return count;
}

static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    double recv_time = get_time_ms();
    if (len < sizeof(hit_ack_t)) return;

    const hit_ack_t *ack = (const hit_ack_t *)data;
    if (ack->client_id != g_my_client_id) {
        g_remote_ack_count++;
        printf(">>> [REMOTE ACK] hitId=%d from client_%d\n", ack->hit_id, ack->client_id);
        if (g_rtt_log_file) fprintf(g_rtt_log_file, "%d,0,0.0,%.2f,0.0\n", ack->hit_id, recv_time);
        return;
    }

    if (ack->hit_id < 0) return;   /* fragment, not a tracked frame */
    for (int i = 0; i < g_record_count; i++) {
        if (g_records[i].hit_id == ack->hit_id && !g_records[i].ack_received) {
            g_records[i].recv_time_ms = recv_time;
            g_records[i].rtt_ms = recv_time - g_records[i].send_time_ms;
            g_records[i].ack_received = 1;
            if (!g_quiet) printf(">>> [LOCAL ACK] hitId=%d | RTT: %.2f ms\n", ack->hit_id, g_records[i].rtt_ms);
            if (g_rtt_log_file) fprintf(g_rtt_log_file, "%d,1,%.2f,%.2f,%.2f\n", ack->hit_id, g_records[i].send_time_ms, recv_time, g_records[i].rtt_ms);
            return;
        }
    }
}

static int cmp_dbl(const void *a, const void *b) {
    return (*(double*)a > *(double*)b) - (*(double*)a < *(double*)b);
}

static void print_summary(void) {
    if (g_record_count == 0) return;
    double *rtts = malloc(g_record_count * sizeof(double));
    int count = 0, lost = 0;

    for (int i = 0; i < g_record_count; i++) {
        if (g_records[i].ack_received) rtts[count++] = g_records[i].rtt_ms;
        else lost++;
    }

    printf("\n=== REPLAY SUMMARY (Client ID: %d) ===\n", g_my_client_id);
    printf("Sent: %d | Rcvd: %d | Lost: %d | Remote ACKs: %d\n", g_record_count, count, lost, g_remote_ack_count);

    if (count > 0) {
        qsort(rtts, count, sizeof(double), cmp_dbl);
        printf("RTT (ms) -> Min: %.2f | Med: %.2f | p95: %.2f | Max: %.2f\n", rtts[0], rtts[count/2], rtts[(int)(count*0.95)], rtts[count-1]);
    }
    printf("=========================================\n");
    free(rtts);
}

int main(int argc, char *argv[]) {
    const char *trace_file = "replay_trace.csv", *target_peer = "client_1", *scheduler = "pmp", *congestion = "cubic";
    const char *out_log = "rtt_results.csv", *qlog = "client.qlog";
    char local_buf[1024] = "127.0.0.1", peer_buf[1024] = "127.0.0.2,127.0.0.3";
    int peer_port = 8000;

    static struct option opts[] = {
        {"trace", 1, 0, 't'}, {"id", 1, 0, 'i'}, {"port", 1, 0, 'p'}, {"local-ips", 1, 0, 'l'},
        {"peer-ips", 1, 0, 'r'}, {"scheduler", 1, 0, 's'}, {"congestion", 1, 0, 'c'},
        {"out", 1, 0, 'o'}, {"qlog", 1, 0, 'q'}, {"quiet", 0, 0, 'Q'},
        {"drop-on-unacked", 0, 0, 'D'}, {"inflight", 1, 0, 'w'}, {"ack-timeout-ms", 1, 0, 'T'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:i:p:l:r:s:c:o:q:QDw:T:h", opts, NULL)) != -1) {
        switch (opt) {
            case 't': trace_file = optarg; break; case 'i': target_peer = optarg; break;
            case 'p': peer_port = atoi(optarg); break; case 'l': strcpy(local_buf, optarg); break;
            case 'r': strcpy(peer_buf, optarg); break; case 's': scheduler = optarg; break;
            case 'c': congestion = optarg; break; case 'o': out_log = optarg; break;
            case 'q': qlog = optarg; break;
            case 'Q': g_quiet = 1; break;
            case 'D': g_drop_on_unacked = 1; break;
            case 'w': g_max_inflight = atoi(optarg); if (g_max_inflight < 1) g_max_inflight = 1; break;
            case 'T': g_ack_timeout_ms = atof(optarg); break;
            default: return EXIT_FAILURE;
        }
    }

    g_my_client_id = (sscanf(target_peer, "client_%d", &g_my_client_id) == 1) ? g_my_client_id : (atoi(target_peer) > 0 ? atoi(target_peer) : 1);

    const char *local_ips[MAX_IPS], *peer_ips[MAX_IPS];
    quic_client_config_t config = {
        .num_local_addrs = parse_ips(local_buf, local_ips), .num_peer_addrs = parse_ips(peer_buf, peer_ips),
        .peer_port = peer_port, .enable_datagram = 1, .enable_redundancy = 1, .scheduler = scheduler,
        .congestion = congestion, .qlog = qlog, .recv_cb = on_client_recv
    };
    for (int i = 0; i < config.num_local_addrs; i++) {
        config.local_ips[i] = local_ips[i];
    }
    for (int i = 0; i < config.num_peer_addrs; i++) {
        config.peer_ips[i] = peer_ips[i];
    }

    if (!(g_rtt_log_file = fopen(out_log, "w"))) return EXIT_FAILURE;
    fprintf(g_rtt_log_file, "hit_id,is_mine,send_time_ms,recv_time_ms,rtt_ms\n");

    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) return EXIT_FAILURE;

    printf("Starting QUIC Client %d...\n", g_my_client_id);
    double deadline = get_time_ms() + CONNECTION_TIMEOUT * MAX_IPS;
    while (!is_connected(client)) {
        quic_endpoint_step(client);
        usleep(100);

        if (get_time_ms() >= deadline) {
            fprintf(stderr, "Handshake failed to complete.\n");
            return EXIT_FAILURE;
        }
    }

    FILE *f = fopen(trace_file, "r");
    if (!f) return EXIT_FAILURE;

    g_records = malloc(g_max_hits * sizeof(hit_record_t));
    char line[2048], *cols[12];
    double first_offset = -1, test_start = 0;

    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "send") || (!strstr(line, "ApplyVelocity") && !strstr(line, "hit"))) continue;

        char *ptr = line;
        int c = 0;
        while ((cols[c] = strsep(&ptr, ",\r\n")) && ++c < 12);

        if (c < 8 || strcmp(cols[2], target_peer) != 0 || strcmp(cols[5], "send") != 0) continue;

        if (first_offset < 0) {
            first_offset = atof(cols[0]);
            test_start = get_time_ms();
        }

        double target_time = test_start + (atof(cols[0]) - first_offset);
        wait_until(client, target_time);

        int hit_id = atoi(cols[7]);
        /* Frame boundary: every fragment carries the frame id, so a change of
           hit_id starts a new frame. Decide once per frame whether to send it.
           This must sit AFTER the pacing wait -- a dropped frame still occupies
           its slot in the timeline, otherwise the loop races through the trace. */
        if (g_drop_on_unacked && hit_id != g_cur_frame_id) {
            g_cur_frame_id = hit_id;
            if (xr_frames_inflight(get_time_ms()) >= g_max_inflight) {
                g_skip_frame_id = hit_id;      /* window full -- drop this frame */
                g_frames_skipped++;
            } else {
                g_skip_frame_id = -2;
                g_frames_sent++;
            }
        }
        if (g_drop_on_unacked && hit_id == g_skip_frame_id) continue;   /* every fragment */

        /* col 10 is size_bytes in cloud-gaming traces; the XR trace has a JSON
           payload there, which atoi() reads as 0 -> falls back to sizeof(). */
        int size_bytes = (c > 10) ? atoi(cols[10]) : 0;
        uint8_t sendbuf[1500];
        memset(sendbuf, 0, sizeof(sendbuf));
        hit_request_t *req = (hit_request_t *)sendbuf;
        req->hit_id = hit_id;
        req->client_id = g_my_client_id;
        req->client_prep_ms = (c > 8 && *cols[8]) ? (float)atof(cols[8]) : 10.0f;
        req->server_proc_ms = (c > 9 && *cols[9]) ? (float)atof(cols[9]) : 2.0f;
        size_t send_len = (size_t)size_bytes;
        if (send_len < sizeof(hit_request_t)) send_len = sizeof(hit_request_t);
        if (send_len > sizeof(sendbuf))       send_len = sizeof(sendbuf);

        /* with -D, one record per frame (its first fragment), not per fragment */
        int is_frame_head = !g_drop_on_unacked || g_prev_frame_idx < 0
                            || g_records[g_prev_frame_idx].hit_id != hit_id;
        if (hit_id >= 0 && is_frame_head) {
            if (g_record_count >= g_max_hits) {
                g_max_hits *= 2;
                g_records = realloc(g_records, g_max_hits * sizeof(hit_record_t));
            }
            g_prev_frame_idx = g_record_count;
            g_records[g_record_count++] = (hit_record_t){.hit_id = hit_id, .send_time_ms = get_time_ms()};
        }
        if (!g_quiet) printf(">>> [CLIENT SEND] hitId=%d | len=%zu\n", hit_id, send_len);

        quic_send(client, sendbuf, send_len);
    }
    fclose(f);

    wait_until(client, get_time_ms() + 3000.0);
    if (g_drop_on_unacked) {
        printf("\n Frame flow control (inflight=%d, ack timeout=%.0fms): "
               "%d sent, %d skipped = %.1f%% skipped\n", g_max_inflight, g_ack_timeout_ms,
               g_frames_sent, g_frames_skipped,
               (g_frames_sent + g_frames_skipped) ? 100.0 * g_frames_skipped / (g_frames_sent + g_frames_skipped) : 0.0);
    }
    print_summary();

    if (g_rtt_log_file) fclose(g_rtt_log_file);
    free(g_records);
    quic_endpoint_stop(client);
    return EXIT_SUCCESS;
}