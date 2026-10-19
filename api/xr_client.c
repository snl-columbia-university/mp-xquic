#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS  16
#define ACK_LOOKBACK 65536   /* records searched per ack, newest first */

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
    int refused;          // quic_send() rejected this datagram; it never left the host
} hit_record_t;

static hit_record_t *g_records = NULL;
static int g_max_hits = 1024;
static int g_record_count = 0;
static int g_remote_ack_count = 0;
static int g_my_client_id = 1;
static FILE *g_rtt_log_file = NULL;

// --- Cloud-Gaming Replay Options ---

// -Q: suppress per-packet send/ack logging at cloud-gaming packet rates
static int g_quiet = 0;
static const char *g_frames_out = NULL;   // -F: per-frame summary CSV
static int g_send_refused = 0;

// -D: frame-level backpressure. Datagrams have no delivery guarantee and
// xquic refuses them (-XQC_EAGAIN) when its send queue is full, so without
// this the sender fires into a void. Skip a frame outright if too many
// earlier frames are still unacknowledged, the way a real-time encoder would.
static int g_drop_on_unacked = 0;
static int g_max_inflight    = 1;       // -w: frames allowed outstanding
static double g_ack_timeout_ms = 200.0; // -T: write a frame off after this
static int g_prev_frame_idx  = -1;      // index in g_records of the last sent frame
static int g_cur_frame_id    = -1;      // frame currently being emitted
static int g_skip_frame_id   = -2;      // frame being skipped (-2 = none)
static int g_frames_sent     = 0;
static int g_frames_skipped  = 0;
static int g_rtp = 0;                   // -R: QUIC-in-RTP encapsulation
static int g_pdu_set = 0;               // -P 1|2: dummy PDU Set marking ext (implies -R)
static int g_rtp_tag = 0;               // -G: end-to-end RTP/QUIC tag check

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// Frames sent, still unacked, and not yet past the timeout. Only the most
// recent 64 records can matter, so the scan is bounded.
static int xr_frames_inflight(double now_ms) {
    int n = 0, lo = g_record_count - 64;
    if (lo < 0) lo = 0;
    for (int i = g_record_count - 1; i >= lo; i--) {
        if (!g_records[i].ack_received && (now_ms - g_records[i].send_time_ms) < g_ack_timeout_ms) n++;
    }
    return n;
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

// Per-fragment ack log (ack_recv.csv): fragment seq echoed by the server, its send time, our arrival.
typedef struct { uint32_t seq; double srv_send_ms, recv_ms; } ack_rec_t;
static ack_rec_t *g_ackrec = NULL;
static size_t g_ackrec_n = 0, g_ackrec_cap = 0;

// XR_FRAG_LOG=1: per-fragment stamps / ack echo / arrival logs (off by default)
static int frag_log_on(void) { static int v = -1; if (v < 0) v = getenv("XR_FRAG_LOG") != NULL; return v; }

static void write_ack_recs(const char *dir_of) {
    char path[1024];
    const char *slash = dir_of ? strrchr(dir_of, '/') : NULL;
    if (slash) snprintf(path, sizeof(path), "%.*s/ack_recv.csv", (int)(slash - dir_of), dir_of);
    else snprintf(path, sizeof(path), "ack_recv.csv");
    FILE *o = fopen(path, "w");
    if (!o) return;
    fprintf(o, "frag_seq,srv_send_ms,recv_ms\n");
    for (size_t i = 0; i < g_ackrec_n; i++)
        fprintf(o, "%u,%.3f,%.3f\n", g_ackrec[i].seq, g_ackrec[i].srv_send_ms, g_ackrec[i].recv_ms);
    fclose(o);
}

static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    double recv_time = get_time_ms();

    if (len >= sizeof(hit_ack_t) + sizeof(uint32_t) + sizeof(double)) {
        if (g_ackrec_n == g_ackrec_cap) {
            g_ackrec_cap = g_ackrec_cap ? g_ackrec_cap * 2 : 262144;
            g_ackrec = realloc(g_ackrec, g_ackrec_cap * sizeof(*g_ackrec));
        }
        ack_rec_t *ar = &g_ackrec[g_ackrec_n++];
        memcpy(&ar->seq, data + sizeof(hit_ack_t), sizeof(uint32_t));
        memcpy(&ar->srv_send_ms, data + sizeof(hit_ack_t) + sizeof(uint32_t), sizeof(double));
        ar->recv_ms = recv_time;
    }

    if (len >= sizeof(hit_ack_t)) {
        const hit_ack_t *ack = (const hit_ack_t *)data;

        if (ack->client_id == g_my_client_id) {
            if (ack->hit_id < 0) return;   // fragment, not a tracked frame
            int lo = g_record_count - ACK_LOOKBACK;
            if (lo < 0) lo = 0;
            for (int i = g_record_count - 1; i >= lo; i--) {
                if (g_records[i].hit_id == ack->hit_id && !g_records[i].ack_received && !g_records[i].refused) {
                    g_records[i].recv_time_ms = recv_time;
                    g_records[i].rtt_ms = recv_time - g_records[i].send_time_ms;
                    g_records[i].ack_received = 1;

                    if (!g_quiet) {
                        printf(">>> [LOCAL ACK RECV] hitId=%d | Measured RTT: %.2f ms\n",
                               ack->hit_id, g_records[i].rtt_ms);
                        fflush(stdout);
                    }

                    if (g_rtt_log_file) {
                        fprintf(g_rtt_log_file, "%d,1,%.2f,%.2f,%.2f\n",
                                ack->hit_id,
                                g_records[i].send_time_ms,
                                g_records[i].recv_time_ms,
                                g_records[i].rtt_ms);
                        if (!g_quiet) fflush(g_rtt_log_file);
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

// --- Per-Frame Summary (-F) ---

// One row per frame: fragments sharing a hit_id are consecutive records.
static void write_frames(const char *path) {
    FILE *o = fopen(path, "w");
    if (!o) return;
    fprintf(o, "frame_id,first_send_ms,n_frags,n_refused,n_acked,first_ack_ms,last_ack_ms,complete_ms\n");
    for (int i = 0; i < g_record_count; ) {
        int j = i, refused = 0, acked = 0;
        double first_ack = 0, last_ack = 0;
        while (j < g_record_count && g_records[j].hit_id == g_records[i].hit_id) {
            if (g_records[j].refused) refused++;
            if (g_records[j].ack_received) {
                double r = g_records[j].recv_time_ms;
                if (!acked || r < first_ack) first_ack = r;
                if (!acked || r > last_ack) last_ack = r;
                acked++;
            }
            j++;
        }
        int n = j - i;
        fprintf(o, "%d,%.3f,%d,%d,%d,", g_records[i].hit_id, g_records[i].send_time_ms, n, refused, acked);
        if (acked) fprintf(o, "%.3f,%.3f,", first_ack, last_ack); else fprintf(o, ",,");
        if (acked == n) fprintf(o, "%.3f\n", last_ack - g_records[i].send_time_ms); else fprintf(o, "\n");
        i = j;
    }
    fclose(o);
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
    double *rtts = malloc((g_record_count > 0 ? g_record_count : 1) * sizeof(double));
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
    free(rtts);
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n\n", prog_name);
    printf("  -t, --trace FILE       Trace CSV file (default: replay_trace.csv)\n");
    printf("  -i, --id NAME          Target peer ID / Client ID (default: client_1)\n");
    printf("  -p, --port PORT        Peer port (default: 8000)\n");
    printf("  -l, --local-ips IPS    Comma-separated local IPs (default: 127.0.0.1)\n");
    printf("  -r, --peer-ips IPS     Comma-separated peer IPs (default: 127.0.0.2,127.0.0.3)\n");
    printf("  -s, --scheduler ALG    Scheduler algorithm (default: pmp)\n");
    printf("  -c, --congestion ALG   Congestion algorithm (default: cubic)\n");
    printf("  -o, --out FILE         Output log (default: rtt_results.csv)\n");
    printf("  -q, --qlog FILE        qlog output (default: client.qlog)\n");
    printf("  -Q, --quiet            No per-packet send/ack logging\n");
    printf("  -F, --frames-out FILE  Per-frame summary CSV, written at exit\n");
    printf("  -D, --drop-on-unacked  Closed loop: skip a frame while -w frames are unacked\n");
    printf("  -w, --inflight N       Frames allowed outstanding with -D (default: 1)\n");
    printf("  -T, --ack-timeout-ms M With -D, write a frame off after M ms (default: 200)\n");
    printf("  -R, --rtp              QUIC-in-RTP: 12 B RTP header on every UDP datagram (both ends)\n");
    printf("  -P, --pdu-set 1|2      With RTP: dummy 3GPP PDU Set marking extension (implies -R)\n");
    printf("  -G, --rtp-tag          With RTP: end-to-end tag check, rtp_check_*.csv (implies -R)\n");
    printf("  -h, --help             Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *trace_file   = "replay_trace.csv";
    const char *target_peer  = "client_1";
    int peer_port            = 8000;
    const char *scheduler    = "pmp";
    const char *congestion   = "cubic";
    const char *out_log_file = "rtt_results.csv";
    const char *out_qlog_file = "client.qlog";
    const char *raw_local_ips = "127.0.0.1";
    const char *raw_peer_ips  = "127.0.0.2,127.0.0.3";

    static struct option long_options[] = {
        {"trace",      required_argument, 0, 't'},
        {"id",         required_argument, 0, 'i'},
        {"port",       required_argument, 0, 'p'},
        {"local-ips",  required_argument, 0, 'l'},
        {"peer-ips",   required_argument, 0, 'r'},
        {"scheduler",  required_argument, 0, 's'},
        {"congestion", required_argument, 0, 'c'},
        {"qlog",       required_argument, 0, 'q'},
        {"out",        required_argument, 0, 'o'},
        {"quiet",      no_argument,       0, 'Q'},
        {"frames-out", required_argument, 0, 'F'},
        {"drop-on-unacked", no_argument,  0, 'D'},
        {"inflight",   required_argument, 0, 'w'},
        {"ack-timeout-ms", required_argument, 0, 'T'},
        {"rtp",        no_argument,       0, 'R'},
        {"pdu-set",    required_argument, 0, 'P'},
        {"rtp-tag",    no_argument,       0, 'G'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:p:l:r:s:c:o:q:QF:Dw:T:RP:Gh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't': trace_file    = optarg; break;
            case 'i': target_peer   = optarg; break;
            case 'p': peer_port     = atoi(optarg); break;
            case 'l': raw_local_ips = optarg; break;
            case 'r': raw_peer_ips  = optarg; break;
            case 's': scheduler     = optarg; break;
            case 'c': congestion    = optarg; break;
            case 'o': out_log_file  = optarg; break;
            case 'q': out_qlog_file = optarg; break;
            case 'Q': g_quiet = 1; break;
            case 'F': g_frames_out = optarg; break;
            case 'D': g_drop_on_unacked = 1; break;
            case 'w': g_max_inflight = atoi(optarg); if (g_max_inflight < 1) g_max_inflight = 1; break;
            case 'T': g_ack_timeout_ms = atof(optarg); break;
            case 'R': g_rtp = 1; break;
            case 'P': g_pdu_set = atoi(optarg); break;
            case 'G': g_rtp_tag = 1; break;
            case 'h': print_usage(argv[0]); return EXIT_SUCCESS;
            default:  print_usage(argv[0]); return EXIT_FAILURE;
        }
    }

    char local_bufs[MAX_IPS][64];
    const char *local_ips[MAX_IPS];
    int num_local_addrs = parse_ip_list(raw_local_ips, local_bufs, local_ips);

    char peer_bufs[MAX_IPS][64];
    const char *peer_ips[MAX_IPS];
    int num_peer_addrs = parse_ip_list(raw_peer_ips, peer_bufs, peer_ips);

    if (num_local_addrs == 0 || num_peer_addrs == 0) {
        fprintf(stderr, "Error: Must specify at least one local and peer IP address.\n");
        return EXIT_FAILURE;
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
        .num_peer_addrs = num_peer_addrs,
        .num_local_addrs = num_local_addrs,
        .peer_port = peer_port,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
        .scheduler = scheduler,
        .congestion = congestion,
        .enable_redundancy = 1,
        .sendmmsg_on = 1,
        .rtp_encap = g_rtp, .rtp_pdu_set = g_pdu_set, .rtp_tag = g_rtp_tag,
        .qlog = out_qlog_file,
        .user_data = NULL
    };

    for (int i = 0; i < num_peer_addrs; i++) {
        config.peer_ips[i] = peer_ips[i];
    }
    for (int i = 0; i < num_local_addrs; i++) {
        config.local_ips[i] = local_ips[i];
    }

    printf("Starting QUIC Client [ID: %d | Peer: '%s']...\n", g_my_client_id, target_peer);
    printf("Local IPs (%d): ", num_local_addrs);
    for (int i = 0; i < num_local_addrs; i++) printf("%s ", local_ips[i]);
    printf("\nPeer IPs  (%d): ", num_peer_addrs);
    for (int i = 0; i < num_peer_addrs; i++) printf("%s ", peer_ips[i]);
    printf("\n");
    fflush(stdout);

    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) {
        fprintf(stderr, "Failed to start client!\n");
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

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
    if (!f) {
        perror("Failed to open trace CSV");
        quic_endpoint_stop(client);
        fclose(g_rtt_log_file);
        return EXIT_FAILURE;
    }

    printf("Replaying trace '%s' for peer '%s'...\n", trace_file, target_peer);
    fflush(stdout);

    g_records = malloc(g_max_hits * sizeof(hit_record_t));
    if (!g_records) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

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

        if (first_match) {
            first_offset_ms = send_offset_ms;
            test_start_ms = get_time_ms();
            first_match = 0;
        }

        double rel_offset_ms = send_offset_ms - first_offset_ms;
        double target_time = test_start_ms + rel_offset_ms;
        
        // Wait non-blocking until target send time
        while (1) {
            double now = get_time_ms();
            if (now >= target_time) break;
            quic_endpoint_step(client);
            usleep(100); 
        }

        // Frame boundary: every fragment carries the frame id, so a change of
        // hit_id starts a new frame. Decide once per frame whether to send it.
        // This must sit AFTER the pacing wait -- a dropped frame still occupies
        // its slot in the timeline, otherwise the loop races through the trace.
        if (g_drop_on_unacked && hit_id != g_cur_frame_id) {
            g_cur_frame_id = hit_id;
            if (xr_frames_inflight(get_time_ms()) >= g_max_inflight) {
                g_skip_frame_id = hit_id;      // window full -- drop this frame
                g_frames_skipped++;
            } else {
                g_skip_frame_id = -2;
                g_frames_sent++;
            }
        }
        if (g_drop_on_unacked && hit_id == g_skip_frame_id) continue;   // every fragment

        // col 10 is size_bytes in cloud-gaming traces; the XR trace has a JSON
        // payload there, which atoi() reads as 0 -> falls back to sizeof().
        int size_bytes = (col_count > 10) ? atoi(cols[10]) : 0;
        uint8_t sendbuf[1500];
        memset(sendbuf, 0, sizeof(sendbuf));
        hit_request_t *req = (hit_request_t *)sendbuf;
        req->hit_id = hit_id;
        req->client_id = g_my_client_id;
        req->client_prep_ms = client_prep_ms;
        req->server_proc_ms = server_proc_ms;
        size_t send_len = (size_t)size_bytes;
        if (send_len < sizeof(hit_request_t)) send_len = sizeof(hit_request_t);
        if (send_len > sizeof(sendbuf))       send_len = sizeof(sendbuf);

        // with -D, one record per frame (its first fragment), not per fragment
        int is_frame_head = !g_drop_on_unacked || g_prev_frame_idx < 0
                            || g_records[g_prev_frame_idx].hit_id != hit_id;
        int rec_idx = -1;
        if (hit_id >= 0 && is_frame_head) {
            if (g_record_count >= g_max_hits) {
                g_max_hits *= 2;
                g_records = realloc(g_records, g_max_hits * sizeof(hit_record_t));
                if (!g_records) {
                    fprintf(stderr, "Out of memory\n");
                    return EXIT_FAILURE;
                }
            }
            g_prev_frame_idx = g_record_count;
            rec_idx = g_record_count;
            g_records[g_record_count++] = (hit_record_t){ .hit_id = hit_id, .send_time_ms = get_time_ms() };
        }

        if (!g_quiet) {
            printf(">>> [CLIENT SEND] hitId=%d | rel_offset=%.2fms | prep=%.2fms | srv_proc=%.2fms | len=%zu\n",
                   hit_id, rel_offset_ms, client_prep_ms, server_proc_ms, send_len);
            fflush(stdout);
        }

        // per-fragment stamp after the header: global fragment seq + send time (CLOCK_MONOTONIC ms)
        static uint32_t frag_seq = 0;
        if (frag_log_on() && send_len >= sizeof(hit_request_t) + sizeof(uint32_t) + sizeof(double)) {
            uint32_t seq = ++frag_seq;
            double t_send = get_time_ms();
            memcpy(sendbuf + sizeof(hit_request_t), &seq, sizeof(seq));
            memcpy(sendbuf + sizeof(hit_request_t) + sizeof(seq), &t_send, sizeof(t_send));
        }

        if (quic_send(client, sendbuf, send_len) < 0) {
            g_send_refused++;
            if (rec_idx >= 0) g_records[rec_idx].refused = 1;
        }
    }

    fclose(f);

    if (matched_lines == 0) {
        printf("\n[WARNING] Parsed %d rows, but 0 matched peer '%s' + event 'send'!\n", 
               parsed_lines, target_peer);
        fflush(stdout);
    }

    // Process network events to catch final ACKs
    double end_wait = get_time_ms() + 3000.0;
    while(get_time_ms() < end_wait) {
        quic_endpoint_step(client);
        usleep(100);
    }

    if (g_drop_on_unacked) {
        printf("\n Frame flow control (inflight=%d, ack timeout=%.0fms): "
               "%d sent, %d skipped = %.1f%% skipped\n", g_max_inflight, g_ack_timeout_ms,
               g_frames_sent, g_frames_skipped,
               (g_frames_sent + g_frames_skipped) ? 100.0 * g_frames_skipped / (g_frames_sent + g_frames_skipped) : 0.0);
    }
    print_rtt_summary();
    if (g_send_refused) printf("Refused by quic_send (never sent): %d\n", g_send_refused);
    if (g_frames_out) write_frames(g_frames_out);
    if (frag_log_on()) write_ack_recs(g_frames_out);
    fflush(stdout);

    // stop first: acks delivered during teardown still reach on_client_recv
    quic_endpoint_stop(client);
    if (g_rtt_log_file) { fclose(g_rtt_log_file); g_rtt_log_file = NULL; }
    free(g_records);
    g_records = NULL;
    fflush(stdout);
    fflush(stderr);
    exit(EXIT_SUCCESS);
}