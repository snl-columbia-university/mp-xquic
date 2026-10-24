#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS 16
#define MAX_PENDING 4096

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

typedef struct {
    int active;
    hit_ack_t ack;
    double target_send_time_ms;
    uint32_t frag_seq;      // 0 = fragment had no per-fragment stamp
} pending_ack_t;

static quic_endpoint_t *g_server = NULL;
static quic_endpoint_t *g_server2 = NULL;
static pending_ack_t g_pending_acks[MAX_PENDING] = {0};
static int g_rtp = 0;                   // -R: QUIC-in-RTP encapsulation
static int g_pdu_set = 0;               // -P 1|2: dummy PDU Set marking ext (implies -R)
static int g_rtp_tag = 0;               // -G: end-to-end RTP/QUIC tag check

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

// Per-frame arrival log (server_recv.csv in the cwd): first/last fragment arrival.
typedef struct { int n; double first_ms, last_ms; } frame_arrival_t;
static frame_arrival_t *g_arr = NULL;
static int g_arr_cap = 0;

// XR_FRAG_LOG=1: per-fragment stamps / ack echo / arrival logs (off by default)
static int frag_log_on(void) { static int v = -1; if (v < 0) v = getenv("XR_FRAG_LOG") != NULL; return v; }

static void write_arrivals(void) {
    FILE *o = fopen("server_recv.csv", "w");
    if (!o) return;
    fprintf(o, "frame_id,n_recv,first_recv_ms,last_recv_ms\n");
    for (int i = 0; i < g_arr_cap; i++)
        if (g_arr[i].n) fprintf(o, "%d,%d,%.3f,%.3f\n", i, g_arr[i].n, g_arr[i].first_ms, g_arr[i].last_ms);
    fclose(o);
}

// Per-fragment log (frag_recv.csv): one row per unique fragment that reached the server.
typedef struct { uint32_t seq; int32_t frame; double send_ms, recv_ms; } frag_rec_t;
static frag_rec_t *g_frag = NULL;
static size_t g_frag_n = 0, g_frag_cap = 0;

static void write_frags(void) {
    FILE *o = fopen("frag_recv.csv", "w");
    if (!o) return;
    fprintf(o, "frag_seq,frame_id,send_ms,recv_ms\n");
    for (size_t i = 0; i < g_frag_n; i++)
        fprintf(o, "%u,%d,%.3f,%.3f\n", g_frag[i].seq, g_frag[i].frame, g_frag[i].send_ms, g_frag[i].recv_ms);
    fclose(o);
}

static void on_term(int sig) { (void)sig; if (getenv("XR_FEC") && g_server) quic_endpoint_print_stats(g_server); if (frag_log_on()) { write_arrivals(); write_frags(); } _exit(0); }

static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    if (len >= sizeof(hit_request_t)) {
        const hit_request_t *req = (const hit_request_t *)data;

        if (frag_log_on() && req->hit_id >= 0) {
            double t = get_time_ms();
            if (req->hit_id >= g_arr_cap) {
                int cap = g_arr_cap ? g_arr_cap : 8192;
                while (cap <= req->hit_id) cap *= 2;
                g_arr = realloc(g_arr, cap * sizeof(*g_arr));
                memset(g_arr + g_arr_cap, 0, (cap - g_arr_cap) * sizeof(*g_arr));
                g_arr_cap = cap;
            }
            if (len >= sizeof(hit_request_t) + sizeof(uint32_t) + sizeof(double)) {
                if (g_frag_n == g_frag_cap) {
                    g_frag_cap = g_frag_cap ? g_frag_cap * 2 : 262144;
                    g_frag = realloc(g_frag, g_frag_cap * sizeof(*g_frag));
                }
                frag_rec_t *fr = &g_frag[g_frag_n++];
                memcpy(&fr->seq, data + sizeof(hit_request_t), sizeof(fr->seq));
                memcpy(&fr->send_ms, data + sizeof(hit_request_t) + sizeof(fr->seq), sizeof(fr->send_ms));
                fr->frame = req->hit_id;
                fr->recv_ms = t;
            }
            frame_arrival_t *a = &g_arr[req->hit_id];
            if (!a->n) a->first_ms = t;
            a->last_ms = t;
            a->n++;
        }

        if (!getenv("XR_MIN_LOG")) printf("<<< [SERVER RECV] hitId=%d from client_%d | Requested processing delay: %.2f ms\n",
               req->hit_id, req->client_id, req->server_proc_ms);

        hit_ack_t ack = {
            .hit_id = req->hit_id,
            .client_id = req->client_id,
            .status = 1
        };

        // Queue the ACK instead of sleeping
        for (int i = 0; i < MAX_PENDING; i++) {
            if (!g_pending_acks[i].active) {
                g_pending_acks[i].ack = ack;
                g_pending_acks[i].frag_seq = 0;
                if (frag_log_on() && len >= sizeof(hit_request_t) + sizeof(uint32_t) + sizeof(double))
                    memcpy(&g_pending_acks[i].frag_seq, data + sizeof(hit_request_t), sizeof(uint32_t));
                g_pending_acks[i].target_send_time_ms = get_time_ms() + req->server_proc_ms;
                g_pending_acks[i].active = 1;
                break;
            }
        }
    }
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n\n", prog_name);
    printf("  -l, --local-ips IPS    Comma-separated local IPs to bind (default: 127.0.0.2,127.0.0.3)\n");
    printf("  -s, --scheduler ALG    Scheduler algorithm (default: pmp)\n");
    printf("  -c, --congestion ALG   Congestion algorithm (default: cubic)\n");
    printf("  -R, --rtp              QUIC-in-RTP: 12 B RTP header on every UDP datagram (both ends)\n");
    printf("  -P, --pdu-set 1|2      With RTP: dummy 3GPP PDU Set marking extension (implies -R)\n");
    printf("  -G, --rtp-tag          With RTP: end-to-end tag check, rtp_check_*.csv (implies -R)\n");
    printf("  -h, --help             Show this help message\n");
}

int main(int argc, char *argv[]) {
    const char *scheduler     = "pmp";
    const char *congestion    = "cubic";
    const char *raw_local_ips = "127.0.0.2,127.0.0.3";
    const char *out_qlog_file = "server.qlog";

    static struct option long_options[] = {
        {"local-ips",  required_argument, 0, 'l'},
        {"scheduler",  required_argument, 0, 's'},
        {"congestion", required_argument, 0, 'c'},
        {"qlog",       required_argument, 0, 'q'},
        {"rtp",        no_argument,       0, 'R'},
        {"pdu-set",    required_argument, 0, 'P'},
        {"rtp-tag",    no_argument,       0, 'G'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "l:s:c:q:RP:Gh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l': raw_local_ips = optarg; break;
            case 's': scheduler     = optarg; break;
            case 'c': congestion    = optarg; break;
            case 'q': out_qlog_file = optarg; break;
            case 'R': g_rtp = 1; break;
            case 'P': g_pdu_set = atoi(optarg); break;
            case 'G': g_rtp_tag = 1; break;
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

    // --- Server Endpoint Config (Port 8000) ---
    quic_server_config_t config = {
        .listen_port = 8000,
        .num_local_addrs = num_local_addrs,
        .enable_datagram = 1,
        .recv_cb = on_server_recv,
        .scheduler = scheduler,
        .congestion = congestion,
        .enable_redundancy = 1,
        .sendmmsg_on = 1,
        .rtp_encap = g_rtp, .rtp_pdu_set = g_pdu_set, .rtp_tag = g_rtp_tag,
        .qlog = out_qlog_file,
        .user_data = &g_server
    };

    for (int i = 0; i < num_local_addrs; i++) {
        config.local_ips[i] = local_ips[i];
    }

    printf("Starting QUIC Replay Server 1 on port 8000...\n");
    g_server = quic_server_start(&config);
    if (!g_server) {
        fprintf(stderr, "Failed to start Server 1!\n");
        return EXIT_FAILURE;
    }

    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    printf("Server running. Press Ctrl+C to stop.\n");
    
    // Main Non-Blocking Loop
    while (1) {
        if (g_server) quic_endpoint_step(g_server);

        double now = get_time_ms();
        for (int i = 0; i < MAX_PENDING; i++) {
            if (g_pending_acks[i].active && now >= g_pending_acks[i].target_send_time_ms) {
                if (!getenv("XR_MIN_LOG")) printf(">>> [SERVER ACK SEND] hitId=%d to client_%d\n", g_pending_acks[i].ack.hit_id, g_pending_acks[i].ack.client_id);
                if (g_server) {
                    // ack + echo of the fragment seq + server send time (CLOCK_MONOTONIC ms)
                    uint8_t abuf[sizeof(hit_ack_t) + sizeof(uint32_t) + sizeof(double)];
                    size_t alen = sizeof(hit_ack_t);
                    memcpy(abuf, &g_pending_acks[i].ack, sizeof(hit_ack_t));
                    if (g_pending_acks[i].frag_seq) {
                        double t_ack = get_time_ms();
                        memcpy(abuf + alen, &g_pending_acks[i].frag_seq, sizeof(uint32_t));
                        memcpy(abuf + alen + sizeof(uint32_t), &t_ack, sizeof(double));
                        alen = sizeof(abuf);
                    }
                    quic_send(g_server, abuf, alen);
                }
                g_pending_acks[i].active = 0;
            }
        }
        
        usleep(100);
    }

    quic_endpoint_stop(g_server);
    return EXIT_SUCCESS;
}