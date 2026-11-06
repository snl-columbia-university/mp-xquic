#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS  16
#define ACK_LOOKBACK 65536
#define MAX_PAYLOAD_MPS 1200 // Max safe QUIC datagram payload bytes per fragment

// Logging levels: 0 = SILENT, 1 = SUMMARY/STATUS, 2 = FULL/VERBOSE
static int g_verbose = 2; 
#define LOG_PRINT(level, fmt, ...) do { if (g_verbose >= (level)) (printf(fmt, ##__VA_ARGS__), fflush(stdout)); } while(0)

// config helpers
static const char* get_env_or_default(const char *env_var, const char *default_val) {
    const char *val = getenv(env_var);
    return (val && *val) ? val : default_val;
}

static int get_env_or_default_int(const char *env_var, int default_val) {
    const char *val = getenv(env_var);
    return (val && *val) ? atoi(val) : default_val;
}

static double get_env_or_default_double(const char *env_var, double default_val) {
    const char *val = getenv(env_var);
    return (val && *val) ? atof(val) : default_val;
}

// frame and fragment structs
typedef struct {
    int verbose;
    const char *trace_file;
    int peer_port;
    const char *scheduler;
    const char *congestion;
    const char *frame_log;
    const char *frag_log;
    const char *qlog;
    const char *raw_local_ips;
    const char *raw_peer_ips;
    int drop_on_unacked;
    int max_inflight;
    double ack_timeout_ms;
    int rtp;
    int pdu_set;
    int rtp_tag;
    int client_id;
} app_config_t;

typedef struct __attribute__((packed)) {
    int32_t frame_id;
    uint8_t frame_type;
    uint32_t frag_idx;
    uint32_t total_frags;
} wire_frame_t;

typedef struct __attribute__((packed)) {
    int32_t frame_id;
    uint32_t frag_idx;
    uint8_t status;
} wire_ack_t;

typedef struct {
    uint32_t frag_idx;
    uint32_t payload_len;
    double send_time_ms;
    double recv_time_ms;
    int ack_received;
    int refused;
} frag_record_t;

typedef struct {
    int32_t frame_id;
    int frame_type;
    size_t total_size_bytes;
    uint32_t total_frags;
    uint32_t acked_frags;
    double frame_first_send_ms;
    double frame_complete_ms;
    frag_record_t *frags;
} frame_state_t;

static frame_state_t *g_frames = NULL;
static int g_max_frames = 1024;
static int g_frame_count = 0;
static int g_remote_ack_count = 0;
static FILE *frame_log = NULL;
static FILE *frag_log = NULL;

static int g_send_refused = 0;
static int g_frames_sent = 0;
static int g_frames_skipped = 0;

// helpers
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

static int frames_inflight(double now_ms, app_config_t *cfg) {
    int n = 0, lo = g_frame_count - 64;
    if (lo < 0) lo = 0;
    for (int i = g_frame_count - 1; i >= lo; i--) {
        if (g_frames[i].acked_frags < g_frames[i].total_frags && 
           (now_ms - g_frames[i].frame_first_send_ms) < cfg->ack_timeout_ms) {
            n++;
        }
    }
    return n;
}

static int parse_ip_list(const char *str, char bufs[MAX_IPS][64], const char *ptrs[MAX_IPS]) {
    if (!str || !*str) return 0;
    char tmp[1024];
    strncpy(tmp, str, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    int count = 0;
    char *token = strtok(tmp, ",");
    while (token && count < MAX_IPS) {
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') { *end = '\0'; end--; }
        strncpy(bufs[count], token, 63);
        bufs[count][63] = '\0';
        ptrs[count] = bufs[count];
        count++;
        token = strtok(NULL, ",");
    }
    return count;
}

// clean-up helper
static void free_frames() {
    for (int i = 0; i < g_frame_count; i++) {
        if (g_frames[i].frags) free(g_frames[i].frags);
    }
    free(g_frames);
    g_frames = NULL;
}

// summary helpers
static int compare_doubles(const void *a, const void *b) {
    double arg1 = *(const double *)a;
    double arg2 = *(const double *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}
static void print_rtt_summary(void) {
    if (g_verbose < 1) return;

    double *rtts = malloc((g_frame_count > 0 ? g_frame_count : 1) * sizeof(double));
    int count = 0, lost = 0;

    for (int i = 0; i < g_frame_count; i++) {
        if (g_frames[i].acked_frags == g_frames[i].total_frags) {
            rtts[count++] = g_frames[i].frame_complete_ms - g_frames[i].frame_first_send_ms;
        } else {
            lost++;
        }
    }

    printf("\n=========================================\n");
    printf(" REPLAY SUMMARY\n");
    printf("=========================================\n");
    printf(" Frames Sent          : %d\n", g_frame_count);
    printf(" Frames Fully ACKed   : %d\n", count);
    printf(" Frames Lost/Partial  : %d\n", lost);
    printf(" Remote ACKs Received : %d\n", g_remote_ack_count);

    if (count > 0) {
        qsort(rtts, count, sizeof(double), compare_doubles);
        printf(" Min Frame RTT        : %.2f ms\n", rtts[0]);
        printf(" Median Frame RTT     : %.2f ms\n", rtts[count / 2]);
        printf(" p95 Frame RTT        : %.2f ms\n", rtts[(int)(count * 0.95)]);
        printf(" Max Frame RTT        : %.2f ms\n", rtts[count - 1]);
    }
    printf("=========================================\n");
    free(rtts);
}

// recieve callback
static void on_client_recv(const uint8_t *data, size_t len, void *user_data) {
    double recv_time = get_time_ms();
    if (len >= sizeof(wire_ack_t)) {
        const wire_ack_t *ack = (const wire_ack_t *)data;

        if (ack->frame_id < 0) return;
        g_remote_ack_count++;

        int lo = g_frame_count - ACK_LOOKBACK;
        if (lo < 0) lo = 0;

        for (int i = g_frame_count - 1; i >= lo; i--) {
            if (g_frames[i].frame_id == ack->frame_id) {

                LOG_PRINT(2, ">>> [FRAG RECIEVED] frame_id=%d frag_idx=%d frame_count=%i\n",
                ack->frame_id, ack->frag_idx, i);
                
                if (ack->frag_idx < g_frames[i].total_frags && 
                    !g_frames[i].frags[ack->frag_idx].ack_received && 
                    !g_frames[i].frags[ack->frag_idx].refused) {
                    
                    g_frames[i].frags[ack->frag_idx].recv_time_ms = recv_time;
                    g_frames[i].frags[ack->frag_idx].ack_received = 1;
                    g_frames[i].acked_frags++;

                    double frag_rtt = recv_time - g_frames[i].frags[ack->frag_idx].send_time_ms;

                    LOG_PRINT(2, ">>> [FRAG RECIEVED] frame_id=%d frag_idx=%d | Measured RTT: %.2f ms\n",
                                    ack->frame_id, ack->frag_idx, frag_rtt);

                    if (frag_log) {
                        fprintf(frag_log, "%d,%d,%.2f,%.2f,%.2f\n",
                                ack->frame_id,
                                ack->frag_idx,
                                g_frames[i].frags[ack->frag_idx].send_time_ms,
                                recv_time,
                                frag_rtt);
                        if (g_verbose >= 2) fflush(frag_log);
                    }

                    // check if frame complete
                    if (g_frames[i].acked_frags == g_frames[i].total_frags) {
                        g_frames[i].frame_complete_ms = recv_time;
                        double frame_rtt = recv_time - g_frames[i].frame_first_send_ms;
                        
                        LOG_PRINT(2, ">>> [FRAME COMPLETE] frame_id=%d | Measured RTT: %.2f ms\n",
                                    ack->frame_id, frame_rtt);

                        if (frame_log) {
                            fprintf(frame_log, "%d,%.2f,%.2f,%.2f\n",
                                    ack->frame_id,
                                    g_frames[i].frame_first_send_ms,
                                    recv_time,
                                    frame_rtt);
                            if (g_verbose >= 2) fflush(frame_log);
                        }
                    }
                }
                return;
            }
        }
    }
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
}

int main(int argc, char *argv[]) {
    app_config_t cfg = {
        .verbose         = get_env_or_default_int("APP_VERBOSE", 2),
        .trace_file      = get_env_or_default("APP_TRACE_FILE", "replay_trace.csv"),
        .peer_port       = get_env_or_default_int("APP_PEER_PORT", 8000),
        .scheduler       = get_env_or_default("APP_SCHEDULER", "pmp"),
        .congestion      = get_env_or_default("APP_CONGESTION", "cubic"),
        .frame_log       = get_env_or_default("APP_FRAME_LOG_FILE", "cframes.csv"),
        .frag_log        = get_env_or_default("APP_FRAG_LOG_FILE", "cfrags.csv"),
        .qlog            = get_env_or_default("APP_QLOG_FILE", "client.qlog"),
        .raw_local_ips   = get_env_or_default("APP_LOCAL_IPS", "127.0.0.1"),
        .raw_peer_ips    = get_env_or_default("APP_PEER_IPS", "127.0.0.2,127.0.0.3"),
        .drop_on_unacked = get_env_or_default_int("APP_DROP_ON_UNACKED", 0),
        .max_inflight    = get_env_or_default_int("APP_MAX_INFLIGHT", 1),
        .ack_timeout_ms  = get_env_or_default_double("APP_ACK_TIMEOUT_MS", 200.0),
        .rtp             = get_env_or_default_int("APP_RTP", 0),
        .pdu_set         = get_env_or_default_int("APP_PDU_SET", 0),
        .rtp_tag         = get_env_or_default_int("APP_RTP_TAG", 0)
    };

    static struct option long_options[] = {
        {"trace", required_argument, 0, 't'}, {"id", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:i:p:l:r:s:c:o:q:v:QF:Dw:T:RP:Gh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't': cfg.trace_file = optarg; break;
            case 'i': cfg.client_id = atoi(optarg); break;
            case 'p': cfg.peer_port = atoi(optarg); break;
            case 'l': cfg.raw_local_ips = optarg; break;
            case 'r': cfg.raw_peer_ips = optarg; break;
            case 's': cfg.scheduler = optarg; break;
            case 'c': cfg.congestion = optarg; break;
            case 'o': cfg.frame_log = optarg; break;
            case 'q': cfg.qlog = optarg; break;
            case 'v': cfg.verbose = atoi(optarg); break;
            case 'Q': cfg.verbose = 1; break;
            case 'F': cfg.frag_log = optarg; break;
            case 'D': cfg.drop_on_unacked = 1; break;
            case 'w': cfg.max_inflight = atoi(optarg); if (cfg.max_inflight < 1) cfg.max_inflight = 1; break;
            case 'T': cfg.ack_timeout_ms = atof(optarg); break;
            case 'R': cfg.rtp = 1; break;
            case 'P': cfg.pdu_set = atoi(optarg); break;
            case 'G': cfg.rtp_tag = 1; break;
            case 'h': print_usage(argv[0]); return EXIT_SUCCESS;
            default:  print_usage(argv[0]); return EXIT_FAILURE;
        }
    }
    
    g_verbose = cfg.verbose;

    char local_bufs[MAX_IPS][64]; const char *local_ips[MAX_IPS];
    int num_local_addrs = parse_ip_list(cfg.raw_local_ips, local_bufs, local_ips);

    char peer_bufs[MAX_IPS][64]; const char *peer_ips[MAX_IPS];
    int num_peer_addrs = parse_ip_list(cfg.raw_peer_ips, peer_bufs, peer_ips);

    frame_log = fopen(cfg.frame_log, "w");
    if (frame_log) fprintf(frame_log, "frame_id,send_time_ms,recv_time_ms,rtt_ms\n");
    frag_log = fopen(cfg.frag_log, "w");
    if (frag_log) fprintf(frag_log, "frame_id,frag_idx,send_time_ms,recv_time_ms,rtt_ms\n");

    quic_client_config_t config = {
        .num_peer_addrs = num_peer_addrs,
        .num_local_addrs = num_local_addrs,
        .peer_port = cfg.peer_port,
        .enable_datagram = 1,
        .recv_cb = on_client_recv,
        .scheduler = cfg.scheduler,
        .congestion = cfg.congestion,
        .enable_redundancy = 1,
        .sendmmsg_on = 1,
        .rtp_encap = cfg.rtp, .rtp_pdu_set = cfg.pdu_set, .rtp_tag = cfg.rtp_tag,
        .qlog = cfg.qlog,
        .user_data = NULL
    };
    for (int i = 0; i < num_peer_addrs; i++) config.peer_ips[i] = peer_ips[i];
    for (int i = 0; i < num_local_addrs; i++) config.local_ips[i] = local_ips[i];

    quic_endpoint_t *client = quic_client_start(&config);
    if (!client) return EXIT_FAILURE;

    while (!is_connected(client)) { quic_endpoint_step(client); usleep(100); }

    FILE *f = fopen(cfg.trace_file, "r");
    if (!f) return EXIT_FAILURE;

    g_frames = malloc(g_max_frames * sizeof(frame_state_t));
    char line[2048];
    int first_match = 1;
    double first_offset_ms = 0.0, test_start_ms = 0.0;
    int g_cur_frame_id = -1, g_skip_frame_id = -2;

    // loop through frames
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || strstr(line, "offset_ms") != NULL) continue;

        char line_copy[2048];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *cols[12]; int col_count = 0; char *ptr = line_copy; char *token = NULL;
        while ((token = strsep(&ptr, ",")) != NULL && col_count < 12) cols[col_count++] = token;
        if (col_count < 4) continue;

        double send_offset_ms = atof(cols[0]);
        int frame_id          = atoi(cols[1]);
        int frame_type        = atoi(cols[2]);
        int size              = atoi(cols[3]);

        if (first_match) {
            first_offset_ms = send_offset_ms;
            test_start_ms = get_time_ms();
            first_match = 0;
        }

        double rel_offset_ms = send_offset_ms - first_offset_ms;
        double target_time = test_start_ms + rel_offset_ms;
        
        // wait until time to send frame
        while (1) {
            if (get_time_ms() >= target_time) break;
            quic_endpoint_step(client);
            usleep(100); 
        }

        // backpressure
        if (cfg.drop_on_unacked && frame_id != g_cur_frame_id) {
            g_cur_frame_id = frame_id;
            if (frames_inflight(get_time_ms(), &cfg) >= cfg.max_inflight) {
                g_skip_frame_id = frame_id;
                g_frames_skipped++;
            } else {
                g_skip_frame_id = -2;
                g_frames_sent++;
            }
        }
        if (cfg.drop_on_unacked && frame_id == g_skip_frame_id) continue;

        // calculate num of fragments
        size_t total_size = (size > 0) ? (size_t)size : sizeof(wire_frame_t);
        uint32_t total_frags = (total_size + MAX_PAYLOAD_MPS - 1) / MAX_PAYLOAD_MPS;

        // init frame state
        if (g_frame_count >= g_max_frames) {
            g_max_frames *= 2;
            g_frames = realloc(g_frames, g_max_frames * sizeof(frame_state_t));
        }

        frame_state_t *frm = &g_frames[g_frame_count++];
        frm->frame_id = frame_id;
        frm->frame_type = frame_type;
        frm->total_size_bytes = total_size;
        frm->total_frags = total_frags;
        frm->acked_frags = 0;
        frm->frame_first_send_ms = get_time_ms();
        frm->frame_complete_ms = 0.0;
        frm->frags = malloc(total_frags * sizeof(frag_record_t));

        // send frags of frame in bartch
        struct iovec *iovs = malloc(total_frags * sizeof(struct iovec));
        uint8_t *sendbufs = calloc(total_frags, 1500); 

        size_t bytes_remaining = total_size;
        for (uint32_t i = 0; i < total_frags; i++) {
            size_t frag_len = (bytes_remaining > MAX_PAYLOAD_MPS) ? MAX_PAYLOAD_MPS : bytes_remaining;
            bytes_remaining -= frag_len;
            if (frag_len < sizeof(wire_frame_t)) frag_len = sizeof(wire_frame_t);
            
            frm->frags[i].frag_idx = i;
            frm->frags[i].payload_len = (uint32_t)frag_len;
            frm->frags[i].send_time_ms = get_time_ms();
            frm->frags[i].recv_time_ms = 0.0;
            frm->frags[i].ack_received = 0;
            frm->frags[i].refused = 0;

            uint8_t *sendbuf = sendbufs + (i * 1500);
            wire_frame_t *wire = (wire_frame_t *)sendbuf;
            wire->frame_id = frame_id;
            wire->frame_type = (uint8_t)frame_type;
            wire->frag_idx = i;
            wire->total_frags = total_frags;

            iovs[i].iov_base = sendbuf;
            iovs[i].iov_len = frag_len;
        }

        // send all fragments in a single call
        int error = quic_send_msg(client, iovs, total_frags);

        if (error < 0) {
            // error
            g_send_refused += total_frags;
            for (uint32_t i = 0; i < total_frags; i++) {
                frm->frags[i].refused = 1;
            }
        }

        free(sendbufs);
        free(iovs);
    }
    fclose(f);

    double end_wait = get_time_ms() + 3000.0;
    while (get_time_ms() < end_wait) {
        quic_endpoint_step(client);
        usleep(100);
    }

    print_rtt_summary();
    free_frames();

    quic_endpoint_stop(client);
    if (frame_log) fclose(frame_log);
    if (frag_log) fclose(frag_log);
    return EXIT_SUCCESS;
}