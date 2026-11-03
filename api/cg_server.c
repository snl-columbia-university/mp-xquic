#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "quic_api.h"

#define MAX_IPS 16

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
    int local_port;
    const char *scheduler;
    const char *congestion;
    const char *qlog;
    const char *frag_log;
    const char *raw_local_ips;
    const char *raw_peer_ips;
    int drop_on_unacked;
    int max_inflight;
    double ack_timeout_ms;
    int rtp;
    int pdu_set;
    int rtp_tag;
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

static quic_endpoint_t *g_server = NULL;
static FILE *frag_log = NULL;

// helpers
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

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000.0) + (ts.tv_nsec / 1000000.0);
}

// recieve callback
static void on_server_recv(const uint8_t *data, size_t len, void *user_data) {
    if (len >= sizeof(wire_frame_t)) {
        const wire_frame_t *frame = (const wire_frame_t *)data;

        wire_ack_t ack;
        ack.frame_id = frame->frame_id;
        ack.frag_idx = frame->frag_idx;
        ack.status = 1; 

        LOG_PRINT(2, ">>> [FRAG RECIEVED] frame_id=%d frag_idx=%d\n",
                        frame->frame_id, frame->frag_idx);

        if (frag_log) {
            fprintf(frag_log, "%d,%d,%.2f\n",
                    frame->frame_id,
                    frame->frag_idx,
                    get_time_ms());
            if (g_verbose >= 2) fflush(frag_log);
        }

        if (g_server) {
            quic_send(g_server, (const uint8_t *)&ack, sizeof(wire_ack_t));
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
        .local_port      = get_env_or_default_int("APP_PEER_PORT", 8000), // Mapped to local_port
        .scheduler       = get_env_or_default("APP_SCHEDULER", "pmp"),
        .congestion      = get_env_or_default("APP_CONGESTION", "cubic"),
        .frag_log        = get_env_or_default("APP_FRAG_LOG_FILE", "sfrags.csv"),
        .qlog            = get_env_or_default("APP_QLOG_FILE", "server.qlog"),
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
    while ((opt = getopt_long(argc, argv, "t:p:l:r:s:c:o:q:v:QF:Dw:T:RP:Gh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't': cfg.trace_file = optarg; break;
            case 'p': cfg.local_port = atoi(optarg); break;
            case 'l': cfg.raw_local_ips = optarg; break;
            case 'r': cfg.raw_peer_ips = optarg; break;
            case 's': cfg.scheduler = optarg; break;
            case 'c': cfg.congestion = optarg; break;
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

    if (num_local_addrs == 0) {
        fprintf(stderr, "Error: Must specify at least one local IP address.\n");
        return EXIT_FAILURE;
    }

    LOG_PRINT(1, "Starting QUIC ACK server on port %d...\n", cfg.local_port);
    LOG_PRINT(1, "  Scheduler  : %s\n", cfg.scheduler);
    LOG_PRINT(1, "  Congestion : %s\n", cfg.congestion);
    LOG_PRINT(1, "  Local IPs  : ");
    for (int i = 0; i < num_local_addrs; i++) {
        LOG_PRINT(1, "%s ", local_ips[i]);
    }
    LOG_PRINT(1, "\n");

    quic_server_config_t config = {
        .listen_port = cfg.local_port,
        .num_local_addrs = num_local_addrs,
        .enable_datagram = 1,
        .recv_cb = on_server_recv,
        .scheduler = cfg.scheduler,
        .congestion = cfg.congestion,
        .enable_redundancy = 1,
        .sendmmsg_on = 1,
        .rtp_encap = cfg.rtp, .rtp_pdu_set = cfg.pdu_set, .rtp_tag = cfg.rtp_tag,
        .qlog = cfg.qlog,
        .user_data = &g_server
    };

    for (int i = 0; i < num_local_addrs; i++) {
        config.local_ips[i] = local_ips[i];
    }

    frag_log = fopen(cfg.frag_log, "w");
    if (frag_log) fprintf(frag_log, "frame_id,frag_idx,recv_time_ms\n");

    g_server = quic_server_start(&config);
    if (!g_server) {
        fprintf(stderr, "Failed to initialize QUIC server endpoint.\n");
        return EXIT_FAILURE;
    }

    LOG_PRINT(1, "Server running. Waiting for client datagrams...\n");

    while (1) {
        quic_endpoint_step(g_server);
        usleep(100); 
    }

    quic_endpoint_stop(g_server);
    if (frag_log) fclose(frag_log);
    return EXIT_SUCCESS;
}