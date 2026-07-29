/**
 * @file xqc_scheduler_biphony.c
 * @brief Biphony multipath scheduler implementation for XQUIC.
 */

#include <stdio.h>
#include <math.h>
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_conn.h"

#define BIPHONY_DEFAULT_ALPHA 0.75f

typedef struct xqc_biphony_scheduler_s {
    float alpha;
    xqc_bool_t sort_by_sjf;
} xqc_biphony_scheduler_t;

static size_t
xqc_biphony_scheduler_size()
{
    return sizeof(xqc_biphony_scheduler_t);
}

static void
xqc_biphony_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_biphony_scheduler_t *sched = (xqc_biphony_scheduler_t *)scheduler;
    sched->alpha = BIPHONY_DEFAULT_ALPHA;
    sched->sort_by_sjf = XQC_FALSE;
}

xqc_path_ctx_t *
xqc_biphony_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
    xqc_bool_t *cc_blocked)
{
    xqc_biphony_scheduler_t *sched = (xqc_biphony_scheduler_t *)scheduler;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path = NULL;
    xqc_path_ctx_t *paths[2] = {NULL, NULL};
    
    // Path metrics: Q = Queue (bytes), B = Bandwidth (bytes/ms), L = Latency (ms)
    size_t Q[2] = {0, 0};
    double B[2] = {0.0, 0.0};
    double L[2] = {0.0, 0.0};
    
    int path_cnt = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    // 1. Collect available active paths and extract metrics
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        // Skip paths that are inactive, frozen, or match reinjection source
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (reinject && (packet_out->po_path_id == path->path_id)))
        {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        // Check congestion window limits
        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        if (path_cnt < 2) {
            paths[path_cnt] = path;

            // Q: In-flight queue bytes
            Q[path_cnt] = path->path_send_ctl->ctl_bytes_in_flight;

            // B: Convert estimated bandwidth from bytes/sec to bytes/ms
            uint64_t bw_bytes_sec = xqc_send_ctl_get_est_bw(path->path_send_ctl);
            B[path_cnt] = (bw_bytes_sec > 0) ? ((double)bw_bytes_sec / 1000.0) : 1.0; // Avoid division by zero

            // L: One-way delay estimation in milliseconds (using SRTT / 2)
            xqc_usec_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
            L[path_cnt] = (double)srtt / 2000.0;

            path_cnt++;
        }
    }

    // Handle path availability using a switch statement
    switch (path_cnt) {
    case 0:
        xqc_log(conn->log, XQC_LOG_ERROR, "|Biphony|No available paths|");
        return NULL;

    case 1:
        // Only one active path available; return it directly
        return paths[0];

    case 2:
    default:
        // Proceed to calculate Biphony metrics for 2 paths
        break;
    }

    // 2. Obtain Message / Frame Size (D)
    size_t D = (size_t)packet_out->po_used_size;
    // Fallback if the packet buffer hasn't been written to yet
    if (D == 0) {
        D = (size_t)packet_out->po_buf_size;
    }

    // 3. Compute Biphony Scheduling Metrics
    double R = (((double)(Q[0] + D) / B[0]) + L[0]) - (((double)(Q[1] + D) / B[1]) + L[1]);
    double C = (double)(Q[1] + D) / B[1];
    double metric = R - (sched->alpha * C);

    xqc_path_ctx_t *best_path = (metric > 0.0) ? paths[1] : paths[0];

    xqc_log(conn->log, XQC_LOG_DEBUG,
        "|Biphony|chosen_path:%ui|used_size:%ui|buf_size:%ui|Q0:%ui|Q1:%ui|metric:%.4f|",
        best_path->path_id, packet_out->po_used_size, packet_out->po_buf_size, Q[0], Q[1], metric);

    return best_path;
}

const xqc_scheduler_callback_t xqc_biphony_scheduler_cb = {
    .xqc_scheduler_size     = xqc_biphony_scheduler_size,
    .xqc_scheduler_init     = xqc_biphony_scheduler_init,
    .xqc_scheduler_get_path = xqc_biphony_scheduler_get_path,
};