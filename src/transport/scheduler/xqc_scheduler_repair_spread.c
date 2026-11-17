/**
 * Repair-spread multipath scheduler: sources on the best path, one repair per other path.
 *
 * Every packet that is not a REPAIR packet (FEC-protected datagrams, ACK-only, control) is
 * scheduled like minrtt, so all source packets of a block go on the lowest-srtt path.
 * REPAIR packets go round-robin over the other active paths, so with RS k + r and r = number of
 * other paths, every repair of a block lands on a different path. A cwnd-blocked path is skipped
 * (the next one in order takes the repair); with no other path, repairs fall back to minrtt.
 * XR_RPR_PATHS=p (env, read once at init) keeps the repairs on the p lowest-srtt non-best paths,
 * so RS k + p puts exactly one repair on each of p extra paths; unset or 0 = all other paths.
 */
#include <stdlib.h>
#include "src/transport/scheduler/xqc_scheduler_repair_spread.h"
#include "src/transport/scheduler/xqc_scheduler_minrtt.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"

#define XQC_RSPREAD_MAX_PATHS 32

typedef struct {
    uint64_t rr;            /* round-robin position over the repair paths */
    int      max_paths;     /* XR_RPR_PATHS: repair paths used, 0 = all non-best paths */
} xqc_repair_spread_scheduler_t;

static size_t
xqc_repair_spread_scheduler_size()
{
    return sizeof(xqc_repair_spread_scheduler_t);
}

static void
xqc_repair_spread_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_repair_spread_scheduler_t *s = (xqc_repair_spread_scheduler_t *)scheduler;
    const char *e = getenv("XR_RPR_PATHS");
    s->rr = 0;
    s->max_paths = e ? atoi(e) : 0;
}

static xqc_path_ctx_t *
xqc_repair_spread_scheduler_get_path(void *scheduler, xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_repair_spread_scheduler_t *s = (xqc_repair_spread_scheduler_t *)scheduler;

    if (!(packet_out->po_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL) || reinject) {
        return xqc_minrtt_scheduler_cb.xqc_scheduler_get_path(scheduler, conn, packet_out,
                                                              check_cwnd, reinject, cc_blocked);
    }

    /* active paths in list order, and the lowest-srtt one (where the sources go) */
    xqc_path_ctx_t *paths[XQC_RSPREAD_MAX_PATHS], *best = NULL;
    int n = 0;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        xqc_path_ctx_t *p = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (p->path_state != XQC_PATH_STATE_ACTIVE || p->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || n >= XQC_RSPREAD_MAX_PATHS)
        {
            continue;
        }
        paths[n++] = p;
        if (best == NULL || xqc_send_ctl_get_srtt(p->path_send_ctl) < xqc_send_ctl_get_srtt(best->path_send_ctl)) {
            best = p;
        }
    }
    if (n <= 1) {
        return xqc_minrtt_scheduler_cb.xqc_scheduler_get_path(scheduler, conn, packet_out,
                                                              check_cwnd, reinject, cc_blocked);
    }

    /* drop the best path, keep list order */
    int m = 0;
    for (int i = 0; i < n; i++) {
        if (paths[i] != best) {
            paths[m++] = paths[i];
        }
    }

    /* XR_RPR_PATHS: keep only the p lowest-srtt of them, in srtt order */
    if (s->max_paths > 0 && m > s->max_paths) {
        for (int i = 0; i < s->max_paths; i++) {
            int lo = i;
            for (int j = i + 1; j < m; j++) {
                if (xqc_send_ctl_get_srtt(paths[j]->path_send_ctl) < xqc_send_ctl_get_srtt(paths[lo]->path_send_ctl)) {
                    lo = j;
                }
            }
            xqc_path_ctx_t *t = paths[i]; paths[i] = paths[lo]; paths[lo] = t;
        }
        m = s->max_paths;
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }
    for (int i = 0; i < m; i++) {
        int idx = (int)((s->rr + i) % m);
        if (xqc_scheduler_check_path_can_send(paths[idx], packet_out, check_cwnd)) {
            s->rr = s->rr + i + 1;
            xqc_log(conn->log, XQC_LOG_DEBUG, "|rspread|repair|path:%ui|pos:%d/%d|best:%ui|",
                    paths[idx]->path_id, idx, m, best->path_id);
            return paths[idx];
        }
    }
    if (cc_blocked) {
        *cc_blocked = XQC_TRUE;
    }
    return NULL;
}

const xqc_scheduler_callback_t xqc_repair_spread_scheduler_cb = {
    .xqc_scheduler_size             = xqc_repair_spread_scheduler_size,
    .xqc_scheduler_init             = xqc_repair_spread_scheduler_init,
    .xqc_scheduler_get_path         = xqc_repair_spread_scheduler_get_path,
};
