#include "src/transport/scheduler/xqc_scheduler_optimization_multipath.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "xquic/xquic_typedef.h"
#include <float.h>

#define TARGET_LOSS 1e-4
#define MAX_PATHS 16
#define BETA_LATENCY 1.0f
#define GAMMA_JITTER 10.0f
#define ALPHA_BW 0.1f
#define PATH_CAP 6

static size_t
xqc_optimization_multipath_scheduler_size()
{
    return 0;
}

static void
xqc_optimization_multipath_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

// optimization helper
static float eval_mask_cost(xqc_path_ctx_t **paths, int count, uint32_t mask, int pkt_sz, 
                            float *out_loss, float *out_lat, float *out_jit, float *out_bw) {
    xqc_usec_t min_srtt = UINT64_MAX;
    float total_bw = 0.0f, sum_cond = 0.0f, loss = 1.0f;

    // latency and bandwidth cost
    for (int i = 0; i < count; i++) {
        if (mask & (1 << i)) {
            xqc_send_ctl_t *ctl = paths[i]->path_send_ctl;
            min_srtt = (ctl->ctl_srtt < min_srtt) ? ctl->ctl_srtt : min_srtt;
            
            uint64_t bw_est = xqc_send_ctl_get_est_bw(ctl);
            float bw_cost = (bw_est > 0) ? ((float)pkt_sz * 1e6f) / (float)bw_est : 1e6f;
            total_bw += ALPHA_BW * bw_cost;
            
            float l = xqc_send_ctl_get_retrans_rate(ctl);
            loss *= (l < 1e-6f ? 1e-6f : l);
        }
    }

    // jitter penalty
    for (int i = 0; i < count; i++) {
        if (mask & (1 << i)) {
            xqc_send_ctl_t *ctl = paths[i]->path_send_ctl;
            float jitter = ctl->ctl_rttvar > 1 ? (float)ctl->ctl_rttvar : 1.0f;
            sum_cond += 1.0f / ((ctl->ctl_srtt - min_srtt) + (jitter));
        }
    }

    *out_loss = loss;
    
    // calculate final components
    float lat_cost = BETA_LATENCY * (float)min_srtt;
    float jit_cost = GAMMA_JITTER * (1.0f / sum_cond);
    
    if (out_lat) *out_lat = lat_cost;
    if (out_jit) *out_jit = jit_cost;
    if (out_bw)  *out_bw  = total_bw;

    return lat_cost + jit_cost + total_bw;
}

xqc_path_ctx_t *
xqc_optimization_multipath_scheduler_get_path(void *scheduler, xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out, int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    packet_out->po_experimental_redundancy_factor = 1;
    packet_out->po_experimental_redundancy_mask = 0;

    xqc_path_ctx_t *paths[MAX_PATHS], *path;
    xqc_list_head_t *pos, *next;
    int count = 0, active_found = 0, cwnd_found = 0;

    // filter paths
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|opt_sched_path| path:%ui state:%d app_status:%d srtt:%ui rttvar:%ui latest_rtt:%ui min_rtt:%ui|",
                path->path_id, path->path_state, path->app_path_status,
                path->path_send_ctl->ctl_srtt, path->path_send_ctl->ctl_rttvar,
                path->path_send_ctl->ctl_latest_rtt, path->path_send_ctl->ctl_minrtt);
        if (path->path_state != XQC_PATH_STATE_ACTIVE || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN) continue;
        active_found = 1;
        
        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) continue;
        cwnd_found = 1;
        
        if (path->path_send_ctl->ctl_srtt > 0 && count < MAX_PATHS) {
            paths[count++] = path;
        }
    }

    if (cc_blocked) *cc_blocked = (active_found && !cwnd_found);
    if (!count) {xqc_log(conn->log, XQC_LOG_WARN, "|opt_sched| count:%d|", count); return NULL;}

    // find primary path
    int best_idx = -1;
    uint32_t best_mask = 0;
    float min_cost = FLT_MAX, joint_loss = 1.0f;
    float current_lat = 0, current_jit = 0, current_bw = 0;

    for (int i = 0; i < count; i++) {
        float loss, lat, jit, bw;
        float cost = eval_mask_cost(paths, count, 1 << i, packet_out->po_used_size, &loss, &lat, &jit, &bw);
        if (cost < min_cost) { 
            min_cost = cost; best_mask = 1 << i; best_idx = i; joint_loss = loss; 
            current_lat = lat; current_jit = jit; current_bw = bw;
        }
    }

    // greedy add redundancy (driven by loss constraint OR latency reduction)
    int paths_added = 0;
    if (conn->conn_settings.enable_experimental_redundancy && (packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM)) {
        while (1) {
            float best_marg = FLT_MAX, next_loss = joint_loss;
            int next_idx = -1;
            float best_lat = 0, best_jit = 0, best_bw = 0;
            
            for (int i = 0; i < count; i++) {
                if (!(best_mask & (1 << i))) {
                    float l, lat, jit, bw;
                    float c = eval_mask_cost(paths, count, best_mask | (1 << i), packet_out->po_used_size, &l, &lat, &jit, &bw);
                    if (c < best_marg) { 
                        best_marg = c; 
                        next_idx = i; 
                        next_loss = l; 
                        best_lat = lat; best_jit = jit; best_bw = bw;
                    }
                }
            }

            if (next_idx == -1) break;

            if ((joint_loss > TARGET_LOSS || best_marg < min_cost) && (paths_added < PATH_CAP - 1)) {
                xqc_log(conn->log, XQC_LOG_DEBUG, 
                        "|opt_sched_dup| ADDED path:%ui | reason:%s | loss:%.6f (target:%.6f) | old (lat:%.1f jit:%.1f bw:%.1f = %.1f) | new (lat:%.1f jit:%.1f bw:%.1f = %.1f)|",
                        paths[next_idx]->path_id,
                        (joint_loss > TARGET_LOSS) ? "loss_constraint" : "cost_reduction",
                        joint_loss, TARGET_LOSS,
                        current_lat, current_jit, current_bw, min_cost,
                        best_lat, best_jit, best_bw, best_marg);
                
                best_mask |= (1 << next_idx);
                joint_loss = next_loss;
                min_cost = best_marg;
                current_lat = best_lat; current_jit = best_jit; current_bw = best_bw;
                paths_added++;
            } else if (paths_added == PATH_CAP - 1){
                xqc_log(conn->log, XQC_LOG_DEBUG, 
                        "|opt_sched_dup| PATH_CAP met");
                break;
            } else {
                xqc_log(conn->log, XQC_LOG_DEBUG, 
                        "|opt_sched_dup| REJECTED path:%ui | old_loss:%.6f target:%.6f | old_cost:%.1f new_cost:%.1f|",
                        paths[next_idx]->path_id,
                        joint_loss, TARGET_LOSS, min_cost, best_marg);
                break;
            }
        }
    }

    // implement best mask
    for (int i = 0; i < count; i++) {
        if ((best_mask & (1 << i)) && i != best_idx) {
            packet_out->po_experimental_redundancy_mask |= (1 << paths[i]->path_id);
        }
    }

    xqc_log(conn->log, XQC_LOG_INFO, 
            "|opt_sched| primary_path:%ui mask:0x%ui cost:%.1f joint_loss:%.6f count:%d|", 
            paths[best_idx]->path_id, 
            packet_out->po_experimental_redundancy_mask, 
            min_cost, 
            joint_loss, 
            count);
    
    return paths[best_idx];
}

const xqc_scheduler_callback_t xqc_optimization_multipath_scheduler_cb = {
    .xqc_scheduler_size             = xqc_optimization_multipath_scheduler_size,
    .xqc_scheduler_init             = xqc_optimization_multipath_scheduler_init,
    .xqc_scheduler_get_path         = xqc_optimization_multipath_scheduler_get_path,
};