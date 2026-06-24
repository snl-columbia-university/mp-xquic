/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */


#include "src/transport/scheduler/xqc_scheduler_proactive_singlepath.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"


static size_t
xqc_proactive_singlepath_scheduler_size()
{
    return 0;
}

static void
xqc_proactive_singlepath_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

xqc_path_ctx_t *
xqc_proactive_singlepath_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
    xqc_bool_t *cc_blocked)
{
    // initalize redundancy mask (which paths) and redundancy factor (how many copies)
    packet_out->po_experimental_redundancy_mask = 0;
    packet_out->po_experimental_redundancy_factor = 2;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;

    // track best path 
    xqc_path_ctx_t *best_path = NULL;
    uint64_t min_srtt = XQC_MAX_UINT64_VALUE;

    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t path_can_send = XQC_FALSE;
    
    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    // iterate through all paths, finding the 'best' one
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        // skip paths that are inactive, frozen, or match the reinjection source
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (reinject && (packet_out->po_path_id == path->path_id)))
        {
            goto skip_path;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        // check if the path's congestion control limits allow sending
        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);
        if (!path_can_send) {
            goto skip_path;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        // get path stats for this path
        uint64_t path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        float path_loss = xqc_send_ctl_get_spurious_loss_rate(path->path_send_ctl);
        float path_retrans = xqc_send_ctl_get_retrans_rate(path->path_send_ctl);
        
        // select path based on some combo of stats
        if (best_path == NULL || path_srtt < min_srtt) {
            best_path = path;
            min_srtt = path_srtt;
        }


skip_path:
        xqc_log(conn->log, XQC_LOG_DEBUG, 
                "|proactive_scheduler|conn:%p|path_id:%ui|path_srtt:%ui|"
                "can_send:%d|path_status:%d|path_state:%d|reinj:%d|"
                "pkt_path_id:%ui|current_best_path:%i|", 
                conn, path->path_id, xqc_send_ctl_get_srtt(path->path_send_ctl), 
                path_can_send, path->app_path_status, path->path_state, reinject, 
                packet_out->po_path_id,
                best_path ? (int)best_path->path_id : -1);
    }
    
    // if enabled, set mask to duplicate redundancy factor copies onto the best path
    if (best_path
        && conn->conn_settings.enable_experimental_redundancy
        && packet_out->po_frame_types & XQC_FRAME_BIT_DATAGRAM) 
    {
        packet_out->po_experimental_redundancy_mask |= ((uint32_t)1 << best_path->path_id);
        xqc_log(conn->log, XQC_LOG_INFO,
                "|proactive_redundancy_masked|conn:%p|pkt_num:%ui|replicated_to_path:%ui|current_mask:%ui|",
                conn, packet_out->po_pkt.pkt_num, best_path->path_id, packet_out->po_experimental_redundancy_mask);
            
    }

    // log scheduling outcome
    if (best_path == NULL) {
        xqc_log(conn->log, XQC_LOG_INFO, "|No available paths to schedule|conn:%p|", conn);
    } else {
        xqc_log(conn->log, XQC_LOG_INFO, "|best path chosen:%ui|pn:%ui|final_redundancy_mask:%ui|",
                best_path->path_id, packet_out->po_pkt.pkt_num, 
                packet_out->po_experimental_redundancy_mask);
    }

    return best_path;
}

const xqc_scheduler_callback_t xqc_proactive_singlepath_scheduler_cb = {
    .xqc_scheduler_size             = xqc_proactive_singlepath_scheduler_size,
    .xqc_scheduler_init             = xqc_proactive_singlepath_scheduler_init,
    .xqc_scheduler_get_path         = xqc_proactive_singlepath_scheduler_get_path,
};