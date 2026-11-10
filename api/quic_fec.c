#include "quic_api.h"
#include "quic_fec.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// FEC for datagrams, using xquic's FEC framework (xqc_fec.c). Off unless config->scheme is set.
// Both ends must use the same scheme. Repairs protect datagrams sent at QoS 3-6, so with FEC on
// the datagram sends use NORMAL instead of HIGHEST.

void quic_fec_init(quic_endpoint_t *ep, const quic_fec_config_t *config, xqc_conn_settings_t *cs) {
    ep->fec_on = 0;
    ep->fec_standby_mask = 0;
    if (!config || !config->scheme || !*config->scheme) return;

#ifdef XQC_ENABLE_FEC
    const char *v = config->scheme;
    xqc_fec_schemes_e sc = strcmp(v, "rs") == 0  ? XQC_REED_SOLOMON_CODE
                         : strcmp(v, "pkm") == 0 ? XQC_PACKET_MASK_CODE : XQC_XOR_CODE;
    cs->enable_encode_fec = 1;
    cs->enable_decode_fec = 1;
    cs->fec_params.fec_encoder_schemes[0] = sc;
    cs->fec_params.fec_decoder_schemes[0] = sc;
    cs->fec_params.fec_encoder_schemes_num = 1;
    cs->fec_params.fec_decoder_schemes_num = 1;
    if (config->block > 0) cs->fec_params.fec_max_symbol_num_per_block = config->block;
    if (config->rate > 0) cs->fec_params.fec_code_rate = config->rate;
    if (config->repairs_on_standby) cs->fec_params.fec_mp_mode = XQC_FEC_MP_USE_STB;

    /* standby_paths = "3,4,5": path indexes (creation order) to create as standby */
    if (config->standby_paths) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s", config->standby_paths);
        for (char *t = strtok(buf, ","); t; t = strtok(NULL, ",")) {
            int idx = atoi(t);
            if (idx >= 0 && idx < 32) ep->fec_standby_mask |= 1u << idx;
        }
    }
    ep->fec_on = 1;
    printf("[fec] %s enabled: scheme=%s block=%d rate=%.3f mp=%s standby_mask=0x%x\n",
           ep->mode == QUIC_MODE_CLIENT ? "client" : "server", v,
           (int)cs->fec_params.fec_max_symbol_num_per_block, cs->fec_params.fec_code_rate,
           cs->fec_params.fec_mp_mode == XQC_FEC_MP_USE_STB ? "standby-path" : "default",
           ep->fec_standby_mask);
#else
    (void)cs;
    printf("[fec] scheme %s requested, but this build has no FEC (-DXQC_ENABLE_FEC=1); FEC off\n",
           config->scheme);
#endif
    fflush(stdout);
}

void quic_fec_stop(quic_endpoint_t *ep) {
    if (!ep->fec_on || !ep->engine || !ep->conn) return;
    xqc_conn_stats_t st = xqc_conn_get_stats(ep->engine, &ep->cid);
    printf("[fec] %s stats: send_count %u lost_count %u lost_dgram %u send_fec %u fec_recovered %u enable_fec %u\n",
           ep->mode == QUIC_MODE_CLIENT ? "client" : "server", st.send_count, st.lost_count,
           st.lost_dgram_count, st.send_fec_cnt, st.fec_recover_pkt_cnt, (unsigned)st.enable_fec);
    fflush(stdout);
}

xqc_data_qos_level_t quic_fec_dgram_qos(const quic_endpoint_t *ep) {
    return ep->fec_on ? XQC_DATA_QOS_NORMAL : XQC_DATA_QOS_HIGHEST;
}

int quic_fec_path_standby(const quic_endpoint_t *ep, int idx) {
    return idx >= 0 && idx < 32 && (ep->fec_standby_mask >> idx) & 1;
}
