#ifndef QUIC_FEC_H
#define QUIC_FEC_H

#include "quic_api.h"

/*helper function for quic_client_start and quic_server_start in quic api: turns FEC on in the
  connection settings when config->scheme is set; needs a build with -DXQC_ENABLE_FEC=1*/
void quic_fec_init(quic_endpoint_t *ep, const quic_fec_config_t *config, xqc_conn_settings_t *cs);
/*helper function for quic_endpoint_stop in quic api*/
void quic_fec_stop(quic_endpoint_t *ep);
/*helper function for the datagram sends in quic api: QoS 3-6 is FEC protected, so datagrams
  go out at NORMAL with FEC on and at HIGHEST (unprotected) otherwise*/
xqc_data_qos_level_t quic_fec_dgram_qos(const quic_endpoint_t *ep);
/*helper function for ready_to_create_path_notify in quic api: 1 if path index idx is a standby path*/
int quic_fec_path_standby(const quic_endpoint_t *ep, int idx);

#endif /* QUIC_FEC_H */
