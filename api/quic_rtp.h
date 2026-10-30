#ifndef QUIC_RTP_H
#define QUIC_RTP_H

#include <sys/types.h>
#include <sys/socket.h>
#include "quic_api.h"

struct msghdr;
struct mmsghdr;

/*helper function for quic_client_start and quic_server_start in quic api*/
void quic_rtp_init(quic_endpoint_t *ep, int encap, int pdu_set, int tag);
/*helper function for quic_endpoint_stop in quic api*/
void quic_rtp_stop(quic_endpoint_t *ep);
/*helper function for packet_read_cb in quic api*/
ssize_t strip_rtp_header(quic_endpoint_t *ep, unsigned char *buf, ssize_t n, unsigned char **pkt);
/*helper function for write_socket in quic api*/
ssize_t quic_rtp_sendto(quic_endpoint_t *ep, unsigned path_idx, const unsigned char *buf, size_t size,
                        const struct sockaddr *peer_addr, socklen_t peer_addrlen);
/*helper function for write_socket_ex in quic api*/
ssize_t quic_rtp_sendmsg(quic_endpoint_t *ep, unsigned path_idx, struct msghdr *msg);
/*helper function for write_mmsg and write_mmsg_ex in quic api*/
int quic_rtp_sendmmsg(quic_endpoint_t *ep, unsigned path_idx, struct mmsghdr *msgs, unsigned int vlen);

/*replacement for quic_send in quic api when rtp enabled*/
int quic_rtp_send(quic_endpoint_t *ep, const uint8_t *data, size_t len);
/*replacement for datagram_read_notify in quic api when rtp enabled*/
void quic_rtp_datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data,
                                   size_t data_len, uint64_t flags);

#endif /* QUIC_RTP_H */
