#define _GNU_SOURCE

#include "quic_api.h"
#include "quic_rtp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <endian.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>

// QUIC-in-RTP. Every UDP datagram gets an RFC 3550 header in front:
// V=2, no padding/CSRC, M=0, PT=96 (dynamic), a sequence number per path,
// a 90 kHz timestamp, SSRC per path. The receiver tells RTP (first byte
// 128-191) from bare QUIC (64-127 / 192-255, RFC 9443) and strips the header.
#define RTP_HDR_LEN 12
#define RTP_PT 96
#define RTP_SSRC_BASE 0x51554900u   
#define RTP_MAX_HDR 64

static size_t write_rtp_header(quic_endpoint_t *ep, unsigned path_idx, size_t size, unsigned char *out) {
    /* PDU Set marking extension (TS 26.522 cl. 4.2.2, RFC 8285 one-byte form):
       0xBEDE | length(words) | ID=1,len | E R R D PSI(4) | PSSN(10) PSN(6)
       [| PSSize(24) | NPDS(16)] | zero padding to a 32-bit boundary.
       Dummy marking: every RTP packet is its own PDU Set (E=1, PSN=0, NPDS=1),
       PSI=0 (importance unknown), D=0, PSSN counts packets per path. */
    size_t ext_data = ep->rtp_pdu_set == 0 ? 0 : (ep->rtp_pdu_set == 1 ? 3 : 8);
    size_t tag_data = ep->rtp_tag ? 9 : 0;           /* element ID 2 */
    size_t ext_bytes = (ext_data ? 1 + ext_data : 0) + (tag_data ? 1 + tag_data : 0);
    size_t ext_words = (ext_bytes + 3) / 4;
    size_t hdr = RTP_HDR_LEN + (ext_bytes ? 4 + 4 * ext_words : 0);
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint32_t rtp_ts = (uint32_t)((uint64_t)ts.tv_sec * 90000u + (uint64_t)ts.tv_nsec / 11111u);
    uint16_t seq = ep->rtp_seq[path_idx % MAX_PATHS]++;
    uint32_t ssrc = RTP_SSRC_BASE | (path_idx & 0xff);

    out[0] = ext_bytes ? 0x90 : 0x80;    /* V=2, X=1 when the extension is present */
    out[1] = RTP_PT;                     /* M=0, PT */
    out[2] = seq >> 8;        out[3] = seq & 0xff;
    out[4] = rtp_ts >> 24;    out[5] = (rtp_ts >> 16) & 0xff;
    out[6] = (rtp_ts >> 8) & 0xff;       out[7] = rtp_ts & 0xff;
    out[8] = ssrc >> 24;      out[9] = (ssrc >> 16) & 0xff;
    out[10] = (ssrc >> 8) & 0xff;        out[11] = ssrc & 0xff;
    unsigned char *e = out + RTP_HDR_LEN + 4;           /* next free element byte */
    if (ext_bytes) {
        unsigned char *x = out + RTP_HDR_LEN;
        memset(x, 0, 4 + 4 * ext_words);
        x[0] = 0xBE; x[1] = 0xDE;
        x[2] = ext_words >> 8; x[3] = ext_words & 0xff;
    }
    if (ext_data) {
        e[0] = (1 << 4) | (unsigned char)(ext_data - 1);        /* ID=1, len-1 */
        uint16_t pssn = ep->rtp_pssn[path_idx % MAX_PATHS]++ & 0x3FF;
        uint8_t psi = 0, psn = 0;
        e[1] = (1 << 7) | (0 << 4) | (psi & 0x0F);              /* E=1, R=00, D=0, PSI */
        e[2] = pssn >> 2;
        e[3] = (unsigned char)(((pssn & 0x3) << 6) | (psn & 0x3F));
        if (ext_data == 8) {
            uint32_t pssize = (uint32_t)(hdr + size + 28);      /* incl. RTP/UDP/IPv4 */
            e[4] = (pssize >> 16) & 0xff; e[5] = (pssize >> 8) & 0xff; e[6] = pssize & 0xff;
            e[7] = 0; e[8] = 1;                                  /* NPDS = 1 */
        }
        e += 1 + ext_data;
    }
    if (tag_data) {                                      /* ID=2: ctr | flags | tag */
        uint32_t ctr = ++ep->tx_pkt_ctr;
        uint32_t tag = (uint32_t)ep->tx_tag;
        e[0] = (2 << 4) | (unsigned char)(tag_data - 1);
        e[1] = ctr >> 24; e[2] = (ctr >> 16) & 0xff; e[3] = (ctr >> 8) & 0xff; e[4] = ctr & 0xff;
        e[5] = ep->tx_tag_valid ? 1 : 0;
        e[6] = tag >> 24; e[7] = (tag >> 16) & 0xff; e[8] = (tag >> 8) & 0xff; e[9] = tag & 0xff;
    }
    return hdr;
}

/* Strip the RTP header of a received UDP packet; returns the QUIC payload length
   (*pkt points at it) or -1 for a malformed packet. Bare QUIC passes through. */
ssize_t strip_rtp_header(quic_endpoint_t *ep, unsigned char *buf, ssize_t n, unsigned char **pkt) {
    *pkt = buf;
    if (n < RTP_HDR_LEN || (buf[0] & 0xC0) != 0x80) {   /* not RTP v2 */
        ep->rtp_rx_plain++;
        return n;
    }
    ssize_t h = RTP_HDR_LEN + 4 * (buf[0] & 0x0F);      /* + CSRCs */
    ep->rx_has_elem = 0;
    ep->rx_ssrc = ((uint32_t)buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];
    ep->rx_seq = (buf[2] << 8) | buf[3];
    if ((buf[0] & 0x10) && n >= h + 4) {                /* X: extension block */
        ssize_t end = h + 4 + 4 * ((buf[h + 2] << 8) | buf[h + 3]);
        if (buf[h] == 0xBE && buf[h + 1] == 0xDE && end <= n) {
            ep->rtp_rx_pduset++;
            for (ssize_t i = h + 4; i < end; ) {         /* RFC 8285 one-byte elements */
                int id = buf[i] >> 4, len = (buf[i] & 0x0F) + 1;
                if (id == 0) { i++; continue; }          /* padding */
                if (id == 15 || i + 1 + len > end) break;
                if (id == 2 && len == 9) {
                    const unsigned char *d = buf + i + 1;
                    ep->rx_has_elem = 1;
                    ep->rx_pkt_ctr = ((uint32_t)d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3];
                    ep->rx_tag_valid = d[4] & 1;
                    ep->rx_tag = (int32_t)(((uint32_t)d[5] << 24) | (d[6] << 16) | (d[7] << 8) | d[8]);
                }
                i += 1 + len;
            }
        }
        h = end;
    }
    if (h > n) return -1;
    *pkt = buf + h;
    ep->rtp_rx++;
    return n - h;
}

void quic_rtp_init(quic_endpoint_t *ep, int encap, int pdu_set, int tag) {
    ep->rtp_tag = tag;
    if (ep->rtp_tag) {
        ep->rtp_check = fopen(ep->mode == QUIC_MODE_CLIENT ? "rtp_check_client.csv"
                                                           : "rtp_check_server.csv", "w");
        if (ep->rtp_check) setvbuf(ep->rtp_check, NULL, _IOLBF, 0);   /* server is killed, not stopped */
        if (ep->rtp_check) fprintf(ep->rtp_check,
            "rtp_ssrc,rtp_seq,rtp_pkt_ctr,he_tag,he_tag_valid,dgram_id,quic_app_tag,result,dup\n");
    }
    ep->rtp_encap = encap || pdu_set || tag;
    ep->rtp_pdu_set = pdu_set;
}

void quic_rtp_stop(quic_endpoint_t *ep) {
    if (ep->rtp_encap) {
        printf("[rtp] %s: sent %lu RTP datagrams (PDU Set ext %d), received %lu RTP "
               "(%lu with BEDE ext) + %lu bare QUIC\n",
               ep->mode == QUIC_MODE_CLIENT ? "client" : "server", (unsigned long)ep->rtp_tx,
               ep->rtp_pdu_set, (unsigned long)ep->rtp_rx, (unsigned long)ep->rtp_rx_pduset,
               (unsigned long)ep->rtp_rx_plain);
        fflush(stdout);
    }
    if (ep->rtp_tag) {
        printf("[rtp-check] %s: datagrams %lu  match %lu  MISMATCH %lu  untagged %lu  no_elem %lu\n",
               ep->mode == QUIC_MODE_CLIENT ? "client" : "server",
               (unsigned long)(ep->chk_match + ep->chk_mismatch + ep->chk_untagged + ep->chk_noelem),
               (unsigned long)ep->chk_match, (unsigned long)ep->chk_mismatch,
               (unsigned long)ep->chk_untagged, (unsigned long)ep->chk_noelem);
        fflush(stdout);
        if (ep->rtp_check) { fflush(ep->rtp_check); fclose(ep->rtp_check); ep->rtp_check = NULL; }
    }
}

ssize_t quic_rtp_sendto(quic_endpoint_t *ep, unsigned path_idx, const unsigned char *buf, size_t size,
                        const struct sockaddr *peer_addr, socklen_t peer_addrlen)
{
    struct iovec iov = { (void *)buf, size };
    struct msghdr msg = {
        .msg_name    = (void *)peer_addr,
        .msg_namelen = peer_addrlen,
        .msg_iov     = &iov,
        .msg_iovlen  = 1
    };
    return quic_rtp_sendmsg(ep, path_idx, &msg);
}

ssize_t quic_rtp_sendmsg(quic_endpoint_t *ep, unsigned path_idx, struct msghdr *msg) {
    unsigned char hbuf[RTP_MAX_HDR];
    struct iovec *pkt_iov = msg->msg_iov;
    size_t hdr = write_rtp_header(ep, path_idx, pkt_iov->iov_len, hbuf);
    struct iovec iov[2] = { { hbuf, hdr }, *pkt_iov };

    msg->msg_iov    = iov;
    msg->msg_iovlen = 2;
    ssize_t res = sendmsg(ep->quic_fd, msg, 0);
    msg->msg_iov    = pkt_iov;
    msg->msg_iovlen = 1;

    if (res < 0) return res;
    ep->rtp_tx++;
    return res >= (ssize_t)hdr ? res - (ssize_t)hdr : 0;   /* xquic expects its own byte count */
}

int quic_rtp_sendmmsg(quic_endpoint_t *ep, unsigned path_idx, struct mmsghdr *msgs, unsigned int vlen) {
    struct iovec *pkt_iovs[vlen];
    struct iovec iovs[vlen][2];
    unsigned char hbufs[vlen][RTP_MAX_HDR];

    for (unsigned int i = 0; i < vlen; i++) {           /* RTP header in front of each QUIC packet */
        struct msghdr *hdr = &msgs[i].msg_hdr;
        pkt_iovs[i] = hdr->msg_iov;
        iovs[i][0].iov_base = hbufs[i];
        iovs[i][0].iov_len  = write_rtp_header(ep, path_idx, pkt_iovs[i]->iov_len, hbufs[i]);
        iovs[i][1] = *pkt_iovs[i];
        hdr->msg_iov    = iovs[i];
        hdr->msg_iovlen = 2;
    }

    int sent = sendmmsg(ep->quic_fd, msgs, vlen, 0);

    for (unsigned int i = 0; i < vlen; i++) {
        msgs[i].msg_hdr.msg_iov    = pkt_iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    if (sent > 0) ep->rtp_tx += sent;
    return sent;
}

int quic_rtp_send(quic_endpoint_t *ep, const uint8_t *data, size_t len) {
    if (!ep || !ep->conn) return -1;

    if (ep->datagram_mode) {
        uint8_t buf[MAX_DGRAM_SIZE];
        if (len + DGRAM_HEADER_SIZE > sizeof(buf)) return -1;

        uint16_t dgram_header_id = ep->dgram_header_id++;
        uint64_t dgram_id = pack_dgram_id(ep->msg_id++, 0, 0, dgram_header_id);

        uint16_t net_header_id = htons(dgram_header_id);
        memcpy(buf, &net_header_id, DGRAM_HEADER_SIZE);
        memcpy(buf + DGRAM_HEADER_SIZE, data, len);

        LOG_DEBUG("[quic] packed dgram: msg_id=%u, seq=0, max_seq=0, wire_id=%u, full_dgram_id=%lu\n",
            ep->msg_id - 1, dgram_header_id, (unsigned long)dgram_id);

        /* tag = first 4 B of the app payload; packets are normally written on the next
           engine tick, so with rtp_tag write them now, while the tag is set */
        ep->tx_tag_valid = len >= 4;
        if (ep->tx_tag_valid) memcpy(&ep->tx_tag, data, sizeof(ep->tx_tag));
        int ret = xqc_datagram_send(ep->conn, buf, len + DGRAM_HEADER_SIZE, &dgram_id, 1);
        if (ret >= 0 && ep->engine) xqc_engine_main_logic(ep->engine);
        ep->tx_tag_valid = 0;            /* packets written later are untagged */
        return ret;
    } else if (ep->stream) {
        return (int)xqc_stream_send(ep->stream, (unsigned char *)data, len, 0);
    }
    return -1;
}

void quic_rtp_datagram_read_notify(xqc_connection_t *conn, void *user_data, const void *data,
                                   size_t data_len, uint64_t flags)
{
    quic_endpoint_t *ep = (quic_endpoint_t *)user_data;
    if (!ep || data_len <= DGRAM_HEADER_SIZE) return;

    uint16_t net_val;
    memcpy(&net_val, data, DGRAM_HEADER_SIZE);
    uint16_t dgram_header_id = ntohs(net_val);

    int is_new = is_new_datagram_win(dgram_header_id, &ep->max_dgram_header_id, ep->dgram_header_win);

    if (ep->rtp_check) {
        int32_t app_tag = 0;
        if (data_len >= DGRAM_HEADER_SIZE + sizeof(app_tag))
            memcpy(&app_tag, (const uint8_t *)data + DGRAM_HEADER_SIZE, sizeof(app_tag));
        const char *res;
        if (!ep->rx_has_elem)            { res = "no_elem";  ep->chk_noelem++; }
        else if (!ep->rx_tag_valid)      { res = "untagged"; ep->chk_untagged++; }
        else if (ep->rx_tag == app_tag)  { res = "match";    ep->chk_match++; }
        else                             { res = "MISMATCH"; ep->chk_mismatch++; }
        fprintf(ep->rtp_check, "%08x,%u,%u,%d,%d,%u,%d,%s,%d\n", ep->rx_ssrc, ep->rx_seq,
                ep->rx_pkt_ctr, ep->rx_tag_valid ? ep->rx_tag : 0, ep->rx_tag_valid,
                (unsigned)dgram_header_id, app_tag, res, !is_new);
    }

    if (!is_new) {
        LOG_DEBUG("[quic] duplicate datagram %u (<=%u) recv\n", dgram_header_id, ep->max_dgram_header_id);
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + DGRAM_HEADER_SIZE;
    size_t payload_len = data_len - DGRAM_HEADER_SIZE;

    if (ep->app_recv_cb) {
        ep->app_recv_cb(payload, payload_len, ep->app_user_data);
    }
}