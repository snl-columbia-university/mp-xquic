#define _GNU_SOURCE

#include "quic_api.h"
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
static ssize_t strip_rtp_header(quic_endpoint_t *ep, unsigned char *buf, ssize_t n, unsigned char **pkt) {
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