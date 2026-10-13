# XR and cloud-gaming replay apps (`xr_client`, `xr_server`)

`xr_client` replays an application trace over multipath QUIC DATAGRAMs, and
`xr_server` acks every datagram. The client records the round trip for each event:
send, then the server's ack back. Both programs use the single-thread API in
`quic_api.c`.

They are normally run inside the network emulator, not by hand. See net-emulator:
`xr-run.sh` for the XR experiments and `batch_cg_frames.sh` for cloud gaming.

## Build

These steps follow the upstream XQUIC instructions (top-level `README.md`, "Build
with BoringSSL"), but use a Release build without tests.

```bash
sudo apt-get install -y build-essential cmake libevent-dev

# BoringSSL, built once
git clone https://github.com/google/boringssl.git boringssl
(cd boringssl && mkdir -p build && cd build && \
 cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" .. && make -j ssl crypto)

git submodule update --init --recursive
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DXQC_ENABLE_TESTING=0 -DXQC_ENABLE_EVENT_LOG=1 \
      -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DGCOV=off \
      -DSSL_TYPE=boringssl -DSSL_PATH=$PWD/../boringssl \
      -DCMAKE_C_FLAGS="-Wno-error=dangling-pointer -Wno-error=array-bounds -Wno-error=stringop-overflow" ..
make -j xr_client xr_server

# xr_server loads server.crt / server.key from its working directory
openssl req -newkey rsa:2048 -x509 -nodes -keyout server.key -out server.crt \
    -subj "/CN=test.xquic.com" -days 365
```

The `CMAKE_C_FLAGS` line is needed with newer GCC (e.g. Ubuntu 24.04). Without it,
unmodified xquic code fails with `-Werror=dangling-pointer`.

The net-emulator scripts expect the binaries and the certificate in
`mp-xquic/build/`, with mp-xquic checked out next to net-emulator. If you build
somewhere else, pass `XR=/path/to/build`.

## `xr_server`

```
xr_server -l <ip,ip,...> -s <scheduler> -c <congestion control> [-q <qlog path>]
```

`-l` lists the local IPs to listen on, one per server path. The server's scheduler
only affects the acks, because the server sends nothing else.

## `xr_client`

```
xr_client -t <trace.csv> -l <local ips> -r <server ips> -s <scheduler> -c <cc>
          [-o rtt.csv] [-F frames.csv] [-Q] [-D [-w N] [-T ms]] [-q qlog]
```

| Flag | Meaning |
|---|---|
| `-t, --trace` | trace to replay (format below) |
| `-l, --local-ips` / `-r, --peer-ips` | client IPs (one per access link) / server IPs |
| `-s, --scheduler` | `minrtt` (default), `pmp`, `psp`, `rmp`, `spmp`, `bi` |
| `-c, --congestion` | `cubic`, `bbrv1`, `bbrv2`, `reno` |
| `-o, --out` | `rtt.csv`: one row per acked event, `hit_id,is_mine,send_time_ms,recv_time_ms,rtt_ms` |
| `-F, --frames-out` | `frames.csv`: one row per frame, written at exit (see below) |
| `-Q, --quiet` | no per-packet stdout; use it for high-rate traces, where stdout logging slows the client |
| `-q, --qlog` | qlog path |
| `-D, --drop-on-unacked` | closed loop: skip a frame while `-w` frames are still waiting for their first ack |
| `-w, --inflight` | frames allowed outstanding with `-D` (default 1) |
| `-T, --ack-timeout-ms` | with `-D`, write a frame off if it gets no ack within this many ms (default 200), so a lost ack can't stall the window |

At exit the client prints a summary. With `-D` the summary includes
`N sent, M skipped`. The client then crashes during teardown with
`double free or corruption`. This is a known bug, and it happens after all output has
been written.

### Trace format

The CSV is read by column position:

| Column | Field |
|---|---|
| 0 | `offset_ms` |
| 2 | `peer` |
| 4 | `event` |
| 5 | `direction` |
| 7 | `hitId` |
| 8 | `client_prep_ms` |
| 9 | `server_proc_ms` |
| 10 | `size_bytes` |

- Each row with `direction == send` for this peer is sent as one datagram at its
  offset.
- **`size_bytes` (column 10)** is the payload length. If it is missing or not a
  number, the client sends `sizeof(hit_request_t)` (16 B). The XR trace
  (`replay_trace.csv`) has a JSON payload in that column, so it keeps its 16 B
  requests.
- **Cloud-gaming traces** give every fragment of a video frame the same `hitId` and
  fill column 10 with the fragment size, up to 1,200 B.
- **`server_proc_ms` is slept by the server for every datagram,** so high-rate
  traces set it to 0.
- **Negative ids** in acks are ignored.

The cloud-gaming traces and their generators are in net-emulator under
`app_traces/` and `app_traces/cg_tools/`.

### Open loop vs closed loop

- **Open loop (no `-D`):** every row is sent at its trace time, whatever comes back,
  like Carson's XR replay. Use `-F frames.csv`. Its columns are
  `frame_id, first_send_ms, n_frags, n_refused, n_acked, first_ack_ms, last_ack_ms, complete_ms`:
  - frame RTT = `first_ack_ms - first_send_ms`;
  - `complete_ms` is filled only if every fragment of the frame was acked;
  - `n_refused` counts fragments that `quic_send` refused because xquic's DATAGRAM
    queue was full.
- **Closed loop (`-D -w 4 -T 250`):** a frame is skipped at the sender while 4 earlier
  frames are still unacked. Only each frame's first fragment is recorded, so use
  `rtt.csv`, which then has one row per frame. The frame RTT is still first fragment
  sent → first ack back.
