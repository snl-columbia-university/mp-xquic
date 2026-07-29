#!/usr/bin/env python3
import re
import json
import argparse
from datetime import datetime
from collections import defaultdict
import matplotlib

# Set non-interactive backend for headless/server execution
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Map XQUIC event names to standard qlog draft-02 categories & events
CATEGORY_EVENT_MAP = {
    "connection_started": ("connectivity", "connection_started"),
    "connection_state_updated": ("connectivity", "connection_state_updated"),
    "connection_closed": ("connectivity", "connection_closed"),
    "path_assigned": ("connectivity", "path_assigned"),
    "path_removed": ("connectivity", "path_removed"),
    "packet_sent": ("transport", "packet_sent"),
    "packet_received": ("transport", "packet_received"),
    "packet_dropped": ("transport", "packet_dropped"),
    "frames_processed": ("transport", "frames_processed"),
    "frame_parsed": ("transport", "frame_parsed"),
    "datagrams_sent": ("transport", "datagrams_sent"),
    "datagrams_received": ("transport", "datagrams_received"),
    "tra_parameters_set": ("transport", "parameters_set"),
    "rec_parameters_set": ("recovery", "parameters_set"),
    "rec_metrics_updated": ("recovery", "metrics_updated"),
    "metrics_updated": ("recovery", "metrics_updated"),
    "congestion_state_updated": ("recovery", "congestion_state_updated"),
    "loss_timer_updated": ("recovery", "loss_timer_updated"),
    "packet_lost": ("recovery", "packet_lost"),
    "key_updated": ("security", "key_updated"),
}

def parse_xquic_log(file_path, endpoint_label="client"):
    """Parses a single XQUIC raw text log into structured event dictionaries."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
        return []

    parsed_events = []

    for line in lines:
        line = line.strip()
        if not line or not line.startswith('['):
            continue

        # Handle truncated lines from interrupted logs
        if not line.endswith('|') and not line.endswith(']'):
            last_pipe = line.rfind('|')
            if last_pipe != -1:
                line = line[:last_pipe + 1]
            else:
                continue

        # Regex match XQUIC line format: [YYYY/MM/DD HH:MM:SS USEC] [EVENT_NAME] BODY
        match = re.match(r'^\[(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\d+)\]\s+\[([^\]]+)\]\s*(.*)', line)
        if not match:
            continue

        date_str, usec_str, raw_event_name, body = match.groups()

        try:
            dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
            abs_ts_ms = (dt.timestamp() * 1000.0) + (int(usec_str) / 1000.0)
        except ValueError:
            continue

        data = {}
        parts = body.strip('|').split('|')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if ':' in part:
                k, v = part.split(':', 1)
                k, v = k.strip(), v.strip()
                if v.isdigit():
                    v = int(v)
                else:
                    try:
                        v = float(v)
                    except ValueError:
                        pass
                data[k] = v
            else:
                if not part.startswith('['):
                    data.setdefault("flags", []).append(part)

        parsed_events.append({
            "endpoint": endpoint_label,
            "ts_ms": abs_ts_ms,
            "event_name": raw_event_name,
            "data": data,
            "path_id": data.get("path_id", 0)
        })

    return parsed_events


def build_qlog_traces(parsed_events, endpoint_label, global_start_ts):
    """Converts events into standard draft-02 qlog trace objects grouped by path_id."""
    path_groups = defaultdict(list)
    for ev in parsed_events:
        pid = int(ev["path_id"]) if ev["path_id"] is not None else 0
        path_groups[pid].append(ev)

    traces = []
    for pid in sorted(path_groups.keys()):
        events = path_groups[pid]
        formatted_events = []

        for ev in events:
            rel_time = round(ev["ts_ms"] - global_start_ts, 3)
            cat, event_type = CATEGORY_EVENT_MAP.get(
                ev["event_name"], ("transport", ev["event_name"])
            )

            # Standard draft-02 event object format (replaces deprecated event_fields array)
            event_obj = {
                "time": rel_time,
                "name": f"{cat}:{event_type}",
                "category": cat,
                "event": event_type,
                "data": ev["data"]
            }
            formatted_events.append(event_obj)

        trace_title = f"{endpoint_label.capitalize()} (Path {pid})"
        traces.append({
            "vantage_point": {
                "name": trace_title,
                "type": endpoint_label
            },
            "title": f"XQUIC {trace_title}",
            "common_fields": {
                "protocol_type": ["QUIC"]
            },
            "events": formatted_events
        })

    return traces


def write_ndjson_qlog(output_file, traces, title):
    """Writes qlog trace in draft-02 NDJSON (Newline Delimited JSON) format."""
    with open(output_file, "w", encoding="utf-8") as f:
        # Top-level file header
        header = {
            "qlog_version": "draft-02",
            "qlog_format": "NDJSON",
            "title": title
        }
        f.write(json.dumps(header) + "\n")

        # Stream trace metadata and event objects line-by-line
        for trace in traces:
            trace_header = {
                "vantage_point": trace["vantage_point"],
                "title": trace["title"],
                "common_fields": trace.get("common_fields", {})
            }
            f.write(json.dumps(trace_header) + "\n")
            for ev in trace["events"]:
                f.write(json.dumps(ev) + "\n")


def compute_metrics_and_plot(all_events, global_start_ts, plot_output_path):
    """Calculates summary statistics and generates performance graphs."""
    metrics_data = defaultdict(lambda: {
        "times": [], "cwnd": [], "srtt": [], "latest_rtt": [], "inflight": []
    })
    
    pkt_stats = defaultdict(lambda: {"sent": 0, "recv": 0, "lost": 0, "bytes_sent": 0})

    for ev in all_events:
        rel_t = round(ev["ts_ms"] - global_start_ts, 3)
        ep = ev["endpoint"]
        pid = int(ev["path_id"]) if ev["path_id"] is not None else 0
        key = f"{ep.capitalize()} - Path {pid}"
        
        event = ev["event_name"]
        data = ev["data"]

        # Track packet counts
        if event == "packet_sent":
            pkt_stats[key]["sent"] += 1
            pkt_stats[key]["bytes_sent"] += data.get("size", 0)
        elif event == "packet_received":
            pkt_stats[key]["recv"] += 1
        elif event == "packet_lost":
            pkt_stats[key]["lost"] += 1

        # Track congestion control metrics
        if event in ("rec_metrics_updated", "metrics_updated"):
            metrics_data[key]["times"].append(rel_t)
            metrics_data[key]["cwnd"].append(data.get("cwnd", 0))
            metrics_data[key]["srtt"].append(data.get("srtt", 0) / 1000.0)  # convert us to ms
            metrics_data[key]["latest_rtt"].append(data.get("latest_rtt", 0) / 1000.0)
            metrics_data[key]["inflight"].append(data.get("inflight", 0))

    # Print Summary Metrics Table
    print("\n" + "="*70)
    print("                      XQUIC SESSION METRICS                       ")
    print("="*70)
    
    all_keys = sorted(set(list(metrics_data.keys()) + list(pkt_stats.keys())))
    for key in all_keys:
        m = metrics_data[key]
        p = pkt_stats[key]
        
        avg_cwnd = sum(m["cwnd"]) / len(m["cwnd"]) if m["cwnd"] else 0
        max_cwnd = max(m["cwnd"]) if m["cwnd"] else 0
        avg_srtt = sum(m["srtt"]) / len(m["srtt"]) if m["srtt"] else 0
        
        total_sent = p["sent"]
        total_lost = p["lost"]
        loss_rate = (total_lost / total_sent * 100) if total_sent > 0 else 0.0

        print(f"\n--- [{key}] ---")
        print(f"  Packets Sent:     {total_sent:,}")
        print(f"  Packets Received: {p['recv']:,}")
        print(f"  Packets Lost:     {total_lost:,} (Loss Rate: {loss_rate:.2f}%)")
        print(f"  Total Data Sent:  {p['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"  Avg / Max CWND:   {avg_cwnd:,.0f} / {max_cwnd:,.0f} bytes")
        print(f"  Avg Smoothed RTT: {avg_srtt:.2f} ms")
    print("="*70 + "\n")

    # Generate Visualization Plots
    fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
    fig.suptitle("XQUIC Performance Metrics Over Time", fontsize=14, fontweight="bold")

    for key, m in metrics_data.items():
        if not m["times"]:
            continue
        axes[0].plot(m["times"], [c / 1024.0 for c in m["cwnd"]], label=f"{key} CWND")
        axes[1].plot(m["times"], m["srtt"], label=f"{key} SRTT")
        axes[2].plot(m["times"], [inf / 1024.0 for inf in m["inflight"]], label=f"{key} In-Flight")

    # Configure Axes
    axes[0].set_ylabel("CWND (KB)", fontweight="bold")
    axes[0].grid(True, linestyle="--", alpha=0.6)
    axes[0].legend(loc="upper right")

    axes[1].set_ylabel("Smoothed RTT (ms)", fontweight="bold")
    axes[1].grid(True, linestyle="--", alpha=0.6)
    axes[1].legend(loc="upper right")

    axes[2].set_ylabel("In-Flight Data (KB)", fontweight="bold")
    axes[2].set_xlabel("Time Relative to Start (ms)", fontweight="bold")
    axes[2].grid(True, linestyle="--", alpha=0.6)
    axes[2].legend(loc="upper right")

    plt.tight_layout()
    plt.savefig(plot_output_path, dpi=300)
    print(f"[✓] Saved metrics plot visualization to: {plot_output_path}")


def main():
    parser = argparse.ArgumentParser(description="Parse XQUIC client/server logs into combined qvis JSON/NDJSON and performance charts.")
    parser.add_argument("--clog", required=True, help="Path to client.qlog")
    parser.add_argument("--slog", required=True, help="Path to server.qlog")
    parser.add_argument("-o", "--output-qlog", default="combined_qvis.json", help="Output combined qlog file (.json or .ndjson)")
    parser.add_argument("-f", "--format", choices=["json", "ndjson"], default="json", help="Output format: json or ndjson (default: json)")
    parser.add_argument("-p", "--output-plot", default="xquic_metrics.png", help="Output metrics visualization plot PNG")

    args = parser.parse_args()

    print("[*] Parsing client and server log files...")
    client_events = parse_xquic_log(args.clog, "client")
    server_events = parse_xquic_log(args.slog, "server")

    all_events = client_events + server_events
    if not all_events:
        print("[!] Error: No valid events extracted from the provided log files.")
        return

    # Sort all combined events chronologically
    all_events.sort(key=lambda x: x["ts_ms"])
    global_start_ts = all_events[0]["ts_ms"]

    # Build qlog trace structures for client and server paths
    client_traces = build_qlog_traces(client_events, "client", global_start_ts)
    server_traces = build_qlog_traces(server_events, "server", global_start_ts)
    all_traces = client_traces + server_traces

    title = "XQUIC Combined Client-Server Session"

    # Auto-detect NDJSON based on extension or flag
    out_format = args.format
    if args.output_qlog.endswith(".ndjson") or args.output_qlog.endswith(".qlogsq"):
        out_format = "ndjson"

    if out_format == "ndjson":
        write_ndjson_qlog(args.output_qlog, all_traces, title)
        print(f"[✓] Saved combined qlog NDJSON to: {args.output_qlog}")
    else:
        qlog_doc = {
            "qlog_version": "draft-02",
            "qlog_format": "JSON",
            "title": title,
            "traces": all_traces
        }
        with open(args.output_qlog, "w", encoding="utf-8") as f:
            json.dump(qlog_doc, f, indent=2)
        print(f"[✓] Saved combined qlog JSON to: {args.output_qlog}")

    # Compute statistics and plot charts
    compute_metrics_and_plot(all_events, global_start_ts, args.output_plot)


if __name__ == "__main__":
    main()