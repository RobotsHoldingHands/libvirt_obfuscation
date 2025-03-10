import argparse
import json
import time
import resource
try:
    from scapy.all import sniff, IP, ICMP
except ImportError:
    print("Error: Scapy is not installed. Please install scapy to use this script.")
    exit(1)
try:
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

def analyze_packets(packets):
    stats = {}
    # Compute total bytes and capture duration
    total_bytes = 0
    times = []
    for pkt in packets:
        total_bytes += len(pkt)
        if hasattr(pkt, 'time'):
            times.append(pkt.time)
    duration = packets[-1].time - packets[0].time if packets else 0
    stats["packet_count"] = len(packets)
    stats["total_bytes"] = total_bytes
    stats["capture_duration_sec"] = duration if duration > 0 else 0
    # Throughput in bits per second
    stats["throughput_bps"] = int((total_bytes * 8) / duration) if duration > 0 else 0
    # Packet size distribution (list of sizes for now)
    sizes = [len(pkt) for pkt in packets]
    stats["packet_sizes"] = sizes

    # Calculate latency (RTT) from ICMP echo/reply pairs
    rtt_list = []
    req_times = {}
    for pkt in packets:
        if IP in pkt and ICMP in pkt:
            ip = pkt[IP]; icmp = pkt[ICMP]
            if icmp.type == 8:  # Echo request
                key = (ip.src, ip.dst, icmp.id, icmp.seq)
                req_times[key] = pkt.time
            elif icmp.type == 0:  # Echo reply
                key = (ip.dst, ip.src, icmp.id, icmp.seq)  # match request src/dst
                if key in req_times:
                    rtt = (pkt.time - req_times[key]) * 1000.0  # RTT in ms
                    rtt_list.append(rtt)
                    del req_times[key]
    if rtt_list:
        avg_latency = sum(rtt_list) / len(rtt_list)
        # Jitter as standard deviation of RTTs
        if len(rtt_list) > 1:
            mean = avg_latency
            variance = sum((x - mean) ** 2 for x in rtt_list) / (len(rtt_list) - 1)
            jitter = variance ** 0.5
        else:
            jitter = 0.0
        stats["avg_latency_ms"] = avg_latency
        stats["jitter_ms"] = jitter
        stats["latency_samples"] = rtt_list
    else:
        stats["avg_latency_ms"] = None
        stats["jitter_ms"] = None
        stats["latency_samples"] = []

    return stats

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer and analyzer")
    parser.add_argument('--iface', required=True, help="Network interface to sniff on")
    parser.add_argument('--duration', type=int, default=10, help="Duration to sniff (seconds)")
    parser.add_argument('--output', default="capture_log.json", help="Output JSON file for results")
    parser.add_argument('--plot', action='store_true', help="Generate plots for captured data")
    args = parser.parse_args()

    start_cpu = time.process_time()
    packets = sniff(iface=args.iface, timeout=args.duration, store=True)
    cpu_time = time.process_time() - start_cpu

    stats = analyze_packets(packets)
    # Record sniffer resource usage
    max_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    cpu_percent = (cpu_time / args.duration * 100) if args.duration > 0 else 0
    stats["cpu_time_sec"] = cpu_time
    stats["cpu_usage_percent"] = cpu_percent
    stats["max_rss_kb"] = max_rss_kb

    with open(args.output, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"Capture complete. Results saved to {args.output}")

    # Visualization (if requested and matplotlib is available)
    if args.plot and plt:
        if stats.get("latency_samples"):
            plt.figure()
            plt.plot(stats["latency_samples"], marker='o')
            plt.title('Ping Round-trip Times')
            plt.xlabel('Ping sequence index')
            plt.ylabel('RTT (ms)')
            plt.grid(True)
            plt.tight_layout()
            plt.savefig("latency_plot.png")
            print("Latency plot saved as latency_plot.png")
        if stats.get("packet_sizes"):
            plt.figure()
            plt.hist(stats["packet_sizes"], bins=10, edgecolor='black')
            plt.title('Packet Size Distribution')
            plt.xlabel('Packet size (bytes)')
            plt.ylabel('Frequency')
            plt.tight_layout()
            plt.savefig("packet_sizes_histogram.png")
            print("Packet size distribution histogram saved as packet_sizes_histogram.png")
    elif args.plot and not plt:
        print("Matplotlib not installed, skipping plot generation.")

if __name__ == "__main__":
    main()
