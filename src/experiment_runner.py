import subprocess
import json
import time
import argparse
import os
import libvirt

# Import helper modules
import vm_manager
import obfuscation

def get_domain_ip(domain):
    # Retrieve the first IPv4 address of a domain's interface (from DHCP lease if available)
    try:
        ifaces = domain.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE, 0)
    except libvirt.libvirtError:
        return None
    for (iface, info) in ifaces.items():
        for addr in info.get('addrs', []):
            if addr.get('type') == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                return addr.get('addr')
    return None

def wait_for_ip(domain, timeout=15):
    # Wait up to `timeout` seconds for a VM to obtain an IP via DHCP
    for _ in range(timeout):
        ip = get_domain_ip(domain)
        if ip:
            return ip
        time.sleep(1)
    return None

def run_experiment(dom_source, dom_dest, bridge_if, scenario, duration=10):
    """
    Run a single scenario:
    - scenario: 'baseline', 'encryption', 'padding', or 'shaping'
    - duration: total capture duration (seconds)
    Returns a dict of results for this scenario.
    """
    src_ip = wait_for_ip(dom_source)
    dest_ip = wait_for_ip(dom_dest)
    if not src_ip or not dest_ip:
        raise RuntimeError("Could not obtain IP addresses for source/dest VMs.")
    print(f"Running scenario '{scenario}' - Source IP: {src_ip}, Dest IP: {dest_ip}")

    # Initialize obfuscation tools as needed
    encryptor = obfuscation.EncryptionObfuscator() if scenario == "encryption" else None
    padder = obfuscation.PaddingObfuscator() if scenario == "padding" else None
    shaper = obfuscation.TrafficShaper(mode="random") if scenario == "shaping" else None

    # Start the sniffer as a subprocess
    output_file = f"results_{scenario}.json"
    sniff_cmd = ["python3", "sniffer.py", "--iface", bridge_if,
                "--duration", str(duration), "--output", output_file]
    sniff_proc = subprocess.Popen(sniff_cmd)
    time.sleep(1)  # give sniffer a moment to initialize

    # Prepare for sending traffic using Scapy
    from scapy.all import IP, ICMP, UDP, Ether, send, sendp, getmacbyip, ARP, sr1

    # Resolve MAC addresses for L2 frames (optional for accuracy in sniffing)
    dest_mac = getmacbyip(dest_ip)
    # Get source VM's MAC (from its domain XML or ARP)
    src_mac = None
    try:
        dom_xml = dom_source.XMLDesc(0)
        import re
        match = re.search(r"<mac address='([^']+)'", dom_xml)
        if match:
            src_mac = match.group(1)
    except libvirt.libvirtError:
        pass
    if not src_mac:
        src_mac = "52:54:00:aa:bb:cc"  # fallback dummy MAC

    if dest_mac is None:
        # If getmacbyip failed, send a manual ARP request
        arp_resp = sr1(ARP(pdst=dest_ip), timeout=2, verbose=False)
        if arp_resp:
            dest_mac = arp_resp[ARP].hwsrc

    # 1. Send ICMP ping requests to measure latency (5 pings)
    ping_count = 5
    for seq in range(ping_count):
        icmp_pkt = IP(src=src_ip, dst=dest_ip)/ICMP(id=0x1234, seq=seq)
        # Do not encrypt/pad ping; we want real ICMP for latency measurement
        if shaper:
            shaper.shape(packet_size=len(icmp_pkt))
        if dest_mac:
            frame = Ether(src=src_mac, dst=dest_mac) / icmp_pkt
            sendp(frame, iface=bridge_if, verbose=False)
        else:
            send(icmp_pkt, verbose=False)
        time.sleep(0.2)  # small gap between pings

    # 2. Send UDP traffic for throughput measurement (for the remaining time)
    send_duration = max(1, duration - 2)  # use duration minus some buffer for ping/setup
    end_time = time.time() + send_duration
    udp_base = IP(src=src_ip, dst=dest_ip)/UDP(sport=5005, dport=5005)
    base_payload = b'x' * 500  # base payload (500 bytes)
    sent_packets = 0

    send_cpu_start = time.process_time()
    while time.time() < end_time:
        payload = base_payload
        if padder:
            payload = padder.pad(payload)       # apply padding
        if encryptor:
            payload = encryptor.encrypt(payload)  # apply encryption
        packet = udp_base / payload
        pkt_len = len(packet)
        if shaper:
            shaper.shape(packet_size=pkt_len)  # apply shaping delay
        if dest_mac:
            frame = Ether(src=src_mac, dst=dest_mac) / packet
            sendp(frame, iface=bridge_if, verbose=False)
        else:
            send(packet, verbose=False)
        sent_packets += 1
    send_cpu_time = time.process_time() - send_cpu_start
    send_wall_time = send_duration
    send_cpu_percent = (send_cpu_time / send_wall_time * 100) if send_wall_time > 0 else 0.0

    print(f"Scenario '{scenario}': Sent {sent_packets} UDP packets.")

    # Wait for sniffer to finish and collect results
    sniff_proc.wait()
    with open(output_file, 'r') as f:
        sniff_data = json.load(f)
    # Combine key metrics with sender CPU overhead
    result = {
        "avg_latency_ms": sniff_data.get("avg_latency_ms"),
        "jitter_ms": sniff_data.get("jitter_ms"),
        "throughput_bps": sniff_data.get("throughput_bps"),
        "cpu_usage_percent": send_cpu_percent
    }
    return result

def main():
    parser = argparse.ArgumentParser(description="Automate traffic obfuscation experiments")
    parser.add_argument('--base-image', required=True, help="Path to base VM image (qcow2 cloud image)")
    parser.add_argument('--vm-count', type=int, default=4, help="Number of VMs to create (default 4)")
    parser.add_argument('--duration', type=int, default=10, help="Duration of each experiment run in seconds (default 10)")
    parser.add_argument('--methods', default="all",
                        help="Obfuscation methods to test: 'all' (default) or comma-separated subset (e.g. 'encryption,padding')")
    parser.add_argument('--no-cleanup', action='store_true', help="Keep VMs and network after experiment (for debugging)")
    args = parser.parse_args()

    conn = libvirt.open("qemu:///system")
    if conn is None:
        raise RuntimeError("Failed to connect to libvirt. Ensure libvirtd is running and accessible.")
    # Set up network and VMs
    net = vm_manager.define_network(conn, net_name="expnet", network_cidr="192.168.124.0/24")
    domains = vm_manager.create_vms(conn, args.vm_count, args.base_image, network_name="expnet")
    # Assume at least 3 VMs: [0]=attacker, [1]=source, [2]=destination
    attacker_vm = domains[0] if len(domains) > 0 else None
    source_vm = domains[1] if len(domains) > 1 else None
    dest_vm = domains[2] if len(domains) > 2 else None
    if not attacker_vm or not source_vm or not dest_vm:
        raise RuntimeError("Not enough VMs created to assign roles for attacker, source, and destination.")
    try:
        bridge_if = net.bridgeName()
    except Exception:
        bridge_if = "expnetbr"  # fallback name, as defined in network XML

    print(f"Network '{net.name()}' is active on bridge interface: {bridge_if}")
    # Determine scenarios to test
    if args.methods.lower() == "all":
        scenarios = ["baseline", "encryption", "padding", "shaping"]
    else:
        scenarios = [m.strip().lower() for m in args.methods.split(',') if m.strip()]
        if "baseline" not in scenarios:
            scenarios.insert(0, "baseline")  # always include baseline for comparison

    results = {}
    for scenario in scenarios:
        results[scenario] = run_experiment(source_vm, dest_vm, bridge_if, scenario, duration=args.duration)

    # Cleanup VMs and network unless disabled
    if not args.no_cleanup:
        vm_names = [dom.name() for dom in domains]
        vm_manager.cleanup_vms(conn, vm_names, network_name="expnet")
    conn.close()

    # Generate comparative graphs (saved as PNG files)
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        plt = None
    if plt:
        scenarios = list(results.keys())
        # Throughput comparison (Mbps)
        throughput_mbps = [ (results[s]["throughput_bps"] or 0) / 1e6 for s in scenarios ]
        plt.figure()
        plt.bar(scenarios, throughput_mbps, color='skyblue')
        plt.title('Throughput Comparison')
        plt.xlabel('Scenario')
        plt.ylabel('Throughput (Mbps)')
        plt.tight_layout()
        plt.savefig("throughput_comparison.png")
        print("Saved throughput_comparison.png")
        # Latency comparison (avg latency with jitter as error bar)
        latency_vals = [results[s]["avg_latency_ms"] or 0 for s in scenarios]
        jitter_vals = [results[s]["jitter_ms"] or 0 for s in scenarios]
        plt.figure()
        plt.bar(scenarios, latency_vals, yerr=jitter_vals, capsize=5, color='orange')
        plt.title('Latency Comparison')
        plt.xlabel('Scenario')
        plt.ylabel('Latency (ms)')
        plt.tight_layout()
        plt.savefig("latency_comparison.png")
        print("Saved latency_comparison.png")
        # CPU usage comparison (percent CPU used by sender)
        cpu_vals = [results[s]["cpu_usage_percent"] for s in scenarios]
        plt.figure()
        plt.bar(scenarios, cpu_vals, color='gray')
        plt.title('Sender CPU Usage Comparison')
        plt.xlabel('Scenario')
        plt.ylabel('CPU Usage (%)')
        plt.tight_layout()
        plt.savefig("cpu_usage_comparison.png")
        print("Saved cpu_usage_comparison.png")
    else:
        print("Matplotlib not installed, skipping graph generation.")

    # Print summary of results
    print("=== Experiment Results ===")
    for scenario, res in results.items():
        print(f"{scenario}: {res}")

if __name__ == "__main__":
    main()
