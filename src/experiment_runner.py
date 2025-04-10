#!/usr/bin/env python3
# experiment_runner.py - Apply obfuscation techniques and measure metrics.

import subprocess
import psutil
import time
import csv
import re

# Configuration (make sure these match your deployment)
manager_ip = "192.168.100.2"    # Manager VM's IP address
worker_ips = ["192.168.100.3", "192.168.100.4", "192.168.100.5"]  # Workers' IPs
ssh_key = "/path/to/ssh_key.pem"  # SSH private key for VMs (for passwordless SSH)
ssh_user = "ubuntu"              # VM username for SSH
iperf_duration = 10              # seconds for each iperf3 test
ping_count = 50                  # number of pings for latency measurement

# Helper functions
def run_ssh(host, command):
    """Run a command on a remote VM via SSH and return the output."""
    ssh_cmd = ["ssh", "-i", ssh_key, "-o", "StrictHostKeyChecking=no",
               f"{ssh_user}@{host}", command]
    result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()

def get_qemu_pids():
    """Get PIDs of all qemu-system processes (assumes one per VM) for CPU usage measurement."""
    pids = []
    for proc in psutil.process_iter(attrs=["name", "cmdline"]):
        if proc.info["name"] and "qemu-system" in proc.info["name"]:
            pids.append(proc.pid)
    return pids

def measure_cpu_usage(duration=5):
    """Measure average CPU usage (%) of all QEMU processes over a given duration."""
    pids = get_qemu_pids()
    if not pids:
        return 0.0
    procs = [psutil.Process(pid) for pid in pids]
    # Start measuring CPU over an interval
    for p in procs:
        p.cpu_percent(interval=None)  # prime initial value
    time.sleep(duration)
    cpu_percents = [p.cpu_percent(interval=None) for p in procs]
    return sum(cpu_percents) / len(cpu_percents)

# Ensure iperf3 is installed on VMs (this could also be done via cloud-init or manually)
print("Installing iperf3 on VMs if not present...")
for host in [manager_ip] + worker_ips:
    run_ssh(host, "sudo apt-get update && sudo apt-get install -y iperf3")

# Start iperf3 server on manager VM
run_ssh(manager_ip, "sudo pkill iperf3; nohup iperf3 -s > /tmp/iperf_server.log 2>&1 &")

# Prepare results storage
fieldnames = ["Scenario", "Throughput_Mbps", "Avg_Latency_ms", "Jitter_ms", "CPU_Usage_percent"]
results = []

# Baseline (No obfuscation)
print("Running baseline scenario (no obfuscation)...")
# Ensure no shaping on host interfaces (clear any qdisc)
subprocess.run("tc qdisc del dev br0 root", shell=True, stderr=subprocess.DEVNULL)  # clear bridge qdisc if any
for i in range(len(worker_ips)+1):
    tap = f"tap{i}"
    subprocess.run(f"tc qdisc del dev {tap} root", shell=True, stderr=subprocess.DEVNULL)
# Run throughput tests (each worker to manager)
throughputs = []
for w_ip in worker_ips:
    output = run_ssh(w_ip, f"iperf3 -c {manager_ip} -t {iperf_duration} -f m")
    # Parse iperf3 output for sender throughput (look for lines like "sender" or "bits/sec")
    match = re.search(r"(\d+\.?\d*) Mbits/sec", output)
    if match:
        throughputs.append(float(match.group(1)))
# Compute total or average throughput; here we'll take average per stream
avg_tput = sum(throughputs) / len(throughputs) if throughputs else 0.0
# Latency & jitter measurement via ping from each worker
latencies = []
for w_ip in worker_ips:
    ping_output = run_ssh(w_ip, f"ping -c {ping_count} {manager_ip}")
    # Parse ping output for avg and mdev (stddev) values from the summary
    match = re.search(r"min/avg/max/mdev = .*?/([0-9\.]+)/.*?/([0-9\.]+) ms", ping_output)
    if match:
        avg = float(match.group(1))
        mdev = float(match.group(2))
        latencies.append((avg, mdev))
# Compute overall average latency and jitter
if latencies:
    avg_lat = sum(x[0] for x in latencies) / len(latencies)
    avg_jit = sum(x[1] for x in latencies) / len(latencies)
else:
    avg_lat = avg_jit = 0.0
# CPU usage (measure during a brief idle period after test to capture baseline CPU)
cpu = measure_cpu_usage(duration=1)
results.append({"Scenario": "Baseline", "Throughput_Mbps": avg_tput, 
                "Avg_Latency_ms": avg_lat, "Jitter_ms": avg_jit, "CPU_Usage_percent": cpu})

# Scenario 1: Packet Encryption (via SSH tunnel)
print("Running Packet Encryption scenario...")
# Establish SSH tunnels from each worker to manager for encrypted iperf (local port 5201 to manager_ip:5201)
tunnel_procs = []
for i, w_ip in enumerate(worker_ips, start=1):
    local_port = 5200 + i  # unique local port for each tunnel
    cmd = ["ssh", "-i", ssh_key, "-N", "-L", f"{local_port}:{manager_ip}:5201", f"{ssh_user}@{w_ip}"]
    proc = subprocess.Popen(cmd)
    tunnel_procs.append((proc, local_port))
    time.sleep(1)  # small delay to ensure tunnel is up
# Run throughput tests through tunnels
throughputs = []
for proc, local_port in tunnel_procs:
    # iperf client connects to its own localhost which forwards to manager
    output = subprocess.run(f"iperf3 -c 127.0.0.1 -p {local_port} -t {iperf_duration} -f m",
                             shell=True, capture_output=True, text=True).stdout
    match = re.search(r"(\d+\.?\d*) Mbits/sec", output)
    if match:
        throughputs.append(float(match.group(1)))
# Close tunnels
for proc, _ in tunnel_procs:
    proc.terminate()
avg_tput = sum(throughputs) / len(throughputs) if throughputs else 0.0
# Ping (still unencrypted ICMP over network, but we can consider latency impact of encryption minimal for ICMP here)
latencies = []
for w_ip in worker_ips:
    ping_output = run_ssh(w_ip, f"ping -c {ping_count} {manager_ip}")
    match = re.search(r"min/avg/max/mdev = .*?/([0-9\.]+)/.*?/([0-9\.]+) ms", ping_output)
    if match:
        avg = float(match.group(1)); mdev = float(match.group(2))
        latencies.append((avg, mdev))
avg_lat = sum(x[0] for x in latencies) / len(latencies) if latencies else 0.0
avg_jit = sum(x[1] for x in latencies) / len(latencies) if latencies else 0.0
# CPU usage during encrypted transfer (encryption adds CPU load)
cpu = measure_cpu_usage(duration=1)
results.append({"Scenario": "Encryption", "Throughput_Mbps": avg_tput, 
                "Avg_Latency_ms": avg_lat, "Jitter_ms": avg_jit, "CPU_Usage_percent": cpu})

# Scenario 2: Traffic Padding
print("Running Traffic Padding scenario...")
# Start a background iperf UDP stream from manager to one worker to generate constant 1Mbps traffic
pad_worker = worker_ips[0]
run_ssh(pad_worker, "sudo pkill iperf3")  # ensure no previous instance
# Launch padding iperf (UDP client on worker connecting to manager server) in background
run_ssh(pad_worker, f"nohup iperf3 -c {manager_ip} -u -b 1M -t {iperf_duration*2} > /tmp/pad.log 2>&1 &")
time.sleep(1)  # let padding traffic start
# Now perform normal throughput test (TCP) with another worker while padding is ongoing
throughputs = []
test_worker = worker_ips[1] if len(worker_ips) > 1 else worker_ips[0]
output = run_ssh(test_worker, f"iperf3 -c {manager_ip} -t {iperf_duration} -f m")
match = re.search(r"(\d+\.?\d*) Mbits/sec", output)
if match:
    throughputs.append(float(match.group(1)))
# (We could also run multiple workers simultaneously to see combined throughput under padding)
avg_tput = sum(throughputs)/len(throughputs) if throughputs else 0.0
# Latency: ping manager from a worker (choose a worker different from padding one to see impact of cross-traffic)
latencies = []
for w_ip in worker_ips:
    ping_output = run_ssh(w_ip, f"ping -c {ping_count} {manager_ip}")
    match = re.search(r"min/avg/max/mdev = .*?/([0-9\.]+)/.*?/([0-9\.]+) ms", ping_output)
    if match:
        avg = float(match.group(1)); mdev = float(match.group(2))
        latencies.append((avg, mdev))
avg_lat = sum(x[0] for x in latencies) / len(latencies) if latencies else 0.0
avg_jit = sum(x[1] for x in latencies) / len(latencies) if latencies else 0.0
# CPU usage during padding + throughput
cpu = measure_cpu_usage(duration=1)
results.append({"Scenario": "Padding", "Throughput_Mbps": avg_tput, 
                "Avg_Latency_ms": avg_lat, "Jitter_ms": avg_jit, "CPU_Usage_percent": cpu})

# Scenario 3: Random Delays (using netem)
print("Running Random Delays scenario...")
# Apply netem delay on all tap interfaces (simulate e.g. 50±10ms delay)
for i in range(len(worker_ips)+1):
    tap = f"tap{i}"
    subprocess.run(f"tc qdisc add dev {tap} root netem delay 50ms 10ms", shell=True, check=True)
# Run throughput test (one stream as representative)
throughputs = []
output = run_ssh(worker_ips[0], f"iperf3 -c {manager_ip} -t {iperf_duration} -f m")
match = re.search(r"(\d+\.?\d*) Mbits/sec", output)
if match:
    throughputs.append(float(match.group(1)))
avg_tput = sum(throughputs)/len(throughputs) if throughputs else 0.0
# Latency: ping (which will naturally include the added random delay)
latencies = []
for w_ip in worker_ips:
    ping_output = run_ssh(w_ip, f"ping -c {ping_count} {manager_ip}")
    match = re.search(r"min/avg/max/mdev = .*?/([0-9\.]+)/.*?/([0-9\.]+) ms", ping_output)
    if match:
        avg = float(match.group(1)); mdev = float(match.group(2))
        latencies.append((avg, mdev))
avg_lat = sum(x[0] for x in latencies) / len(latencies) if latencies else 0.0
avg_jit = sum(x[1] for x in latencies) / len(latencies) if latencies else 0.0
# CPU usage (should be low impact from delay, mostly network wait)
cpu = measure_cpu_usage(duration=1)
# Remove netem qdisc to clean up for next test
for i in range(len(worker_ips)+1):
    tap = f"tap{i}"
    subprocess.run(f"tc qdisc del dev {tap} root", shell=True, stderr=subprocess.DEVNULL)
results.append({"Scenario": "RandomDelay", "Throughput_Mbps": avg_tput, 
                "Avg_Latency_ms": avg_lat, "Jitter_ms": avg_jit, "CPU_Usage_percent": cpu})

# Scenario 4: Constant Bitrate (using TBF)
print("Running Constant Bitrate Shaping scenario...")
# Apply TBF shaping on all taps (e.g., rate limit to 50 Mbps, with a burst buffer)
rate = "50mbit"
burst = "32kbit"
lat = "50ms"
for i in range(len(worker_ips)+1):
    tap = f"tap{i}"
    subprocess.run(f"tc qdisc add dev {tap} root tbf rate {rate} burst {burst} latency {lat}", shell=True, check=True)
# Run throughput test (attempt to saturate; iperf will likely hit the 50 Mbps cap)
throughputs = []
output = run_ssh(worker_ips[0], f"iperf3 -c {manager_ip} -t {iperf_duration} -f m")
match = re.search(r"(\d+\.?\d*) Mbits/sec", output)
if match:
    throughputs.append(float(match.group(1)))
avg_tput = sum(throughputs)/len(throughputs) if throughputs else 0.0
# Latency: ping (with shaped queue, might see higher latency if queueing occurs)
latencies = []
for w_ip in worker_ips:
    ping_output = run_ssh(w_ip, f"ping -c {ping_count} {manager_ip}")
    match = re.search(r"min/avg/max/mdev = .*?/([0-9\.]+)/.*?/([0-9\.]+) ms", ping_output)
    if match:
        avg = float(match.group(1)); mdev = float(match.group(2))
        latencies.append((avg, mdev))
avg_lat = sum(x[0] for x in latencies) / len(latencies) if latencies else 0.0
avg_jit = sum(x[1] for x in latencies) / len(latencies) if latencies else 0.0
# CPU usage (shaping might add slight overhead in kernel, likely minimal)
cpu = measure_cpu_usage(duration=1)
# Remove TBF qdisc
for i in range(len(worker_ips)+1):
    tap = f"tap{i}"
    subprocess.run(f"tc qdisc del dev {tap} root", shell=True, stderr=subprocess.DEVNULL)
results.append({"Scenario": "ConstantRate", "Throughput_Mbps": avg_tput, 
                "Avg_Latency_ms": avg_lat, "Jitter_ms": avg_jit, "CPU_Usage_percent": cpu})

# Stop iperf3 server on manager
run_ssh(manager_ip, "pkill iperf3")

# Write results to CSV
csv_file = "experiment_results.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in results:
        writer.writerow(row)
print(f"Results saved to {csv_file}")
