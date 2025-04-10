# Virtio Obfuscation Experiments

This repository contains a complete codebase for deploying and testing network obfuscation techniques in a virtio-based virtualized environment using KVM and Open vSwitch (OVS). The experiments focus on assessing the performance impact of various obfuscation techniques compared to a baseline scenario. The key metrics evaluated are throughput, latency, jitter, and CPU usage.

## Overview

The experiments simulate traffic between multiple virtual machines (VMs) communicating via a virtual network with virtio networking. The obfuscation techniques implemented include:

1. **Packet Encryption**: Encrypting network traffic end-to-end (simulated using SSH tunnels in this repo, but can be extended to VPNs such as WireGuard).
2. **Traffic Padding**: Injecting dummy traffic to mask real traffic patterns.
3. **Traffic Shaping with Random Delays**: Introducing random delays (via Linux `tc`/`netem`) to obfuscate timing analysis.
4. **Traffic Shaping with Constant Bitrate**: Using a Token Bucket Filter (TBF) to cap and smooth bandwidth, enforcing a constant rate.

The default setup instantiates 4 VMs (1 manager and 3 worker VMs) with changeable configuration. The manager coordinates testing; workers send HTTP-like or `iperf3` traffic to the manager. Standard Linux tools (iperf3, ping) are used for traffic generation and metric collection, and results are exported to CSV. Additionally, Python scripts using Matplotlib generate boxplots for a visual comparison of the impact of each obfuscation method.

## Repository Structure

- `deploy_vms.py`  
  *Deploys KVM VMs with virtio networking and connects them via an Open vSwitch bridge.*

- `experiment_runner.py`  
  *Orchestrates experiments by applying each obfuscation technique, running network tests (using iperf3 and ping), and collecting performance metrics (throughput, latency, jitter, CPU usage). Results are saved in a CSV file.*

- `plot_results.py`  
  *Reads the experiment results CSV and generates boxplot graphs (PNG) for each key metric.*

- `README.md`  
  *This documentation file.*

## Prerequisites

Before running the experiments, ensure the following on your host machine:
- **Operating System**: Linux with kernel support for KVM, QEMU, and OVS.
- **Virtualization Tools**: KVM, QEMU, and Open vSwitch (`ovs-vsctl` command).
- **Dependencies**:
  - Python 3.x
  - Python modules: `psutil`, `pandas`, `matplotlib`
  - Common Linux networking tools: `tc`, `iperf3`, `ping`
- **VM Preparation**:  
  Prepare a base QCOW2 image (e.g., an Ubuntu cloud image) installed with an SSH server and basic networking. Ensure that the VM image is encrypted and that encryption keys are properly provisioned on each VM (the scripts assume that each VM’s security is already in place).
- **SSH Access**:  
  Set up SSH access to all VMs using a common key (update the `ssh_key` and `ssh_user` values in the scripts accordingly).

## Setup and Deployment

1. **Deploy the VMs**:  
   Run the `deploy_vms.py` script to create an OVS bridge (`br0`), set up tap interfaces, and launch the VMs. Adjust the number of VMs by modifying the configuration variables in the script (default is 4 VMs: 1 manager + 3 workers).

   ```bash
   sudo python3 deploy_vms.py
   ````

2. **Verify the Setup**
Confirm that the VMs have booted and that network connectivity exists between them. You can use commands like `ping` from the host or via SSH into the VMs.

## Running the Experiments

Run the `experiment_runner.py` script to execute the following test scenarios:
- Baseline (No Obfuscation)
- Packet Encryption (using SSH tunnels as a simulation)
- Traffic Padding
- Traffic Shaping with Random Delays
- Traffic Shaping with Constant Bitrate

The script will:
- Install necessary tools on the VMs if missing.
- Start an iperf3 server on the manager VM.
- Execute tests from worker VMs to the manager.
- Collect throughput (via iperf3), latency and jitter (via ping), and measure CPU usage (using `psutil`).
- Save results to a CSV file named `experiment_results.csv`.

To run the experiments:
```bash
sudo python3 experiment_runner.py
```


## Generating Plots
After running the experiments, generate boxplots of the collected metrics by executing:
```bash
python3 plot_results.py
```
This will create PNG images (one per metric) in the repository directory showing the distribution of throughput, average latency, jitter, and CPU usage under each scenario.

## Experiment Details
- **VM Communication:**
  The manager and workers exchange HTTP-like traffic (simulated via iperf3) over the virtual network provided by OVS with virtio networking.

- **Obfuscation Techniques:**
  Each technique is applied by either modifying network traffic control settings (using `tc`) on the host side or by creating encrypted tunnels (using SSH as a proxy for encryption). The performance impact of each technique is then measured and compared to the baseline.

- **Metrics Collected:**
  - **Throughput (Mbps):** Averaged from iperf3 output.
  - **Average Latency (ms) and Jitter (ms):** Parsed from ICMP ping statistics.
  - **CPU Usage (%):** Collected from host monitoring of QEMU processes.

## Cleanup
After your experiments, you may want to clean up:
- Shut down the VMs (use SSH or appropriate VM management commands).
- Remove the tap interfaces and delete the OVS bridge:
  ```bash
  sudo ovs-vsctl del-br br0
  sudo ip link del tap0  # and similarly for other tap interfaces if not automatically removed
  ```