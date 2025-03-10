# Traffic Obfuscation Experiment Codebase

This repository contains a complete Python codebase for creating a virtual network of KVM/QEMU VMs and conducting traffic obfuscation experiments. It automates VM provisioning with libvirt, monitors network traffic with a Scapy\-based sniffer, applies various obfuscation techniques (encryption, padding, traffic shaping), and runs experiments to compare their impacts on network metrics. The code is structured into modular scripts as described below.

## Repository Structure

- **`vm_manager.py`** – Creates and configures VMs using libvirt. Sets up an isolated virtual network (for inter\-VM communication) and manages VM lifecycle (creation and cleanup). One VM is designated as a passive attacker/sniffer.
- **`sniffer.py`** – Packet sniffer using Scapy to capture network traffic. Logs metrics like latency, throughput, jitter, packet size distribution, and resource usage to a JSON file. Optionally generates plots (using Matplotlib) for captured data.
- **`obfuscation.py`** – Defines obfuscation methods:
  - *Encryption* (simulated network\-layer encryption using AES),
  - *Randomized padding* (adds random\-length padding to packets),
  - *Traffic shaping* (introduces delays for random jitter or constant rate).
  
  Provides a modular interface to apply these methods dynamically during experiments.
- **`experiment_runner.py`** – Automates experiment execution. It creates the VMs/network, runs baseline traffic tests and tests with each obfuscation method, collects results, and generates comparative graphs (using Matplotlib) for key metrics. This script ties everything together for one\-touch experimentation.
- **`README.md`** – This document, which includes setup instructions and usage examples for running the experiments in a libvirt/KVM environment.

## Prerequisites

- **Host Environment**: A Linux machine with **KVM/QEMU** and **libvirt** installed and configured. Ensure the libvirt daemon is running and you have permission to create VMs (you may need to run as root or be in the `libvirt` group).
- **Python Environment**: Python 3.x is required. We use [pipenv](https://pipenv.pypa.io/) for package and environment management.
- **Required Python Packages**: Install dependencies using pipenv:

  ```bash
  pipenv install scapy pycryptodome matplotlib libvirt-python
  ```
  
- **Cloud Image**: Download a lightweight cloud image (e.g., Cirros or Ubuntu cloud image). Ensure it is a QCOW2 image. For quick testing, Cirros is recommended due to its small size and fast boot times. Note the path to the image.

## Setup and Usage

1. **Create and Configure VMs**

   Use `vm_manager.py` to create the isolated network and VMs. For example, to create 4 VMs using your cloud image:
   
   ```bash
   sudo pipenv run python vm_manager.py create --count 4 --base-image /path/to/cirros.qcow2
   ```
   
   This command defines an isolated network `expnet` (default subnet 192.168.124.0/24) and launches 4 VMs connected to it.

2. **Run Experiments**

   The `experiment_runner.py` script orchestrates the entire experiment suite. It will:
   - Create the necessary VMs and network (if not already created),
   - Run a baseline test (no obfuscation) and tests with **encryption**, **padding**, and **traffic shaping**,
   - Capture traffic using the sniffer,
   - Collect and log metrics in JSON files,
   - Generate comparative graphs (PNG images).
   
   To run the experiments, execute:
   
   ```bash
   sudo pipenv run python experiment_runner.py --base-image /path/to/cirros.qcow2
   ```
   
   Additional parameters:
   - `--vm-count`: Number of VMs (default is 4).
   - `--duration`: Duration of each experiment run (in seconds, default is 10).
   - `--methods`: Comma\-separated list of obfuscation methods to test (e.g., `encryption,padding`). The default is to run all methods.
   - `--no-cleanup`: If set, the VMs and network are not automatically cleaned up after the experiment (for debugging).

3. **Review Results**

   After the experiment, JSON files (e.g., `results_baseline.json`, `results_encryption.json`, etc.) will contain detailed metrics. Comparative graphs will be saved as:
   - `throughput_comparison.png`
   - `latency_comparison.png`
   - `cpu_usage_comparison.png`
   
   These graphs provide visual comparisons of throughput, latency (with jitter), and CPU usage for each obfuscation method.

4. **Cleanup**

   By default, the experiment runner cleans up by destroying the VMs and network after the experiments. To manually clean up, run:
   
   ```bash
   sudo pipenv run python vm_manager.py cleanup
   ```

## Notes

- The scripts assume that the VM’s network configuration uses DHCP to obtain IP addresses from the isolated network.
- The sniffer runs on the host’s network bridge to simulate an attacker observing traffic in promiscuous mode.
- The encryption method in this repository simulates network\-layer encryption using AES. In a production setup, consider using IPsec or a similar protocol.
- The obfuscation methods (encryption, padding, and shaping) can be configured and turned on/off via command\-line options in `experiment_runner.py`.
- Feel free to modify the code and parameters to suit your research needs.

Happy testing and experimentation!
