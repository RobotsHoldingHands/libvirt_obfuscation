#!/usr/bin/env python3
# deploy_vms.py - Launch KVM VMs and connect them via an Open vSwitch bridge.

import os
import subprocess

# Configuration
NUM_WORKERS = 3
NUM_MANAGER = 1
TOTAL_VMS = NUM_MANAGER + NUM_WORKERS  # default 4 (1 manager + 3 workers)
VM_BASE_IMAGE = "base.img"  # Path to base VM image (assumed to be OS installed with necessary tools)
VM_IMAGE_DIR = "./vm_images"  # Directory to store individual VM disk copies
VM_RAM = "1024M"  # RAM for each VM
VM_CPU = 2        # vCPUs for each VM
OVS_BRIDGE = "br0"
HOST_INT_NAME = "host-br0"   # Name for host's OVS internal port (for host management access)

# Ensure base image exists
if not os.path.exists(VM_BASE_IMAGE):
    raise FileNotFoundError(f"Base VM image {VM_BASE_IMAGE} not found. Prepare a base image before deploying VMs.")

# Create OVS bridge
subprocess.run(f"ovs-vsctl --may-exist add-br {OVS_BRIDGE}", shell=True, check=True)
# Set bridge fail-mode to standalone (no controller) so it acts as a normal switch
subprocess.run(f"ovs-vsctl set-fail-mode {OVS_BRIDGE} standalone", shell=True, check=True)
# (Optional) enable STP on the bridge to avoid loops (not strictly necessary in this simple topology)
subprocess.run(f"ovs-vsctl set Bridge {OVS_BRIDGE} stp_enable=true", shell=True, check=True)

# Create an internal interface for host on the OVS bridge (for host-based management or ping, if needed)
subprocess.run(f"ovs-vsctl --may-exist add-port {OVS_BRIDGE} {HOST_INT_NAME} -- set Interface {HOST_INT_NAME} type=internal", shell=True, check=True)
# Assign an IP to the host internal port (ensure this subnet doesn't conflict with other networks)
HOST_IP = "192.168.100.1/24"
subprocess.run(f"ip addr add {HOST_IP} dev {HOST_INT_NAME}", shell=True, check=False)
subprocess.run(f"ip link set {HOST_INT_NAME} up", shell=True, check=True)

# Prepare VM disk images (copy base image for each VM to avoid altering base)
os.makedirs(VM_IMAGE_DIR, exist_ok=True)
vm_images = []
for i in range(TOTAL_VMS):
    vm_img = os.path.join(VM_IMAGE_DIR, f"vm{i}.qcow2")
    if not os.path.exists(vm_img):
        # Create a copy-on-write QCOW2 image based on the base image to save space
        subprocess.run(f"qemu-img create -f qcow2 -b {VM_BASE_IMAGE} {vm_img}", shell=True, check=True)
    vm_images.append(vm_img)

# Launch VMs
vm_processes = []
for i, img in enumerate(vm_images):
    vm_name = f"VM{i}"
    tap_name = f"tap{i}"
    mac_addr = f"52:54:00:00:00:{i:02x}"  # generate a MAC (just an example range)
    # Create tap interface if it doesn't exist
    subprocess.run(f"ip tuntap add dev {tap_name} mode tap user $(whoami)", shell=True, check=True)
    subprocess.run(f"ip link set {tap_name} up", shell=True, check=True)
    # Attach tap to OVS bridge
    subprocess.run(f"ovs-vsctl --may-exist add-port {OVS_BRIDGE} {tap_name}", shell=True, check=True)
    # Build QEMU command
    qemu_cmd = [
        "qemu-system-x86_64",
        "-name", vm_name,
        "-enable-kvm",
        "-m", VM_RAM,
        "-smp", str(VM_CPU),
        "-drive", f"file={img},if=virtio,cache=none",
        "-netdev", f"tap,id=net0,ifname={tap_name},script=no,downscript=no",
        "-device", f"virtio-net-pci,netdev=net0,mac={mac_addr}",
        "-display", "none",      # no GUI
        "-daemonize"             # run in background
    ]
    # Note: We assume the VM's OS will bring up the network (via DHCP or static config)
    subprocess.run(" ".join(qemu_cmd), shell=True, check=True)
    # Optionally, we could capture the PID of QEMU if needed (e.g., by removing -daemonize and running in Popen)
