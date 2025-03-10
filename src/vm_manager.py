import libvirt
import os
import subprocess
import time
import argparse

def define_network(conn, net_name="expnet", network_cidr="192.168.124.0/24"):
    """
    Define and start an isolated network for VMs to communicate.
    Returns the network object.
    """
    # Parse network CIDR for IP and netmask
    ip_net = network_cidr.split('/')[0]
    prefix = int(network_cidr.split('/')[1])
    # Simplistic netmask calculation for common prefixes
    if prefix == 24:
        netmask = "255.255.255.0"
    elif prefix == 16:
        netmask = "255.255.0.0"
    elif prefix == 8:
        netmask = "255.0.0.0"
    else:
        netmask = "255.255.255.0"
    # Use .1 as gateway, .2-.254 as DHCP range
    base_ip = ip_net.rsplit('.', 1)[0]
    gateway_ip = base_ip + ".1"
    dhcp_start = base_ip + ".2"
    dhcp_end = base_ip + ".254"
    net_xml = f"""
    <network>
      <name>{net_name}</name>
      <bridge name='{net_name}br' stp='on' delay='0'/>
      <ip address='{gateway_ip}' netmask='{netmask}'>
        <dhcp>
          <range start='{dhcp_start}' end='{dhcp_end}'/>
        </dhcp>
      </ip>
    </network>
    """
    try:
        net = conn.networkLookupByName(net_name)
        # If network exists and is inactive, start it
        if net.isActive() == 0:
            net.create()
    except libvirt.libvirtError:
        # Define and start a new network
        net = conn.networkDefineXML(net_xml)
        net.create()
        net.setAutostart(True)
    return net

def create_disk_image(base_image_path, new_image_path):
    """Create a new qcow2 disk image for a VM, using base_image as backing (copy-on-write)."""
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-b", base_image_path, new_image_path], check=True)

def define_vm(conn, name, disk_path, memory=512, vcpus=1, network_name="expnet"):
    """
    Define and start a VM with given name, disk, memory, vcpus, and network.
    Returns the domain object.
    """
    memory_kib = memory * 1024  # memory in KiB for XML
    domain_xml = f"""
    <domain type='kvm'>
      <name>{name}</name>
      <memory unit='KiB'>{memory_kib}</memory>
      <currentMemory unit='KiB'>{memory_kib}</currentMemory>
      <vcpu>{vcpus}</vcpu>
      <os>
        <type arch='x86_64' machine='pc'>hvm</type>
      </os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{disk_path}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'>
          <source network='{network_name}'/>
          <model type='virtio'/>
        </interface>
        <graphics type='vnc' port='-1' autoport='yes'/>
        <console type='pty'/>
      </devices>
    </domain>
    """
    dom = conn.defineXML(domain_xml)
    if dom is None:
        raise RuntimeError(f"Failed to define VM {name}")
    dom.create()  # start the VM
    return dom

def create_vms(conn, count, base_image, storage_dir="/var/lib/libvirt/images",
               memory=512, vcpus=1, network_name="expnet"):
    """
    Create `count` VMs using the base image and connect them to the network.
    Returns a list of domain objects.
    """
    domains = []
    for i in range(1, count+1):
        name = f"expvm{i}"
        disk_path = os.path.join(storage_dir, f"{name}.qcow2")
        # Remove any existing disk from previous runs
        if os.path.exists(disk_path):
            os.remove(disk_path)
        create_disk_image(base_image, disk_path)
        dom = define_vm(conn, name, disk_path, memory, vcpus, network_name)
        domains.append(dom)
    return domains

def cleanup_vms(conn, names, network_name="expnet", storage_dir="/var/lib/libvirt/images"):
    """
    Destroy and undefine VMs listed in `names`, delete their disk images,
    and tear down the virtual network.
    """
    for name in names:
        try:
            dom = conn.lookupByName(name)
        except libvirt.libvirtError:
            continue
        if dom.isActive():
            dom.destroy()
        dom.undefine()
        disk_path = os.path.join(storage_dir, f"{name}.qcow2")
        if os.path.exists(disk_path):
            os.remove(disk_path)
    # Destroy the network
    try:
        net = conn.networkLookupByName(network_name)
        if net.isActive():
            net.destroy()
        net.undefine()
    except libvirt.libvirtError:
        pass

def main():
    parser = argparse.ArgumentParser(description="VM Manager for experiment VMs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    # Subcommand: create VMs and network
    create_parser = subparsers.add_parser('create', help="Create VMs and network")
    create_parser.add_argument('--count', type=int, default=4, help="Number of VMs (default 4)")
    create_parser.add_argument('--base-image', required=True, help="Path to base cloud image (qcow2)")
    create_parser.add_argument('--memory', type=int, default=512, help="Memory (MB) per VM")
    create_parser.add_argument('--vcpus', type=int, default=1, help="vCPUs per VM")
    create_parser.add_argument('--network-cidr', default="192.168.124.0/24",
                               help="Subnet for isolated network (default 192.168.124.0/24)")
    # Subcommand: cleanup VMs and network
    subparsers.add_parser('cleanup', help="Destroy all experiment VMs and the network")
    args = parser.parse_args()

    conn = libvirt.open("qemu:///system")
    if conn is None:
        print("Failed to connect to libvirt. Ensure libvirtd is running and accessible.")
        return

    if args.command == 'create':
        net = define_network(conn, net_name="expnet", network_cidr=args.network_cidr)
        domains = create_vms(conn, args.count, args.base_image,
                              memory=args.memory, vcpus=args.vcpus, network_name="expnet")
        print(f"Created {len(domains)} VMs and network '{net.name()}' (subnet {args.network_cidr}).")
    elif args.command == 'cleanup':
        # Determine all experiment VM names to clean up
        try:
            active_domains = [dom.name() for dom in conn.listAllDomains()]
        except libvirt.libvirtError:
            active_domains = []
        try:
            inactive_domains = conn.listDefinedDomains()
        except libvirt.libvirtError:
            inactive_domains = []
        names = [n for n in (active_domains + list(inactive_domains)) if n.startswith("expvm")]
        if not names:
            names = [f"expvm{i}" for i in range(1, 10)]  # fallback pattern
        cleanup_vms(conn, names, network_name="expnet")
        print("Cleaned up experiment VMs and network.")
    conn.close()

if __name__ == "__main__":
    main()
