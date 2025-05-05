
from scapy.all import *
import time

blacklist = ["192.168.178.24"]


def show_packet(packet):

    global sniffer

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst


        if source_ip in blacklist or dest_ip in blacklist:
            print("\n======\n WARNING: SUS PING FROM IP:{}\n======".format(source_ip))
                


    print("{} {}".format(timestamp, packet.summary())) # Summary of packet


iface = "\\Device\\NPF_{6CF310CB-2858-4450-9F0F-1C447815573E}" # WIFI Interface

sniff(iface=iface, prn=show_packet, store=False, promisc=True)
