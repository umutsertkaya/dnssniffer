from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

def dns_sniffer(packet):
   if DNSQR in packet and packet[DNSQR].qtype == 1:
      name = packet[DNSQR].qname.decode('utf-8')
      print(name)


sniff(filter="udp port 53", prn=dns_sniffer)   