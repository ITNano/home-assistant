import sys
from scapy.all import *
conf.verb = 0


def on_packet_receive(packet):
  if packet.haslayer(TCP):
    handle_tcp(packet)
  elif packet.haslayer(UDP):
    handle_udp(packet)
  elif STP in packet:
    print("Router scanning packet (STP) [mac: %s, cost: %s]" % (packet.rootmac, packet.pathcost))
  else:
    print("Unknown packet arrived!")
    # packet.show()

def handle_tcp(packet):
  ip_addr = get_ip_addresses(packet)
  print("TCP/%s [ %s:%s  =>  %s:%s]" % (ip_addr['proto'], ip_addr['src'], packet[TCP].sport, ip_addr['dst'], packet[TCP].dport))

def handle_udp(packet):
  ip_addr = get_ip_addresses(packet)
  print("UDP/%s [ %s:%s  =>   %s:%s]" % (ip_addr['proto'], ip_addr['src'], packet[UDP].sport, ip_addr['dst'], packet[UDP].dport))

  if packet.haslayer(DNS):
    handle_dns(packet)

def handle_dns(packet):
  print("  DNS request")

def get_ip_addresses(packet):
  if IP in packet:
    return {"src": packet[IP].src, "dst": packet[IP].dst, "proto": "IP"}
  elif IPv6 in packet:
    return {"src": packet[IPv6].src, "dst": packet[IPv6].dst, "proto": "IPv6"}
  else:
    return {"src": "???", "dst": "???", "proto": "unknown"}

def get_dns_records(packet, depth=0):
  print("get_dns_records depth=%i" % (depth))
  if DNSRR in packet:
    return [packet[DNSRR]]+get_dns_records(packet[DNSRR], depth+1)
  else:
    return []

print("Starting capture...")
sniff(iface="tap0", prn=on_packet_receive, store=0)