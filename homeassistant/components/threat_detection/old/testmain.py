from profile import handle_packet, load_profiles, save_profiles, all_profiles, ignore_device
from scapy.all import *

def get_protocol_children(protocol, level=1):
    res = [(level, protocol)]
    for child in protocol.get_next_protocol():
        res.extend(get_protocol_children(child, level+1))
    return res
        

if __name__ == '__main__':
    # load_profiles('tmp.dat')
    ignore_device('b8:27:eb:26:29:2b')
    pkts = rdpcap('./test.pcap')
    for i, pkt in enumerate(pkts):
        handle_packet(pkt)
    
    print(" ---------------- ### ------------ ### ----------------- ")
    for profile in all_profiles():
        print("Using profile " + profile.id())
        for protocol in profile.protocols():
            for level, p in get_protocol_children(protocol):
                print('\t'*level + str(p))
    save_profiles('tmp.dat')