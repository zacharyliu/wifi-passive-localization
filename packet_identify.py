from scapy.layers.dot11 import Dot11

def is_beacon_frame(p):
    return p.type == 0 and p.subtype == 8

def is_access_point(p):
    return p.haslayer(Dot11) and p.addr2 is not None and is_beacon_frame(p)
