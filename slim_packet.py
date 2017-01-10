class SlimPacket():
    def __init__(self, time, addr2, signal_rssi, source=None):
        assert source in [None, 'a', 'b']

        self.time = time
        self.addr2 = addr2
        self.signal_rssi = signal_rssi
        self.source = source

    @classmethod
    def from_packet(cls, packet, source=None):
        from get_rssi import get_signal_rssi
        return cls(packet.time, packet.addr2, get_signal_rssi(packet), source)

    @classmethod
    def list_from_pcap(cls, pcap_filename):
        from scapy.all import rdpcap
        from packet_identify import is_access_point
        return [cls.from_packet(packet)
                for packet in rdpcap(pcap_filename) if is_access_point(packet)]

def main():
    import argparse
    import pickle
    import time

    parser = argparse.ArgumentParser(description='Convert pcap pair captures to SlimPacket saved files.')
    parser.add_argument('label', help='output label')
    parser.add_argument('a', help='pcap file A')
    parser.add_argument('b', help='pcap file B')
    args = parser.parse_args()

    print 'Loading %s...' % args.a
    packets_a = SlimPacket.list_from_pcap(args.a)
    print 'Loading %s...' % args.b
    packets_b = SlimPacket.list_from_pcap(args.b)

    print 'Processing...'
    packets = []
    while packets_a or packets_b:
        if (not packets_b) or (packets_a and packets_b and packets_a[0].time < packets_b[0].time):
            packet = packets_a.pop(0)
            packet.source = 'a'
        else:
            packet = packets_b.pop(0)
            packet.source = 'b'
        packets.append(packet)

    filename = 'packets/packets-'
    if args.label:
        filename += args.label + '-'
    filename += '%d.pkl' % int(time.time() * 1000)
    print 'Saving %s...' % filename
    with open(filename, 'wb') as f:
        pickle.dump(packets, f)

    print 'Done.'

if __name__ == '__main__':
    main()
