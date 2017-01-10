import argparse
import os
import pickle
import sys
import threading
import time
from channel_hopper import ChannelHopper
from scapy.all import sniff
from tqdm import trange
from slim_packet import SlimPacket
from packet_identify import is_access_point

def setup_interface(interface, duration, prn):
    print 'Configuring interface %s...' % interface
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode monitor' % interface)
    os.system('ifconfig %s up' % interface)

    print 'Starting channel hopping thread...'
    ChannelHopper(interface).start()

    print 'Sniffing packets on interface %s...' % interface
    thread = threading.Thread(target=lambda: sniff(iface=interface, timeout=duration, prn=prn, store=0))
    thread.daemon = True
    thread.start()

    return thread

def main():
    if os.geteuid() != 0:
        print 'Error: must run this script as root'
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--duration', type=int, default=60, help='capture duration (seconds)')
    parser.add_argument('label', help='output file label')
    args = parser.parse_args()

    filename = 'packets/packets-%s-%d.pkl' % (args.label, int(time.time() * 1000))
    print 'Saving to: %s' % filename

    packets = []

    def add_packet(packet, source):
        if is_access_point(packet):
            packets.append(SlimPacket.from_packet(packet, source))

    thread_1 = setup_interface('wlan1', args.duration, lambda p: add_packet(p, 'a'))
    thread_2 = setup_interface('wlan3', args.duration, lambda p: add_packet(p, 'b'))

    print 'Capturing %d seconds of packets...' % args.duration
    for i in trange(args.duration):
        time.sleep(1)

    thread_1.join()
    thread_2.join()

    print 'Saving...'
    with open(filename, 'wb') as file:
        pickle.dump(packets, file)

    print 'Done.'

if __name__ == '__main__':
    main()
