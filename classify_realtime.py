import argparse
import os
import threading
from scapy.all import sniff
from channel_hopper import ChannelHopper
from classifier import ClassifierPair

def setup_interface(interface, prn):
    print 'Configuring interface %s...' % interface
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode monitor' % interface)
    os.system('ifconfig %s up' % interface)

    print 'Starting channel hopping thread...'
    ChannelHopper(interface).start()

    print 'Sniffing packets on interface %s...' % interface
    t = threading.Thread(target=lambda: sniff(iface=interface, prn=prn, store=0))
    t.daemon = True
    t.start()

    return t

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('model', help='model file (.pkl)')
    args = parser.parse_args()

    print 'Loading model %s...' % args.model
    classifier = ClassifierPair.from_file(args.model)

    t1 = setup_interface('wlan1', lambda p: classifier.add_packet(p, 'a'))
    t2 = setup_interface('wlan3', lambda p: classifier.add_packet(p, 'b'))

    t1.join()
    t2.join()

if __name__ == '__main__':
    main()
