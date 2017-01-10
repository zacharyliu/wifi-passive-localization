from collections import defaultdict
from multiprocessing import Lock

import numpy as np
from scapy.layers.dot11 import Dot11
from scapy.packet import Packet
from packet_identify import is_access_point
from get_rssi import get_signal_rssi
from slim_packet import SlimPacket

class SampleStreamPair(object):
    def __init__(self, sample_handler, window_size=5, interval=0.5):
        assert window_size > 0

        self.sample_handler = sample_handler
        self.window_size = window_size
        self.interval = interval

        self.data = defaultdict(lambda: {'a': [], 'b': []})
        self.prev_time = None
        self.access_points_counts = defaultdict(lambda: {'a': 0, 'b': 0})
        self.mutex = Lock()

    def add_packet(self, p, source):
        with self.mutex:
            assert source in ['a', 'b']

            if isinstance(p, Packet):
                if not (p.haslayer(Dot11) and is_access_point(p)):
                    return

                signal_rssi = get_signal_rssi(p)
                if signal_rssi is None:
                    return
            elif isinstance(p, SlimPacket):
                assert source == p.source

                signal_rssi = p.signal_rssi
            else:
                raise Exception('Unrecognized packet class: %s' % p.__class__.__name__)

            self.access_points_counts[p.addr2][source] += 1

            data_list = self.data[p.addr2][source]
            data_list.append(signal_rssi)
            if len(data_list) > self.window_size:
                data_list.pop(0)

            if self.prev_time is None:
                self.prev_time = p.time

            if p.time > self.prev_time + self.interval:
                self.prev_time = p.time
                self.call_handler()

    def call_handler(self):
        sample = {addr: [
            np.median(addr_data['a']),
            np.median(addr_data['b']),
            np.median(addr_data['a']) - np.median(addr_data['b']),
            ] for addr, addr_data in self.data.iteritems()}
        self.sample_handler(sample)
