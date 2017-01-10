import argparse
import pickle
from scapy.layers.dot11 import Dot11
from collections import defaultdict
from sample_stream import SampleStreamPair
from slim_packet import SlimPacket

threshold_packets_per_second = 3.5

def is_access_point(p):
    return p.haslayer(Dot11) and p.addr2 is not None and p.type == 0 and p.subtype == 8

def load(filename):
    print 'Reading packets...'
    with open(filename) as f:
        packets = pickle.load(f)

    print 'Processing...'
    counts = defaultdict(int)
    for p in packets:
        counts[p.addr2] += 1

    return packets, counts

def sample_to_X(sample, access_points):
    sample_data = []
    for addr in access_points:
        if addr in sample:
            assert len(sample[addr]) == 3
            sample_data.extend(sample[addr])
        else:
            sample_data.extend([float('NaN'), float('NaN'), float('NaN')])
    return sample_data

def get_samples(data):
    samples = []
    sample_stream = SampleStreamPair(samples.append)

    for packet in sorted(data, key=lambda p: p.time):
        sample_stream.add_packet(packet, packet.source)

    return samples

def get_training_data(items):
    raw_samples = defaultdict(list)
    counts_by_addr = defaultdict(int)
    total_time = 0
    for label, filename in items:
        print 'Current label %d' % label
        print 'Loading %s...' % filename
        data, counts = load(filename)
        print 'Adding counts...'
        for addr, count in counts.iteritems():
            counts_by_addr[addr] += count
        print 'Adding time...'
        min_time = data[0].time
        max_time = data[-1].time
        total_time += max_time - min_time
        print 'Getting samples...'
        samples = get_samples(data)
        print 'Adding %d samples...' % len(samples)
        raw_samples[label].extend(samples)
    print 'Done loading files. Determining access points to use...'
    rates_by_addr = {addr: float(count) / float(total_time) for addr, count in counts_by_addr.iteritems()}
    print rates_by_addr
    addrs = [addr for addr, rate in rates_by_addr.iteritems() if rate > threshold_packets_per_second]
    print addrs
    print 'Found %d addresses with rate above %.2f' % (len(addrs), threshold_packets_per_second)
    print 'Filtering samples...'
    xs, ys = [], []
    for label, samples in raw_samples.iteritems():
        for sample in samples:
            xs.append(sample_to_X(sample, addrs))
            ys.append(label)
    print 'Done. Generated %d total samples.' % len(xs)
    assert len(xs) == len(ys)
    return {
        'xs': xs,
        'ys': ys,
        'addrs': addrs,
    }

def parse_data_list(l):
    output = []
    current_label = None
    for item in l:
        if len(item) == 1:
            current_label = int(item)
        else:
            if current_label is None:
                raise Exception('No label specified')
            output.append((current_label, item))
    return output

def main():
    parser = argparse.ArgumentParser(description='Create training data for the given packet capture data.')
    parser.add_argument('label', help='output label for training data file')
    parser.add_argument('data', nargs='+', help='labeled data')
    args = parser.parse_args()

    items = parse_data_list(args.data)

    filename = 'data/training-data-%s.pkl' % args.label
    with open(filename, 'wb') as f:
        training_data = get_training_data(items)
        print 'Saving training data to %s...' % filename
        pickle.dump(training_data, f)

if __name__ == '__main__':
    main()
