import argparse
import pickle
from classifier import ClassifierPair
from slim_packet import SlimPacket

def classify_packets(model, packets_filename, print_results=True):
    predictions = []

    print 'Loading model %s...' % model
    classifier = ClassifierPair.from_file(model, print_results=print_results, predict_handler=predictions.append)

    print 'Loading packets...'
    with open(packets_filename) as file:
        packets = pickle.load(file)

    print 'Running classifier...'
    for packet in sorted(packets, key=lambda p: p.time):
        classifier.add_packet(packet, packet.source)

    print 'Done.'
    return predictions

def main():
    parser = argparse.ArgumentParser(description='Run a classifier on a saved file.')
    parser.add_argument('model', help='model file')
    parser.add_argument('packets', help='packets file')
    args = parser.parse_args()

    print classify_packets(args.model, args.packets)

if __name__ == '__main__':
    main()
