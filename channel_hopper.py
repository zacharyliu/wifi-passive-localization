import os
import threading
import time

class ChannelHopper():
    channels = [1, 6, 11]

    def __init__(self, interface):
        self.interface = interface

    def start(self):
        t = threading.Thread(target=self.__thread)
        t.daemon = True
        t.start()

    def __thread(self):
        current = 0
        while True:
            current = (current + 1) % len(self.channels)
            os.system('iwconfig %s channel %d' % (self.interface, self.channels[current]))
            time.sleep(0.2)
