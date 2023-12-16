from collections import defaultdict

from utils import Singleton


class Cache(metaclass=Singleton):
    def __init__(self):
        self.sessions = defaultdict(list)
        self.total_packets = 0

    def put(self, parsed_packet):
        self.sessions[parsed_packet.tcp_stream].append(parsed_packet)
        self.total_packets += 1

    def clear_all(self):
        self.sessions = defaultdict(list)
        self.total_packets = 0
