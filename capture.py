import os
import signal
import threading
import time
import typing
from dataclasses import dataclass
from datetime import datetime
from queue import Queue, Empty
import subprocess

import ipaddress

from cache import Cache
from utils import Singleton

HOSTNAMES = {}  # {tcp_stream: hostname}


class CaptureThreadFactory(metaclass=Singleton):
    def __init__(self):
        self.thread: CaptureThread | None = None

    def new(self, *args, **kwargs):
        if self.thread and self.thread.is_running:
            raise Exception("CaptureThread already running.")
        self.thread = CaptureThread(*args, **kwargs)
        self.thread.start()

    def kill(self):
        self.thread.terminate()
        self.thread.join()


class CaptureThread(threading.Thread):
    def __init__(self, cache: Cache | None = None, verbose: bool = False):
        self.is_running = False
        self.stop = threading.Event()
        self.cache = cache
        threading.Thread.__init__(self, target=self.capture, args=(verbose,))
        self.daemon = True

    @staticmethod
    def enqueue_output(out, queue: Queue):
        for line in iter(out.readline, ""):
            queue.put(line)
        out.close()

    @staticmethod
    def build_tshark_command() -> typing.List[str]:
        columns = ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'tcp.stream',
                   'tcp.len', 'tls.handshake.extensions_server_name', 'http.host']

        bpf = "tcp[tcpflags] == (tcp-push + tcp-ack)"

        tshark_command = [
            'tshark', '-i', '5', '-l', '-f', bpf, '-T', 'fields'
        ]
        tshark_command.extend(["-e"] + " -e ".join(columns).split())
        return tshark_command

    # Function to read packet sizes from Tshark
    def capture(self, verbose: bool = False):
        tshark_command = CaptureThread.build_tshark_command()
        print(" ".join(tshark_command))
        tshark_process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, text=True, bufsize=1)

        tshark_output_queue = Queue()
        enqueue_thread = threading.Thread(target=CaptureThread.enqueue_output,
                                          args=(tshark_process.stdout, tshark_output_queue))
        enqueue_thread.daemon = True  # thread dies with the program
        enqueue_thread.start()

        try:
            while not self.stop.wait(.001):
                try:
                    line = tshark_output_queue.get_nowait()
                    # line = tshark_output_queue.get(timeout=.01)
                    parsed_line = TsharkLine.read_line(line)
                    if parsed_line.server_name:
                        HOSTNAMES[parsed_line.tcp_stream] = parsed_line.server_name

                    if self.cache:
                        self.cache.put(parsed_line)

                    if verbose:
                        print(
                            f"{tshark_process.pid}: {parsed_line.ts} - {parsed_line.session_id()} - {parsed_line.tcp_len}",
                            flush=True)
                except Empty:
                    pass
        finally:
            self.is_running = False

    def terminate(self):
        print("Capture terminated.")
        self.stop.set()


@dataclass(frozen=True, eq=True)
class TsharkLine:
    ts: datetime
    ip_server: str
    ip_client: str
    port_server: int
    port_client: int
    tcp_stream: int
    tcp_len: int
    server_name: str | None

    def session_id(self) -> typing.Tuple[int, int, str, int]:
        return self.tcp_stream, self.port_client, self.ip_server, self.port_server

    @staticmethod
    def read_line(line: str) -> 'TsharkLine':
        args = line.split()
        ts = datetime.fromtimestamp(float(args[0]))
        ip_a = args[1]
        ip_b = args[2]
        port_a = int(args[3])
        port_b = int(args[4])
        tcp_stream = int(args[5])
        tcp_len = int(args[6])
        if ipaddress.ip_address(ip_a).is_private:
            ip_server = ip_b
            ip_client = ip_a
            port_client = port_a
            port_server = port_b
        else:
            ip_server = ip_a
            ip_client = ip_b
            port_client = port_b
            port_server = port_a
            tcp_len = -1 * tcp_len
        if len(args) >= 8:
            server_name = args[7]
        elif len(args) >= 9:
            server_name = args[8]
        else:
            server_name = None
        return TsharkLine(ts=ts, ip_client=ip_client, ip_server=ip_server, port_client=port_client,
                          port_server=port_server, tcp_stream=tcp_stream, tcp_len=tcp_len, server_name=server_name)


if __name__ == '__main__':
    capture_thread = CaptureThread(verbose=True)
    capture_thread.start()
    time.sleep(10)
    capture_thread.terminate()
    capture_thread.join()
    print("finished.")
