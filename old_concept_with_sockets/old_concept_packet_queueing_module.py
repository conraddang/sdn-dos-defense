import multiprocessing
from multiprocessing import Process, Queue
import os
import netifaces
from functools import partial
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw
from threading import Timer
import pickle
import socket

print("Number of processors: ", multiprocessing.cpu_count())

HEADER_LENGTH = 10

Controller_IP = "10.0.0.2"
Controller_PORT = 1234

class RepeatingTimer(Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)


class PacketCachingModuleInstance(Process):
    def __init__(self, queue):
        super(PacketCachingModuleInstance, self).__init__()
        # Process.__init__(self)
        self.queue = queue
        self.iface = "eth0"
        self.ip = "0.0.0.0."
        self.mac = "00:00:00:00:00:00"
        self.initialization()

    def initialization(self):
        self.iface = self.get_iface()
        self.ip = self.get_ip(self.iface)
        self.mac = self.get_mac(self.iface)

    def get_iface(self):
        interface_list = os.listdir('/sys/class/net/')
        interface = [s for s in interface_list if "eth0" in s]
        print(interface[0])
        return interface[0]

    def get_ip(self, iface):
        ip_address = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        print(ip_address)
        return(ip_address)

    def get_mac(self, iface):
        try:
            mac_address = open('/sys/class/net/'+iface+'/address').readline()
        except:
            mac_address = "00:00:00:00:00:00"
        print(mac_address[0:17])
        return mac_address[0:17]

    def run(self):
        pass


class CacheEnqueuer(PacketCachingModuleInstance):
    def __init__(self, queue):
        super(CacheEnqueuer, self).__init__(queue)

    def start_sniffing(self):
        sniff(iface=self.iface, filter='dst host ' + self.ip, prn=self.enqueue_cache)

    def enqueue_cache(self, pkt):
        if Raw in pkt:
            print("++++++++++++++")
            pkt.show()
            print(pkt[Raw])
            self.queue.put(self.get_header(pkt))
            print('Queue size:', self.queue.qsize())
            print("++++++++++++++")

    def get_header(self, pkt):
        pkt_header = {
            "Ether_Src": pkt[Ether].src,
            "Ether_Dst": pkt[Ether].dst,
            "Ether_Type": pkt[Ether].type,
            "IP_Src": pkt[IP].src,
            "IP_Dst": pkt[IP].dst,
            "IP_Proto": pkt[IP].proto,
            "TCP_sport": pkt[TCP].sport,
            "TCP_dport": pkt[TCP].dport,
        }
        return pkt_header

    def run(self):
        print("Process 1 - Sniffing: Running")
        self.start_sniffing()


class CacheDequeuer(PacketCachingModuleInstance):
    def __init__(self, queue):
        super(CacheDequeuer, self).__init__(queue)
        self.client_socket = None
        self.whitelist = []
        self.packetsPerSec = 0.1
        self.state = "PCMDiscoveryRequest"
        self.connection_established = False

    def create_client_socket(self):
        self. client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((Controller_IP, Controller_PORT))

        self.start_client()

    def start_client(self):
        while not self.connection_established:
            if self.state == "PCMDiscoveryRequest":
                self.send_pcm_network_address()

            if self.state == "PCMDiscoveryResponse":
                self.get_controller_whitelist()

            if self.state == "ConnectionEstablished":
                self.start_sending()

    def send_pcm_network_address(self):
        print("State: ", self.state)

        address = {"ip": self.ip, "mac": self.mac, "iface": self.iface}
        msg = pickle.dumps(address)
        msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', "utf-8") + msg
        self.client_socket.send(msg)

        self.state = "PCMDiscoveryResponse"

    def get_controller_whitelist(self):
        print("State: ", self.state)

        message_header = self.client_socket.recv(HEADER_LENGTH)
        message_length = int(message_header.decode("utf-8"))

        msg = self.client_socket.recv(message_length)
        self.whitelist = pickle.loads(msg)
        print(self.whitelist)

        self.state = "ConnectionEstablished"

    def start_sending(self):
        print("Connection established")
        timer = RepeatingTimer(self.packetsPerSec, self.dequeue_cache)
        timer.start()
        self.connection_established = True

    def check_whitelist(self, pkt_header):
        if pkt_header["IP_Src"] in self.whitelist or pkt_header["IP_Dst"] in self.whitelist:
            return True
        else:
            return False

    def dequeue_cache(self):
        if not self.queue.empty():
            print("<<<<<<<<<<<<<<")
            print('Queue size before:', self.queue.qsize())

            pkt_header = self.queue.get()

            if self.check_whitelist(pkt_header):
                print(pkt_header)
                msg = pickle.dumps(pkt_header)
                msg = bytes(f'{len(msg):<{HEADER_LENGTH}}', "utf-8") + msg
                self.client_socket.send(msg)
            else:
                print("Dropped packet")

            print('Queue size after:', self.queue.qsize())
            print(">>>>>>>>>>>>>>")

    def filter(self):
        pass

    def run(self):
        print('Process 2 - Controller Communication: Running')
        self.create_client_socket()


if __name__ == "__main__":
    pkt_queue = multiprocessing.Queue()

    cache_enq = CacheEnqueuer(pkt_queue)
    cache_deq = CacheDequeuer(pkt_queue)

    cache_enq.start()
    cache_deq.start()
