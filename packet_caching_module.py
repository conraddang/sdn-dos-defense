import multiprocessing
from multiprocessing import Process, Queue
import os
import netifaces
from scapy.all import sniff, Ether, IP, TCP, UDP, Raw, ARP
from scapy.sendrecv import sendp, send
from scapy.volatile import RandShort, RandIP
import random
from threading import Timer

class RepeatingTimer(Timer):

    """
    Timer class that calls function every given interval.
    """

    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)


class PacketCachingModuleInstance(Process):
    
    """
    PacketCachingModuleInstance class is an abstract class with initialization attributes and methods.
    Inherits from Process class to run child classes as seperate processes.
    """

    def __init__(self, queue):
        super(PacketCachingModuleInstance, self).__init__()
        """
        Initialize class with network addresses.
        """
        self.queue = queue
        self.iface = "eth0"
        self.ip = "0.0.0.0."
        self.mac = "00:00:00:00:00:00"
        self.initialization()

    def initialization(self):
        """
        Method to call all initialization parameters at assign to attributes.
        """
        self.iface = self.get_iface()
        self.ip = self.get_ip(self.iface)
        self.mac = self.get_mac(self.iface)

    def get_iface(self):
        """
        Return interface name of the host.
        """
        interface_list = os.listdir('/sys/class/net/')
        interface = [s for s in interface_list if "eth0" in s]
        print(interface[0])
        return interface[0]

    def get_ip(self, iface):
        """
        Return IP address of the host.
        """
        ip_address = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        print(ip_address)
        return(ip_address)

    def get_mac(self, iface):
        """
        Return MAC address of the host.
        """
        try:
            mac_address = open('/sys/class/net/'+iface+'/address').readline()
        except:
            mac_address = "00:00:00:00:00:00"
        print(mac_address[0:17])
        return mac_address[0:17]

    def run(self):
        """
        Starts the process.
        Abstract method - implemented in subclass.
        """
        raise NotImplementedError("Please Implement this method")


class CacheEnqueuer(PacketCachingModuleInstance):

    """
    CacheEnqueuer class to sniff packets arriving at the given interface and to enqueue the packets to the multiprocessing queue.
    Inherits from abstract PacketCachingModuleInstance class.
    """

    def __init__(self, queue):
        """
        Constructor calling constrctor of parent class.
        """
        super(CacheEnqueuer, self).__init__(queue)

    def start_sniffing(self):
        """
        Scapy sniffing function, receives every packet arriving at interface and calling self.enqueue_cache function.
        """
        sniff(iface=self.iface, prn=self.enqueue_cache)

    def enqueue_cache(self, pkt):
        """
        Enqueues packets to the multiprocessing queue.
        Filters for incoming and outgoing traffic by checking the payload of packet.
        If packet is "PQM" the packet is outgoing and comes from the PQM and won't be sniffed, only incoming traffic should be sniffed.
        Solution since, Berkley packet filtering can't be applied since PQM with fixed IP/MAC addresses is sending out packets with spoffed addresses.
        """
        if Raw in pkt:
            if str(pkt[Raw].load, 'UTF-8') == "PQM":
                print(
                    "Load: " + "'" + str(pkt[Raw].load, 'UTF-8') + "'" + " => Not sniffed outgoing packet")
            else:
                print(
                    "Load: " + "'" + str(pkt[Raw].load, 'UTF-8') + "'" + " => Sniffed incoming packet")
                print("++++++++++++++")
                pkt.show()
                self.queue.put(pkt)
                print('Queue size:', self.queue.qsize())
                print("++++++++++++++")

    def run(self):
        """
        Starts the process.
        """
        print("Process 1 - Enqueuer: Running")
        self.start_sniffing()


class CacheDequeuer(PacketCachingModuleInstance):

    """
    CacheDequeuer class to dequeue packet from the multiprocessing class and sending packet back to the network.
    Inherits from abstract PacketCachingModuleInstance class.
    """

    def __init__(self, queue):
        """
        Constructor calling constrctor of parent class.
        :param_ packetsPerSec is packet sending rate to the controller
        """
        super(CacheDequeuer, self).__init__(queue)
        self.packetsPerSec = 100

    def start_sending(self):
        """
        Starting timer to send packets with packetsPerSec rate.
        """
        timer = RepeatingTimer(
            self.calculate_timer_interval(), self.dequeue_cache)
        timer.start()

    def calculate_timer_interval(self):
        """
        Return time interval calculated with packetsPerSec rate for timer.
        """
        return 1/self.packetsPerSec

    def dequeue_cache(self):
        """
        Dequeues packets from multiprocessing queue, parsing packet headers and constructing new packet and sending back to the network.
        Construcing packet again is necessary, since packets can't be extracted from queue and send out directly.
        Adds "PQM" as payload to detect outgoing traffic.
        Packet headers are sufficient for installing flows on the switch, so packet with removed payload can be retransmitted afterwards.
        OpenFlow also ignores payload, if packet size is to big.
        """
        if not self.queue.empty():
            print("---------------")
            print('Queue size before:', self.queue.qsize())

            pkt = self.queue.get()

            ### Check if IPv4 packet
            if pkt[Ether].type == 2048:  

                ### Handling of TCP packets
                if pkt[IP].proto == 6:  
                    ether = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
                    ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
                    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport)
                    ### Put PQM as payload to inform that packet is outgoing traffic, so that it won't be sniffed.
                    ### Acts as filter.
                    raw = Raw("PQM")
                    p = ether / ip / tcp / raw
                    # p.show()
                    sendp(p, iface=self.iface)

                ### Handling of UDP packets
                elif pkt[IP].proto == 17:  
                    ether = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst)
                    ip = IP(src=pkt[IP].src,
                            dst=random.choice(self.subnet_list))
                    tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport)
                    raw = Raw("PQM")
                    p = ether / ip / tcp / raw
                    # p.show()
                    sendp(p, iface=self.iface)

            print('Queue size after:', self.queue.qsize())
            print("---------------")

    def run(self):
        """
        Starts the process.
        """
        print('Process 2 - Dequeuer: Running')
        self.start_sending()


if __name__ == "__main__":
    
    """
    Main function starting both cache_enq and cache deq processes.
    Initializing multiprocessing queue on shared memory.
    """
    
    pkt_queue = multiprocessing.Queue()

    cache_enq = CacheEnqueuer(pkt_queue)
    cache_deq = CacheDequeuer(pkt_queue)

    cache_enq.start()
    cache_deq.start()
