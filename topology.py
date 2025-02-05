"""Custom topology example

Demo topology with one switch and one controller. Four hosts directly connected to the switch.
Two legitimate hosts, one host running PQM server and one attacker host.

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink


class MyTopo(Topo):
    "Demo topology."

    def __init__(self):
        "Create demo topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        att1 = self.addHost('att1')
        pcm = self.addHost('pcm')

        switch1 = self.addSwitch('s1')

        # links between hosts and switches
        self.addLink(h1, switch1)
        self.addLink(h2, switch1)
        self.addLink(att1, switch1)
        self.addLink(pcm, switch1)


topos = {'mytopo': (lambda: MyTopo())}
