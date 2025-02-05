# Based on the implementation of the SimpleSwitch13
from operator import attrgetter
import networkx as nx
import config

from ryu import cfg
from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_0

from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, tcp, udp, ether_types

from ryu.topology import api as topo_api
from ryu.topology import event as topo_event

from collections import defaultdict

import logging

CONF = cfg.CONF
FLOW_DEFAULT_PRIO_FORWARDING = config.FLOW_DEFAULT_PRIO_FORWARDING
TABLE_ROUTING = config.TABLE_ROUTING
FLOW_DEFAULT_IDLE_TIMEOUT = config.FLOW_DEFAULT_IDLE_TIMEOUT


class NetworkDiscovery(app_manager.RyuApp):
    """
    This class maintains the network state and fetches the CPU load of the servers. The routing paths are calculated here.
    """
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(NetworkDiscovery, self).__init__(*args, **kwargs)
        self.name = 'SwitchWithForwarding'
        self.mac_to_port = {}
        self.ip_to_mac = {}
        # Variables for the network topology
        self.graph = nx.DiGraph()
        self.hosts = []
        self.links = []
        self.switches = []

        self.arp_checker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))

        self.reset_arp_checker = hub.spawn(self._reset_arp)

        self.logger.setLevel(logging.INFO)

    @set_ev_cls(topo_event.EventHostAdd)
    def new_host_handler(self, ev):
        host = ev.host
        self.logger.debug("New %s detected", host)
        # Add also appropriate edges to connect it to the next switch
        self.graph.add_node(host.mac)
        self.graph.add_edge(host.mac, host.port.dpid, load=0, timestamp=0, src_port=host.port.port_no)
        self.graph.add_edge(host.port.dpid, host.mac, load=0, timestamp=0, src_port=host.port.port_no)


    @set_ev_cls(topo_event.EventSwitchEnter)
    def new_switch_handler(self, ev):
        switch = ev.switch
        self.logger.debug("New %s detected", switch)
        self.graph.add_node(switch.dp.id)
        self.switches.append(switch)

    def __get_port_speed(self, dpid, port_no, switches_list):
        for switch in switches_list:
            if switch.dp.id == dpid:
                return switch.dp.ports[port_no].curr
        self.logger.debug("No BW info for %s at %s" % (port_no, dpid))
        return 1  # default value

    @set_ev_cls(topo_event.EventLinkAdd)
    def new_link_handler(self, ev):
        link = ev.link
        self.logger.debug("New %s detected", link)
        if (link.src.dpid, link.dst.dpid) not in self.graph.edges:
            self.graph.add_edge(link.src.dpid, link.dst.dpid, load=0, timestamp=0, src_port=link.src.port_no)

    def _reset_arp(self):
        hub.sleep(2)
        while True:
            self.arp_checker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))
            hub.sleep(2)

    def _print_topo(self):
        """
        Prints a list of nodes and edges to the console
        For Debugging, Period 10s
        :return:
        """
        hub.sleep(15)
        while True:
            self.logger.debug("Nodes: %s" % self.graph.nodes)
            self.logger.debug("Edges: %s" % self.graph.edges)
            hub.sleep(10)

    def calculate_path_to_server(self, src, dst):
        """
        Returns the path of the flow
        Args:
            src: dpid of switch next to source host
            dst: dpid of switch next to destination host
        Returns:
             list of hops (dict of dpid and outport) {'dp': XXX, 'port': YYY}
        """
        path_out = []
        path_tmp = nx.shortest_path(self.graph, src, dst, weight=None)  # weight = 1, Path weight = # Hops
        path_index = 1
        for dpid in path_tmp[:-1]:
            port = self.graph.edges[dpid, path_tmp[path_index]]["src_port"]
            dp = None
            for switch in self.switches:
                if switch.dp.id == dpid:
                    dp = switch.dp
            path_out.append({"dp": dp, "port": port})
            path_index += 1
        self.logger.debug("Path: %s" % path_out)
        if len(path_out) == 0:
            pass
        return path_out

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, **added_fields):
        """
        Installs a single rule on a switch given the match and actions
        Args:
            datapath:
            priority:
            match:
            actions:
            buffer_id:
            idle_timeout:

        Returns:

        """
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle_timeout, priority=priority, match=match,
                                    actions=actions, **added_fields)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    match=match, actions=actions, **added_fields)
        datapath.send_msg(mod)

    def add_flow_for_path(self, parser, routing_path, pkt, nw_src, nw_dest, dl_src, in_port):
        """
        Installs rules on all switches on the given path to forward the flow.
        If packet is tcp, add tcp src and dst port to the match
        Args:
            parser: OF parser object
            routing_path: List of dp objects with corresponding out port
            pkt: whole packet
            nw_src: ipv4 source address
            nw_dest: ipv4 destination address
            dl_src: eth source address
            in_port: input port of packet

        Returns:

        """
        tcp_data = pkt.get_protocol(tcp.tcp)

        if tcp_data:
            tcp_src = tcp_data.src_port
            tcp_dst = tcp_data.dst_port

        port_previous_hop = in_port
        for hop in routing_path:  # The switches between the incoming switch and the server
            self.logger.debug("previous port: %s, this hop dp: %s" % (port_previous_hop, hop['dp'].id))
            if tcp_data:
                self.logger.debug("found tcp")
                match = parser.OFPMatch(in_port=port_previous_hop, dl_src=haddr_to_bin(dl_src), nw_src=nw_src, nw_dst=nw_dest, nw_proto=6, dl_type= ether_types.ETH_TYPE_IP, tp_src=tcp_src, tp_dst=tcp_dst)
            else:
                self.logger.debug("no tcp")
                match = parser.OFPMatch(in_port=port_previous_hop, dl_src=haddr_to_bin(dl_src), nw_src=nw_src,
                                        nw_dst=nw_dest, nw_proto=6)
            actions = [parser.OFPActionOutput(hop["port"])]
            self.add_flow(hop['dp'], FLOW_DEFAULT_PRIO_FORWARDING, match, actions, None, FLOW_DEFAULT_IDLE_TIMEOUT)
            port_previous_hop = hop['port']

    def add_flow_to_cache(self, parser, routing_path, pkt, in_port):
        """
        Installs rules on all switches to forward to cache after an attack
        Args:
            parser: OF parser object
            routing_path: List of dp objects with corresponding out port
            pkt: whole packet
            in_port: input port of packet

        Returns:

        """

        port_previous_hop = in_port
        for hop in routing_path:  # The switches between the incoming switch and the server
            self.logger.debug("previous port: %s, this hop dp: %s" % (port_previous_hop, hop['dp'].id))
            match = parser.OFPMatch(in_port=port_previous_hop)
            actions = [parser.OFPActionOutput(hop["port"])]
            self.add_flow(hop['dp'], 1, match, actions, None, FLOW_DEFAULT_IDLE_TIMEOUT, hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)
            port_previous_hop = hop['port']
        return port_previous_hop

    def _handle_ipv4(self, datapath, in_port, pkt):
        """
        Handles an IPv4 packet. Calculates the route and installs the appropriate rules. Finally, the packet is sent
        out at the target switch and port.
        Args:
            datapath: DP object where packet was received
            in_port: ID of the input port
            pkt: The packet
        Output:
            -output on single port of the switch
        And installs flows to forward the packet on the port that is connected to the next switch/the target server

        Returns:
            SimpleSwitch forwarding indicator (True: simpleswitch forwarding), the (modified) packet to forward
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # extract headers from packet
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_data = pkt.get_protocol(ipv4.ipv4)

        eth_dst_in = eth.dst
        net_src = ipv4_data.src
        net_dst = ipv4_data.dst

        # Get the path to the server
        try:
            routing_path = self.calculate_path_to_server(
                datapath.id, self.ip_to_mac.get(net_dst, eth_dst_in)
            )
            self.logger.debug("Calculated path from %s-%s: %s" % (datapath.id, self.ip_to_mac.get(net_dst, eth_dst_in),
                                                                 routing_path))
            self.add_flow_for_path(parser, routing_path, pkt, net_src, net_dst, eth.src, in_port)
            self.logger.debug("Installed flow entries FORWARDING (pub->priv)")

            actions_po = [parser.OFPActionOutput(routing_path[-1]["port"], 0)]
            out_po = parser.OFPPacketOut(datapath=routing_path[-1]['dp'],
                                         buffer_id=ofproto.OFP_NO_BUFFER,
                                         in_port=in_port, actions=actions_po, data=pkt.data)

            datapath.send_msg(out_po)
            self.logger.debug("Packet put out at %s %s", datapath, routing_path[-1]["port"])

        except nx.exception.NodeNotFound:
            self.logger.debug(f"Packet with {eth.src} {eth.dst} not in G")

        return False, pkt

    def _handle_simple_switch(self, datapath, in_port, pkt, buffer_id=None, eth_dst=None):
        """
        Simple learning switch handling for non IPv4 packets.
        Args:
            datapath:
            in_port:
            pkt:
            buffer_id:
            eth_dst:

        Returns:

        """
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth_dst is None:
            eth_dst = eth.dst
        dl_src = eth.src
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        self.logger.debug("M2P: %s", self.mac_to_port)
        # learn mac address
        self.mac_to_port[dpid][dl_src] = in_port
        self.logger.debug("packet in %s %s %s %s", dpid, in_port, dl_src, eth_dst)

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        elif eth_dst == 'ff:ff:ff:ff:ff:ff':
            self.logger.debug("Broadcast packet at %s %s %s", dpid, in_port, dl_src)
            out_port = ofproto.OFPP_FLOOD
        else:
            self.logger.debug("OutPort unknown, flooding packet %s %s %s %s", dpid, in_port, dl_src, eth_dst)
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, dl_dst=haddr_to_bin(eth_dst))
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, FLOW_DEFAULT_PRIO_FORWARDING, match, actions, buffer_id,
                              FLOW_DEFAULT_IDLE_TIMEOUT)
            else:
                self.add_flow(datapath, FLOW_DEFAULT_PRIO_FORWARDING, match, actions, None,
                              FLOW_DEFAULT_IDLE_TIMEOUT)
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = pkt.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)