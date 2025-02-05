# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

import json
import config
from network_discover import NetworkDiscovery
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import time
import requests

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, ether_types, tcp

PACKET_COUNT_RESOLUTION = config.PACKET_COUNT_RESOLUTION
MONITOR_PERIOD = config.MONITOR_PERIOD


class Controller(NetworkDiscovery):

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        # self.save_thread = hub.spawn(self._save_traffic_stats)
        self.fetch_threshold = hub.spawn(self._fetch_threshold_loop)
        self.counter_reset_thread = hub.spawn(self._reset_send_packet_in_counter)
        self.PQM_counter_reset_thread = hub.spawn(self._reset_PQM_send_packet_in_counter)
        self.traffic_monitor = {}
        self.packet_in_thres_s = 400
        self.pkt_cache_mac = "00:00:00:00:00:04"
        self.pkt_cache_dp_id = None
        self.infected_sw = None

        self.defend_controller = False
        self.defending = False
        self.blocking = False

        self.filename = "./traffic.json"
        self.rx_packets_delta = 0
        self.rx_packets_last_iteration = 0
        self.interation_counter = 0
        self.packet_in_counter = 0
        self.PQM_packet_in_counter = 0
        self.PQM_last_pkt_count_value = 0

    def _save_traffic_stats(self):
        """
        Save self.traffic_monitor as .json for later analysis
        :param self:
        :return:
        """
        hub.sleep(10)
        while True:
            json_dict = json.dumps(self.traffic_monitor)
            f = open(self.filename, "w")
            f.write(json_dict)
            f.close()
            hub.sleep(8)

    def _fetch_threshold_loop(self):
        """
        Fetch new threshold set in GUI
        """
        while True:
            try:
                req = requests.get("http://127.0.0.1:5000/threshold")
                new_threshold = req.json()["threshold"]
                if new_threshold != self.packet_in_thres_s:
                    self.logger.info(f"Fetched new threshold: {new_threshold}")
                self.packet_in_thres_s = new_threshold
            except:
                pass
            hub.sleep(2)

    def _reset_send_packet_in_counter(self):
        """
        Push packet-in rate to controller
        """
        while True:
            try:
                requests.post("http://127.0.0.1:5000/packet_rate_controller",
                              json=self.packet_in_counter / PACKET_COUNT_RESOLUTION)  # sends the packet rate in 1/s
            except:
                pass
            self.packet_in_counter = 0
            hub.sleep(PACKET_COUNT_RESOLUTION)
    
    def _reset_PQM_send_packet_in_counter(self):
        """
        Push packet-in rate at packet queue manager
        """
        while True:
            try:
                requests.post("http://127.0.0.1:5000/packet_rate_pqm",
                              json=self.PQM_packet_in_counter/MONITOR_PERIOD)  # sends the packet rate in 1/s
            except:
                pass
            hub.sleep(PACKET_COUNT_RESOLUTION)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install flow for table misses with priority=0
        :param ev: event data
        :return:
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    def _find_packet_throttler_switch(self):
        """
        Find switch to which the packet queue manager is connected
        :return:
        """
        for link in self.graph.edges:
            if link[0] == self.pkt_cache_mac:
                self.pkt_cache_dp_id = link[1]
                self.logger.debug(
                    f"Found packet throttler at switch: {self.pkt_cache_dp_id}")
                return
            elif link[1] == self.pkt_cache_mac:
                self.pkt_cache_dp_id = link[0]
                self.logger.debug(
                    f"Found packet throttler at switch: {self.pkt_cache_dp_id}")
                return
            else:
                pass

    def _detect_traffic_anomaly(self, dp, priority):
        """
        Detect whether current packet in rate is higher than threshold
        :param dp: datapath of switch
        :param priority: priority of flow to be analyzed
        :return:
        """
        return self.traffic_monitor[dp.id][priority]["delta"] / MONITOR_PERIOD > self.packet_in_thres_s

    def _monitor(self):
        """
        Monitor the network: Collect flow stats, check for anomalies in incoming traffic
        at controller and trigger defense stage
        :return:
        """
        while True:
            if self.pkt_cache_dp_id is None:
                self._find_packet_throttler_switch()

            for dp in self.datapaths.values():
                for port in dp.ports.keys():
                    self._block_attack_port(dp, port)
                self._request_flow_stats(dp)
                self._request_stats(dp, dp.ofproto.OFPP_NONE)
                try:
                    if self._detect_traffic_anomaly(dp, 0):
                        self.infected_dp = dp
                        self.defend_controller = True
                        self.logger.warning(f"Switch {dp.id} infected!")
                except KeyError as e:
                    self.logger.warning(f"Caught KeyError: {e}")
            hub.sleep(MONITOR_PERIOD)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Is called if a packet is forwarded to the controller. Packet handling is done here.
        We drop LLDP and IPv6 packets and pre-install paths for IPv4 packets. Other packets are handled by simple learning switch
        If the defense flag is set, all traffic is rerouted to the packet cache manager
        :param ev: OF PacketIn event
        Returns:

        """
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.in_port

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        self.packet_in_counter += 1

        arp_header = pkt.get_protocol(arp.arp)
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        tcp_header = pkt.get_protocol(tcp.tcp)
        if self.defend_controller:
            self.logger.info("defending controller")
            self._handle_attack(datapath, pkt)
        elif tcp_header: # handle tcp packet. _handle_ipv4 implements TCP handling also
            self.logger.debug("handling packet tcp")
            self._handle_ipv4(datapath, in_port, pkt)
        elif arp_header:  # handle ARPs
            # Learn src ip to mac mapping and forward
            self.logger.debug("using arp")
            if arp_header.src_ip not in self.ip_to_mac:
                self.ip_to_mac[arp_header.src_ip] = arp_header.src_mac
            eth_dst = self.ip_to_mac.get(arp_header.dst_ip, None)
            arp_dst = arp_header.dst_ip
            arp_src = arp_header.src_ip
            current_switch = datapath.id
            # Check if ARP-package from arp_src to arp_dst already passed this switch.
            if self.arp_checker[current_switch][arp_src][arp_dst]:
                self.logger.debug("ARP package known and therefore dropped")
                return
            else:
                self.arp_checker[current_switch][arp_src][arp_dst] = 1
                self.logger.debug(
                    "Forwarding ARP to learn address, but dropping all consecutive packages.")
                self._handle_simple_switch(
                    datapath, in_port, pkt, msg.buffer_id, eth_dst)
        elif ipv4_header:  # IP packet ->
            self.logger.debug("handling packet ipv4")
            self._handle_ipv4(datapath, in_port, pkt)
        else:
            self.logger.debug("handling packet normal")
            self._handle_simple_switch(datapath, in_port, pkt, msg.buffer_id)

    def _handle_attack(self, datapath, pkt):
        """
        Handle flooding of connection between switch and controller by installing a flow redirecting all
        traffic to the packet cache manager and another flow sending traffic from the packet cache manager back to
        the controller.
        :param datapath: datapath of switch
        :param pkt: incoming packet
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # reroute all traffic from infected switch
        # calculate path to packet cache from switch
        path_to_cache = self.calculate_path_to_server(
            self.infected_dp.id, self.pkt_cache_dp_id)
        if len(path_to_cache) > 0: # this route will probably give errors, as the iterative flow installation is still a bit buggy
            # install flow on infected switch rerouting all traffic in direction to cache
            match = parser.OFPMatch(wildcards=ofproto.OFPFW_ALL)
            actions = [parser.OFPActionOutput(path_to_cache[0]["port"])]
            self.add_flow(self.infected_dp, config.FLOW_DEFENSE_PRIO_FORWARDING, match, actions,
                          hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)
            # route traffic from infected switch through network
            port_previous_hop = path_to_cache[0]["port"]
            port_last_hop = self.add_flow_to_cache(
                parser, path_to_cache, pkt, port_previous_hop)
            # route infected traffic from last switch before pkt cache to pkt cache
            pkt_cache_dp = path_to_cache[-1]["dp"]
            match = parser.OFPMatch(in_port=port_last_hop)
            actions = [parser.OFPActionOutput(
                self.mac_to_port[self.pkt_cache_dp_id][self.pkt_cache_mac])]
            self.add_flow(pkt_cache_dp, config.FLOW_DEFENSE_PRIO_FORWARDING, match, actions,
                          hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)
        else:  # if the switch attacked is directly connected to the cache manager
            match = parser.OFPMatch(wildcards=ofproto.OFPFW_ALL)
            actions = [parser.OFPActionOutput(
                self.mac_to_port[self.pkt_cache_dp_id][self.pkt_cache_mac])]
            self.add_flow(self.infected_dp, config.FLOW_DEFENSE_PRIO_FORWARDING, match, actions,
                          hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)
            match = parser.OFPMatch(
                in_port=self.mac_to_port[self.pkt_cache_dp_id][self.pkt_cache_mac])
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(self.infected_dp, config.FLOW_DEFAULT_PRIO_FORWARDING, match, actions,
                          hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)

        self.defend_controller = False

    def _request_stats(self, datapath, port):
        """
        Request port stats for specific datapath and port
        :param datapath: datapath of switch
        :param port: port of switch
        :return:
        """
        self.logger.debug(f'send stats request: {datapath.id}::{port}')
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, port)
        datapath.send_msg(req)

    def _request_flow_stats(self, datapath):
        """
        Request flow stats for specific switch for flows matching priority=0
        :param datapath: datapath of switch
        :return:
        """
        self.logger.debug(f'send stats request: {datapath.id}')
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(wildcards=ofproto.OFPFW_ALL)
        # Request stats for flows with priority=0 only, from table 0
        req = parser.OFPFlowStatsRequest(
            datapath, 0, match, 0, ofproto.OFPP_NONE)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handle flow stats reply: Process and add stats to self.traffic_monitor. Also, set the status
        of the controller for the GUI. Stats in OpenFlow are cumulative, so appropriate handling is needed to calculate a
        rate or 'delta'.
        :param ev: event data
        :return:
        """
        body = ev.msg.body

        available_prios = []

        for stat in [flow for flow in body]:
            collected_info = {"packet_count": stat.packet_count}
            for item, value in collected_info.items():
                dp = ev.msg.datapath.id
                prio = stat.priority
                available_prios.append(prio)
                try:
                    delta = abs(
                        value - self.traffic_monitor[dp][prio][item][-1]["value"])
                    self.logger.debug(
                        f"{dp}::{item} results {value} - {self.traffic_monitor[dp][prio][item][-1]['value']} = {delta}")
                    if delta >= 0:
                        self.traffic_monitor[dp][prio][item].append(
                            {"time": time.time_ns(), "value": value})
                    else:
                        self.traffic_monitor[dp][prio][item].append({"time": time.time_ns(
                        ), "value": value + abs(self.traffic_monitor[dp][prio][item][-1]["value"])})
                    self.traffic_monitor[dp][prio]["delta"] = delta
                except KeyError as ke: # to initialize dictionaries
                    if dp not in self.traffic_monitor.keys():
                        self.traffic_monitor[dp] = {}
                        self.traffic_monitor[dp][prio] = {}
                        self.traffic_monitor[dp][prio][item] = [
                            {"time": time.time_ns(), "value": value}]
                    elif prio not in self.traffic_monitor[dp].keys():
                        self.traffic_monitor[dp][prio] = {}
                        self.traffic_monitor[dp][prio][item] = [
                            {"time": time.time_ns(), "value": value}]
                    else:
                        self.logger.warning(f"Unknown KeyError flow: {ke}")
        # Set stage of controller based on the defense flows installed in the switch (for GUI reporting)
        if config.FLOW_DEFENSE_PRIO_BLOCKING in available_prios:
            self.defending = True
            self.blocking = True
            requests.post("http://127.0.0.1:5000/controller_stage", json="BLOCKING")
        elif config.FLOW_DEFENSE_PRIO_FORWARDING in available_prios:
            self.defending = True
            self.blocking = False
            requests.post("http://127.0.0.1:5000/controller_stage", json="MITIGATION")
        else:
            self.defending = False
            self.blocking = False
            requests.post("http://127.0.0.1:5000/controller_stage", json="NORMAL")


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Handle port stats reply: Process and add stats to self.traffic_monitor. Also, update packet-in counter
        at the packet queue manager. Stats in OpenFlow are cumulative, so appropriate handling is needed to calculate a
        rate or 'delta'.
        :param ev: event data
        :return:
        """
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            collected_info = {"rx_packets": stat.rx_packets}
            for item, value in collected_info.items():
                try:
                    delta = abs(value - self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item][-1])
                    if delta >= 0:
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item].append(value)
                    else:
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item].append(value + abs(
                            self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item][-1]["value"]))
                    self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no]["delta"] = delta
                    self.logger.debug(f"{ev.msg.datapath.id}::{stat.port_no} has packets: {delta}")
                except KeyError as ke: # to initialize dictionaries
                    if ev.msg.datapath.id not in self.traffic_monitor.keys():
                        self.traffic_monitor[ev.msg.datapath.id] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item] = [value]

                    elif "ports" not in self.traffic_monitor[ev.msg.datapath.id].keys():
                        self.traffic_monitor[ev.msg.datapath.id]["ports"] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item] = [value]

                    elif stat.port_no not in self.traffic_monitor[ev.msg.datapath.id]["ports"]:
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no] = {}
                        self.traffic_monitor[ev.msg.datapath.id]["ports"][stat.port_no][item] = [value]
                    else:
                        self.logger.warning(f"Unknown KeyError port: {ke}")
            try:
                if ev.msg.datapath.id == self.pkt_cache_dp_id and stat.port_no == self.mac_to_port[self.pkt_cache_dp_id][self.pkt_cache_mac]:
                    self.PQM_packet_in_counter = abs(stat.tx_packets - self.PQM_last_pkt_count_value)
                    self.PQM_last_pkt_count_value = stat.tx_packets
            except KeyError:
                self.logger.warning(f"Packet queue manager not yet found!")

    def _block_attack_port(self, datapath, port):
        """
        Handle port blocking.
        :param datapath: datapath to be analyzed and handled
        :param port: port to be analyzed and handled
        """
        parser = datapath.ofproto_parser
        self.logger.debug(f"Blocking counter: {self.interation_counter}")
        self.logger.debug(f"Defending: {self.defending}")
        self.logger.debug(f"Blocking: {self.blocking}")

        # self.iteration_counter delays the triggering of blocking to avoid unnecessary blocking
        if self.defending and self.traffic_monitor[datapath.id]["ports"][port]["delta"] > self.packet_in_thres_s:
            self.interation_counter += 1

        if self.defending and self.interation_counter >= 3:
            self.logger.debug("Blocking port")
            match = parser.OFPMatch(in_port=port)
            actions = [] # drop traffic to block port
            self.add_flow(datapath, config.FLOW_DEFENSE_PRIO_BLOCKING, match, actions, hard_timeout=config.FLOW_ATTACK_HARD_TIMEOUT)
            self.interation_counter = 0