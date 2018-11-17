from pox.core import core
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as open_flow
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.util import dpidToStr
import os
import random

log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ['HOME']
used_ports = {}
last_used_port = {}

class Controller(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_Connection_up(self, event):
        switch = dpidToStr(event.connection.dpid)
        log.info("Flooding multicast packets in switch: " + switch)
        msg = open_flow.ofp_flow_mod()
        msg.match.dl_dst = EthAddr("ff:ff:ff:ff:ff:ff")
        port = open_flow.OFPP_FLOOD
        msg.actions.append(open_flow.ofp_action_output(port=port))
        event.connection.send(msg)
        used_ports[event.dpid] = set()

    def _handle_Packet_in(self, event):
        src_port = event.port
        src_pid = event.connection.dpid
        packet = event.parsed
        if not packet.parsed:
            log.warning("%i %i ignoring not parsed packet", src_pid, src_port)
            return
        icmp_packet = packet.find(pkt.icmp)
        ip6_packet = packet.find(pkt.ipv6)
        arp_packet = packet.find(pkt.arp)
        eth_packet = packet.find(pkt.ethernet)
        ip4_packet = packet.find(pkt.ipv4)
        tcp_packet = packet.find(pkt.tcp)
        udp_packet = packet.find(pkt.udp)

        if [icmp_packet, tcp_packet, udp_packet, arp_packet] == [None]*4:
            return
        if ip6_packet is not None:
            return
        packets = [ip4_packet, eth_packet, tcp_packet, udp_packet, arp_packet]
        self.flood(event, packets, src_pid)

    def flood(self, event, packets, src_pid):
        ip4_packet, eth_packet, tcp_packet, udp_packet, arp_packet = packets
        dst_pid, dst_entry = self.find_dst(event, arp_packet, eth_packet)
        if src_pid == dst_pid:
            src_port = dst_entry.port
        else:
            paths = self.get_minimum_paths(dst_pid)
            src_port = self.find_dst_port(paths, dst_pid)
        self._update_flow_table(event, packets, src_port, dst_pid)
        self._send_packet(event, src_port)

    def get_minimum_paths(self, dst_pid):
        adjacents = self.get_adjacents(dst_pid)
        paths = [[an_adjacent] for an_adjacent in adjacents]
        while not self.has_reached_dst(paths, dst_pid):
            for a_path in paths:
                adjacents_of_last_link = self.get_adjacents(a_path[-1].dpid2)
                for an_adjacent in adjacents_of_last_link:
                    paths.append(a_path + [an_adjacent])
        return self.filter_paths_not_reaches_dst(paths, dst_pid)

    def find_dst_port(self, paths, dst_pid):
        if len(paths) == 1:
            return paths[0][0].port1
        if len(paths) == 0:
            return None
        for a_path in paths:
            dst_port = a_path[-1].port1
            if dst_port not in used_ports[dst_pid]:
                return dst_port
        port = None
        while not port:
            dst_port = random.choice(paths)[0].port1
            if dst_port == last_used_port[dst_pid]:
                continue
            port = dst_port
        return port

    def _update_flow_table(self, event, packets, src_port, dst_pid):
        ip4_packet, eth_packet, tcp_packet, udp_packet = packets
        message = "Sending packet in switch: %s '\n'" % dpidToStr(dst_pid)
        message += "eth:%s -> %s '\n'" % (eth_packet.src, eth_packet.dst)
        msg = open_flow.ofp_flow_mod()
        msg.match.dl_type = eth_packet.type
        msg.match.nw_src = ip4_packet.srcip
        msg.match.nw_dst = ip4_packet.dstip
        msg.match.nw_proto = ip4_packet.protocol
        message += "IPv4: %s -> %s" % (ip4_packet.srcip, ip4_packet.dstip)
        message += self.match_packet(tcp_packet, msg, "TCP")
        message += self.match_packet(udp_packet, msg, "UDP")
        msg.actions.append(open_flow.ofp_action_output(port=src_port))
        event.connection.send(msg)
        print message
        used_ports[dst_pid].add(src_port)
        last_used_port[dst_pid] = src_port

    def _send_packet(self, event, src_port):
        msg = open_flow.ofp_packet_out()
        msg.actions.append(open_flow.ofp_action_output(port=src_port))
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)

    def find_dst(self, event, arp_packet, eth_packet):
        src_pid = event.connection.dpid
        switch = dpidToStr(src_pid) + " --- dst=" + str(eth_packet.dst)
        if arp_packet is None:
            log.info("Flooding packet in switch: " + switch)
        msg = open_flow.ofp_packet_out()
        port = open_flow.OFPP_FLOOD
        msg.actions.append(open_flow.ofp_action_output(port=port))
        msg.data = event.ofp
        msg.in_port = event.port
        event.connection.send(msg)
        dst_entry = core.host_tracker.getMacEntry(eth_packet.dst)
        if dst_entry is None or arp_packet is not None:
            return self.find_dst(event, arp_packet, eth_packet)
        switch = dpidToStr(src_pid) + " --- dst=" + str(eth_packet.dst)
        log.info("Calculating packet path in switch: " + switch)
        dst_pid = dst_entry.dpid
        return dst_pid, dst_entry

    def filter_paths_not_reaches_dst(self, paths, pid_dst):
        dst_paths = []
        for some_path in paths:
            if some_path[-1].dpid2 != pid_dst:
                continue
            dst_paths.append(some_path)
        return dst_paths

    def has_reached_dst(self, paths, pid_dst):
        for some_path in paths:
            if some_path[-1].dpid2 != pid_dst:
                continue
            return True
        return False

    def match_packet(self, packet, msg, protocol):
        if packet is None:
            return ""
        msg.match.tp_src = packet.srcport
        msg.match.tp_dst = packet.dstport
        return "\n%s: %s -> %s" % (protocol, packet.srcport, packet.dstport)

    def get_adjacents(self, dst_pid):
        adjacents = []
        for an_adjacent in core.openflow_discovery.adjacency:
            if an_adjacent.dpid1 != dst_pid:
                continue
            adjacents.append(an_adjacent)
        return adjacents

