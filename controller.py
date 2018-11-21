from pox.core import core
from pox.host_tracker import host_tracker
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.revent import *

log = core.getLogger()

class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)
        self.eth_packet = None
        self.ip_packet = None
        self.arp_packet = None
        self.icmp_packet = None
        self.tcp_packet = None
        self.udp_packet = None
        self.dst_dpid = None
        self.out_port = None
        self.table = {}

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        dpid = dpidToStr(event.connection.dpid)
        log.info("Flooding multicast packets in switch: " + dpid)
        msg = of.ofp_flow_mod()
        msg.match.dl_dst = pkt.ETHER_BROADCAST
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    @staticmethod
    def print_msg(msg):
        print "++++++++++++++++++++++++++++++++++++++++++"
        print msg
        print "++++++++++++++++++++++++++++++++++++++++++"

    def _handle_PacketIn(self, event):
        self.event = event
        self.dpid = event.connection.dpid
        self.in_port = event.port
        self.packet = event.parsed
        if not self.packet.parsed:
            log.warning(
                "%i %i ignoring unparsed packet" % (self.dpid, self.in_port))
            return
        if not self.get_packet():
            return
        entry = None
        while entry is None:
            self.flood()
            entry = host_tracker.getMacEntry(self.eth_packet.dst)

        self.dst_dpid = entry.dpid
        if self.dpid == self.dpid:
            self.out_port = entry.port
        else:
            minimun_paths = self.get_minimun_paths()
            self.out_port = self.get_out_port(minimun_paths)
            if self.out_port is None:
                return
            self.update_table()
            self.send_packet()

    def flood(self):
        if self.arp_packet is None:
            dpid = dpidToStr(self.event.connection.dpid)
            dst = str(self.eth_packet.dst)
            log.info("Flooding packet in switch: " + dpid + " --- dst=" + dst)
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = self.event.ofp
        msg.in_port = self.in_port
        self.event.connection.send(msg)

    def get_packet(self):
        self.eth_packet = self.packet.find(pkt.ethernet)
        self.ip_packet = self.packet.find(pkt.ipv4)
        self.arp_packet = self.packet.find(pkt.arp)
        self.icmp_packet = self.packet.find(pkt.icmp)
        self.tcp_packet = self.packet.find(pkt.tcp)
        self.udp_packet = self.packet.find(pkt.udp)
        packets = [
            self.icmp_packet,
            self.tcp_packet,
            self.udp_packet,
            self.arp_packet
        ]
        return packets == [None]*4

    def save_packet(self, packet, msg):
        if self.tcp_packet is None:
            return
        msg.match.tp_src = packet.srcport
        msg.match.tp_dst = packet.dstport

    def update_table(self):
        msg = of.ofp_flow_mod()
        msg.match.dl_type = self.eth_packet.type
        msg.match.nw_src = self.ip_packet.srcip
        msg.match.nw_dst = self.ip_packet.dstip
        msg.match.nw_proto = self.ip_packet.protocol
        self.save_packet(self.tcp_packet, msg)
        self.save_packet(self.udp_packet, msg)
        msg.actions.append(of.ofp_action_output(port=self.in_port))
        self.event.connection.send(msg)
        self.balance_of_charges()

    def get_minimun_paths(self):
        paths = [[neighbour] for neighbour in self.get_adjacents(self.dpid)]
        paths_to_dst = []
        while not paths_to_dst:
            for path in paths:
                adjacents = self.get_adjacents(path[-1]["dpid"])
                for an_adjacent in adjacents:
                    paths.append(path + [an_adjacent])
            paths_to_dst = self.filter_paths(paths, self.dst_dpid)
        return paths_to_dst

    def get_out_port(self, paths_to_dst):
        if len(paths_to_dst) == 0:
            return None
        return self.get_port_applying_ecmp(self.get_all_ports(paths_to_dst))

    def get_port_applying_ecmp(self, ports):
        for port in ports:
            if self.table[(self.dpid, self.dst_dpid)][self.tcp_packet] == port:
                return port
        return ports[0]  # random

    def balance_of_charges(self):
        self.table[(self.dpid, self.dst_dpid)][self.tcp_packet] = self.out_port

    @staticmethod
    def get_all_ports(paths_to_dst):
        return [a_path[0]["port"] for a_path in paths_to_dst]

    @staticmethod
    def filter_paths(paths, dpid):
        paths_to_dst = []
        for path in paths:
            if path[-1]["dpid"] != dpid:
                continue
            paths_to_dst.append(path)
        return paths_to_dst

    @staticmethod
    def get_adjacents(dpid):
        adjacents = []
        for an_adjacent in core.openflow_discovery.adjacency:
            if an_adjacent.dpi1 != dpid:
                continue
            adjacents.append({
                "dpid": an_adjacent.dpid2,
                "port": an_adjacent.port2
            })
        return adjacents

    def send_packet(self):
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=self.out_port))
        msg.data = self.event.ofp
        msg.in_port = self.in_port
        self.event.connection.send(msg)


def launch():
    core.registerNew(Controller)
