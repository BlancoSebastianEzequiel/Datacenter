from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.revent import *

log = core.getLogger()


class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)
        self.event = None
        self.dpid = None
        self.in_port = None
        self.packet = None
        self.dst_dpid = None
        self.out_port = None
        self.table = {}
        self.eth_packet = None
        self.ip_packet = None
        self.arp_packet = None
        self.icmp_packet = None
        self.tcp_packet = None
        self.udp_packet = None
        self.net_packet = None
        self.protocol_packet = None
        self.protocol = None
        self.arp_table = {}
        self.is_ip = True

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        self.print_msg("EVENT: %s" % event.connection.__class__.__name__)

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = pkt.ETHER_BROADCAST
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.IPV6_TYPE
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.match.dl_type = pkt.ethernet.ARP_TYPE
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
        self.eth_packet = self.packet.find(pkt.ethernet)
        self.ip_packet = self.packet.find(pkt.ipv4)
        self.arp_packet = self.packet.find(pkt.arp)
        self.icmp_packet = self.packet.find(pkt.icmp)
        self.tcp_packet = self.packet.find(pkt.tcp)
        self.udp_packet = self.packet.find(pkt.udp)

        if not self.validate_protocols():
            return
        if not self.validate_net_packets():
            return

        entry = core.host_tracker.getMacEntry(self.packet.dst)

        if entry is None:
            log.warning("Could not find dst")
            return self.flood()

        self.dst_dpid = entry.dpid
        if self.dpid == self.dst_dpid:
            log.info("Current switch is destination")
            self.out_port = entry.port
        else:
            if self.packet.dst.is_multicast:
                self.print_msg("MULTICAST")
                return self.flood()
            log.info("Finding minimun paths")
            minimun_paths = self.get_minimun_paths()
            log.info("finding out port")
            self.out_port = self.get_out_port(minimun_paths)
            if self.out_port is None:
                log.info("could not find out port")
                return
        log.info("Updating flow table")
        self.update_table()
        log.info("Sending packet")
        self.send_packet()

    def flood(self):
        dpid = dpidToStr(self.dpid)
        dst = str(self.eth_packet.dst)
        log.info("Flooding packet in switch: " + dpid + " --- dst=" + dst)
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = self.event.ofp
        msg.in_port = self.in_port
        self.event.connection.send(msg)

    def validate_protocols(self):
        if self.udp_packet is not None:
            log.info("UDP packet!")
            self.protocol = "UDP"
            self.protocol_packet = self.udp_packet
            return True
        elif self.tcp_packet is not None:
            log.info("TCP packet!")
            self.protocol = "TCP"
            self.protocol_packet = self.tcp_packet
            return True
        elif self.icmp_packet is not None:
            log.info("ICMP packet!")
            self.protocol = "ICMP"
            self.protocol_packet = self.icmp_packet
            return True
        else:
            log.warning("icmp, tcp and udp packets are None!")
            return False

    def validate_net_packets(self):
        if self.eth_packet is None:
            log.warning("ETHERNET packet is None!")
            return False
        if self.ip_packet is not None:
            log.info("IP packet!")
            self.is_ip = True
            self.net_packet = self.ip_packet
        elif self.arp_packet is not None:
            log.info("ARP packet!")
            self.is_ip = False
            self.net_packet = self.arp_packet
        else:
            log.warning("ARP and TCP packets are None!")
            return False
        return True

    def match_protocol_packets(self, msg):
        if self.is_ip:
            msg.match.nw_src = self.net_packet.srcip
            msg.match.nw_dst = self.net_packet.dstip
            msg.match.nw_proto = self.net_packet.protocol
            return msg
        msg.match.nw_src = self.net_packet.protosrc
        msg.match.nw_dst = self.net_packet.protodst
        msg.match.nw_proto = self.net_packet.prototype
        return msg

    def match_packet(self, msg):
        if not self.is_ip:
            return msg
        msg.match.nw_src = self.ip_packet.srcip
        msg.match.nw_dst = self.ip_packet.dstip
        msg.match.nw_proto = self.ip_packet.protocol
        return msg

    def update_table(self):
        msg = of.ofp_flow_mod()
        msg.match.dl_type = self.eth_packet.type
        msg = self.match_packet(msg)
        if self.protocol != "ICMP":
            msg.match.tp_src = self.protocol_packet.srcport
            msg.match.tp_dst = self.protocol_packet.dstport
        msg.actions.append(of.ofp_action_output(port=self.out_port))
        self.event.connection.send(msg)
        self.balance_of_charges()

    def get_minimun_paths(self):
        begin = {"dpid": self.dpid, "port": self.in_port}
        adjacents = self.get_adjacents(self.dpid)
        paths = [[begin, neighbour] for neighbour in adjacents]
        paths_to_dst = []
        while not paths_to_dst:
            last_paths = paths[:]
            for path in last_paths:
                adjacents = self.get_adjacents(path[-1]["dpid"])
                for an_adjacent in adjacents:
                    if not self.node_belongs_path(an_adjacent, path):
                        paths.append(path + [an_adjacent])
            paths_to_dst = self.filter_paths(paths, self.dst_dpid)
        return paths_to_dst

    def node_belongs_path(self, node, path):
        dpid = node["dpid"]
        port = node["port"]
        for a_node in path:
            if a_node["dpid"] == dpid and a_node["port"] == port:
                return True
        return False

    def get_out_port(self, paths_to_dst):
        if len(paths_to_dst) == 0:
            return None
        return self.get_port_applying_ecmp(self.get_all_ports(paths_to_dst))

    def get_port_applying_ecmp(self, ports):
        key = (self.dpid, self.dst_dpid, self.protocol)
        if key not in self.table:
            self.table[key] = ports[0]
            return ports[0]  # random
        for port in ports:
            if self.table[key] == port:
                return port
        return ports[0]  # random

    def balance_of_charges(self):
        log.info("saving (%s, %s, %s): %s" %
                 (self.dpid, self.dst_dpid, self.protocol, self.out_port))
        key = (self.dpid, self.dst_dpid, self.protocol)
        self.table[key] = self.out_port

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
            if an_adjacent.dpid1 == dpid:
                adjacents.append({
                    "dpid": an_adjacent.dpid2,
                    "port": an_adjacent.port2
                })
            elif an_adjacent.dpid2 == dpid:
                adjacents.append({
                    "dpid": an_adjacent.dpid1,
                    "port": an_adjacent.port1
                })
        return adjacents

    def send_packet(self):
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=self.out_port))
        msg.data = self.event.ofp
        msg.in_port = self.in_port
        self.event.connection.send(msg)
