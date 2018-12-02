from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.util import dpidToStr
from pox.lib.packet.packet_utils import _ethtype_to_str
from pox.host_tracker.host_tracker import host_tracker
import pox.lib.packet as pkt
from pox.lib.revent import *
from ecmp_table import ECMPTable

log = core.getLogger()


class Controller(object):

    def __init__(self):
        core.openflow.addListeners(self)

        def startup():
            core.openflow.addListeners(self, priority=0)
            core.openflow_discovery.addListeners(self)

        core.call_when_ready(startup, ('openflow', 'openflow_discovery'))

        self.event = None
        self.dpid = None
        self.in_port = None
        self.packet = None
        self.dst_dpid = None
        self.out_port = None
        self.table = ECMPTable()
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
        self.adjacency = {}
        self.host_tracker = host_tracker()
        log.info("controller ready")

    def add_adjacency(self, dpid1, port1, dpid2, port2):
        if dpid1 not in self.adjacency:
            self.adjacency[dpid1] = {}
        self.adjacency[dpid1][port1] = {
                "dpid": dpid2,
                "port": port2
            }

    def remove_adjacency(self, dpid, port):
        if dpid not in self.adjacency:
            return
        if port not in self.adjacency[dpid][port]:
            return
        del self.adjacency[dpid][port]

    def _handle_LinkEvent(self, event):
        log.info("--------------------------------------------------")
        link = event.link
        if event.added:
            self.add_adjacency(link.dpid1, link.port1, link.dpid2, link.port2)
            self.add_adjacency(link.dpid2, link.port2, link.dpid1, link.port1)
        elif event.removed:
            self.remove_adjacency(link.dpid1, link.port1)
            self.remove_adjacency(link.dpid2, link.port2)
        log.info('link added is %s' % event.added)
        log.info('link removed is %s' % event.removed)
        log.info('switch1 %d' % link.dpid1)
        log.info('port1 %d' % link.port1)
        log.info('switch2 %d' % link.dpid2)
        log.info('port2 %d' % link.port2)
        log.info("--------------------------------------------------")

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = ETHER_BROADCAST
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

    def fill_arp_table(self):
        entry = self.host_tracker.getMacEntry(self.addr_dst)
        if entry is None:
            log.info("HOST TRACKER COULD NOT FIND ENTRY DST")
            return
        self.arp_table[self.addr_dst] = {
            "dpid": entry.dpid,
            "port": entry.port
        }

    def print_adjacents(self):
        msg = ""
        for dpid in self.adjacency:
            msg += "dpid: %s: [" % dpid
            for port in self.adjacency[dpid]:
                msg += "%s, " % self.adjacency[dpid][port]["dpid"]
            msg += "]"
            log.info(msg)
            msg = ""

    def has_discovered_the_entire_topology(self):
        if len(self.adjacency.keys()) != 7:
            return False
        for dpid in self.adjacency:
            size = len(self.adjacency[dpid])
            if dpid in [4, 5, 6, 7] and size < 2:
                return False
            if dpid in [2, 3] and size < 4:
                return False
            if dpid == 1 and size < 1:
                return False
        return True

    def _handle_PacketIn(self, event):
        self.host_tracker._handle_PacketIn(event)
        if not self.has_discovered_the_entire_topology():
            log.info("Please wait... learning the topology")
            return
        self.event = event
        self.dpid = event.connection.dpid
        log.info("--------------------------------------------------------")
        self.print_adjacents()
        log.info("SWITCH %s" % self.dpid)
        self.in_port = event.port
        self.packet = event.parsed
        log.info("ports: %s" % event.connection.ports)
        log.info("ports: %s" % event.connection.ports)
        log.info("in port: %s" % self.in_port)
        if not self.packet.parsed:
            log.warning("%i %i ignoring unparsed packet" %
                        (self.dpid, self.in_port))
            return
        log.info("HOST SRC %s" % self.packet.src)
        log.info("HOST DST: %s" % self.packet.dst)
        self.eth_packet = self.packet.find(pkt.ethernet)
        self.addr_dst = self.packet.dst
        self.fill_arp_table()
        self.ip_packet = self.packet.find(pkt.ipv4)
        self.arp_packet = self.packet.find(pkt.arp)
        self.icmp_packet = self.packet.find(pkt.icmp)
        self.tcp_packet = self.packet.find(pkt.tcp)
        self.udp_packet = self.packet.find(pkt.udp)

        if not self.validate_protocols():

            return
        if not self.validate_net_packets():
            return

        if self.addr_dst not in self.arp_table:
            log.warning("Could not find dst")
            return self.flood()

        entry = self.arp_table[self.addr_dst]
        self.dst_dpid = entry["dpid"]
        if self.dpid == self.dst_dpid:
            log.info("Current switch is destination")
            self.out_port = entry["port"]
        else:
            if self.packet.dst.is_multicast:
                self.print_msg("MULTICAST")
                return self.flood()
            log.info("Finding minimun paths from %s to %s"
                     % (self.dpid, self.dst_dpid))
            minimun_paths = self.get_minimun_paths()
            log.info("finding out port")
            self.out_port = self.get_out_port(minimun_paths)
            if self.out_port is None:
                log.info("Could not find out port")
                return
        log.info("out port: %s" % self.out_port)
        log.info("Updating flow table")
        self.update_table()
        log.info("Sending packet")
        self.send_packet()

    def flood(self):
        log.info("FLOODING PACKET")
        msg = of.ofp_packet_out()
        msg.buffer_id = self.event.ofp.buffer_id
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
        if _ethtype_to_str[self.packet.type] == "IPV6":
            log.warning("DROP IPV6 packet")
            return False
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
        msg.buffer_id = self.event.ofp.buffer_id
        if self.protocol != "ICMP":
            msg.match.tp_src = self.protocol_packet.srcport
            msg.match.tp_dst = self.protocol_packet.dstport
        msg.actions.append(of.ofp_action_output(port=self.out_port))
        self.event.connection.send(msg)
        self.balance_of_charges()

    def get_minimun_paths(self):
        adjacents = self.get_adjacents(self.dpid)
        if not adjacents:
            log.warning("NO ADJACENTS FOUND")
            return []
        paths = [[neighbour] for neighbour in adjacents]
        while not self.has_found_a_path(paths, self.dst_dpid):
            last_paths = paths[:]
            for path in last_paths:
                adjacents = self.get_adjacents(path[-1]["dpid"])
                for an_adjacent in adjacents:
                    if an_adjacent["dpid"] != self.dpid:
                        if not self.node_belongs_path(an_adjacent, path):
                            paths.append(path + [an_adjacent])
        return self.filter_paths(paths, self.dst_dpid)

    def node_belongs_path(self, node, path):
        dpid = node["dpid"]
        for a_node in path:
            if a_node["dpid"] == dpid:
                return True
        return False

    def get_out_port(self, paths_to_dst):
        if len(paths_to_dst) == 0:
            return None
        ports = self.get_all_ports(paths_to_dst)
        data = (
            ports,
            self.dpid,
            self.dst_dpid,
            self.protocol,
            self.packet.src,
            self.packet.dst
        )
        return self.table.get_port_applying_ecmp(data)

    def balance_of_charges(self):
        log.info("saving (%s, %s, %s): %s" %
                 (self.dpid, self.dst_dpid, self.protocol, self.out_port))
        data = (
            self.dpid,
            self.dst_dpid,
            self.protocol,
            self.packet.src,
            self.packet.dst,
            self.out_port
        )
        self.table.save_port(data)

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

    def has_found_a_path(self, paths, dpid):
        for path in paths:
            if path[-1]["dpid"] == dpid:
                log.info("FOUND A PATH!")
                return True
        return False

    def get_adjacents(self, dpid):
        adjacents = []
        if dpid not in self.adjacency:
            return adjacents
        for port in self.adjacency[dpid]:
            adjacents.append({
                "dpid": self.adjacency[dpid][port]["dpid"],
                "port": port
            })
        return adjacents

    def filter_repeated(self, adjacents):
        filtered = []
        belongs = False
        for an_adjacent in adjacents:
            for final_adjacent in filtered:
                dpid_1 = final_adjacent["dpid"]
                dpid_2 = an_adjacent["dpid"]
                port_1 = final_adjacent["port"]
                port_2 = an_adjacent["port"]
                if dpid_1 == dpid_2 and port_1 == port_2:
                    belongs = True
                    break
            if not belongs:
                filtered.append(an_adjacent)
                belongs = False
        return filtered

    def send_packet(self):
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=self.out_port))
        msg.data = self.event.ofp
        msg.buffer_id = self.event.ofp.buffer_id
        msg.in_port = self.in_port
        self.event.connection.send(msg)
