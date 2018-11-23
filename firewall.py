import pox.lib.packet as pkt
from pox.core import core
import pox.openflow.libopenflow_01 as of
from time import time

UDP_PROTOCOL = pkt.ipv4.UDP_PROTOCOL
IP_TYPE = pkt.ethernet.IP_TYPE

log = core.getLogger()

class Firewall(object):
    def __init__(self):
        self.MAX_UDP_PACKETS = 100
        self.MAX_UDP_TIME = 100
        self.udp_flow_packets = {}
        self.total_udp_flow_packets = {}
        self.current_udp_flow_packets = {}
        self.blocked_udp_packets = {}
        self.dst_ip = None
        core.openflow.addListeners(self)
        core.openflow.addListenerByName("FlowStatsReceived", self.handle_denial_of_service)

    def handle_denial_of_service(self, event):
        for flow in event.stats:
            self.dst_ip = flow.match.nw_dst
            self.get_udp_flow(flow)
            self.evaluate_blocking()

    def get_udp_flow(self, flow):
        if self.dst_ip is not None and flow.match.nw_proto != UDP_PROTOCOL:
            return
        if self.dst_ip not in self.udp_flow_packets:
            self.total_udp_flow_packets[self.dst_ip] = flow.packet_count
        else:
            self.total_udp_flow_packets[self.dst_ip] += flow.packet_count

    def evaluate_blocking(self):
        for dst_ip in self.total_udp_flow_packets:
            total = self.total_udp_flow_packets[dst_ip]
            self.current_udp_flow_packets[dst_ip] = total
            last = self.udp_flow_packets[dst_ip]
            if (total - last) > self.MAX_UDP_PACKETS:
                self.block_udp_packet(dst_ip)
            else:
                self.unblock_udp_packet(dst_ip)

    def block_udp_packet(self, dst_ip):
        if dst_ip not in self.blocked_udp_packets:
            log.info("Blocking ip: %s" % dst_ip)
            msg = of.ofp_flow_mod()
            msg.match.nw_proto = UDP_PROTOCOL
            msg.match.dl_type = IP_TYPE
            msg.priority = of.OFP_DEFAULT_PRIORITY + 1
            msg.match.nw_dst = dst_ip
            self.send_message_to_all(msg)
        self.blocked_udp_packets[dst_ip] = time()

    def unblock_udp_packet(self, dst_ip):
        if dst_ip not in self.blocked_udp_packets:
            return
        time_passed = time() - self.blocked_udp_packets[dst_ip]
        if time_passed < self.MAX_UDP_TIME:
            return
        log.info("unblocking ip: %s" % dst_ip)
        msg = of.ofp_flow_mod()
        msg.match.nw_proto = UDP_PROTOCOL
        msg.match.dl_type = IP_TYPE
        msg.command = of.OFPFC_DELETE
        msg.match.nw_dst = dst_ip
        self.send_message_to_all(msg)

    def send_message_to_all(self, msg):
        for a_connection in core.openflow.connections:
            a_connection.send(msg)


def launch():
    core.registerNew(Firewall)
