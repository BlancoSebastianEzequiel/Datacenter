import pox.lib.packet as pkt
from pox.core import core
import pox.openflow.libopenflow_01 as of
from time import time
from pox.lib.recoco import Timer
from pox.lib.revent import *

UDP_PROTOCOL = pkt.ipv4.UDP_PROTOCOL
IP_TYPE = pkt.ethernet.IP_TYPE
log = core.getLogger()


class Firewall(EventMixin):
    def __init__(self):
        self.MAX_UDP_PACKETS = 100
        self.MAX_UDP_TIME = 100
        self.last_udp_flow_packets = {}
        self.total_udp_flow_packets = {}
        self.blocked_udp_packets = {}
        self.dst_ip = None
        self.dpid = None
        core.openflow.addListenerByName(
            "FlowStatsReceived",
            self._handle_flowstats_received
        )
        Timer(5, self.request_for_switch_statistics, recurring=True)
        log.info("firewall ready")

    def request_for_switch_statistics(self):
        for connection in core.openflow.connections:
            body = of.ofp_flow_stats_request()
            connection.send(of.ofp_stats_request(body=body))

    def _handle_flowstats_received(self, event):
        log.info("handle denial of service")
        self.dpid = event.connection.dpid
        self.total_udp_flow_packets = {}
        for flow in event.stats:
            self.dst_ip = flow.match.nw_dst
            if self.dst_ip is None:
                log.info("DST IP IS NONE. COULD NOT HANDLE DoS")
                continue
            if not self.get_udp_flow(flow):
                continue
            self.evaluate_blocking()
            current = self.total_udp_flow_packets[self.dst_ip]
            self.last_udp_flow_packets[self.dpid] = {}
            self.last_udp_flow_packets[self.dpid][self.dst_ip] = current

    def get_udp_flow(self, flow):
        if self.dst_ip is None or flow.match.nw_proto != UDP_PROTOCOL:
            return False
        if self.dst_ip not in self.total_udp_flow_packets:
            self.total_udp_flow_packets[self.dst_ip] = flow.packet_count
        else:
            self.total_udp_flow_packets[self.dst_ip] += flow.packet_count
        return True

    def get_last_udp_flow_packets(self, dst_ip):
        if self.dpid not in self.last_udp_flow_packets:
            self.last_udp_flow_packets[self.dpid] = {}
            self.last_udp_flow_packets[self.dpid][dst_ip] = 0
            return 0
        elif dst_ip not in self.last_udp_flow_packets[self.dpid]:
            self.last_udp_flow_packets[self.dpid][dst_ip] = 0
        return self.last_udp_flow_packets[self.dpid][dst_ip]

    def evaluate_blocking(self):
        for dst_ip in self.total_udp_flow_packets:
            current = self.total_udp_flow_packets[dst_ip]
            last = self.last_udp_flow_packets.get(self.dpid, {}).get(dst_ip, 0)
            if (current - last) > self.MAX_UDP_PACKETS:
                self.block_udp_packet(dst_ip)
            else:
                self.unblock_udp_packet(dst_ip)

    def block_udp_packet(self, dst_ip):
        log.info("BLOCKING UDP PACKET IN %s" % dst_ip)
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
        del self.blocked_udp_packets[dst_ip]
        log.info("UNBLOCKING UDP PACKET IN %s" % dst_ip)
        log.info("unblocking ip: %s" % dst_ip)
        msg = of.ofp_flow_mod()
        msg.match.nw_proto = UDP_PROTOCOL
        msg.match.dl_type = IP_TYPE
        msg.command = of.OFPFC_DELETE
        msg.match.nw_dst = dst_ip
        self.send_message_to_all(msg)

    @staticmethod
    def send_message_to_all(msg):
        for a_connection in core.openflow.connections:
            a_connection.send(msg)
