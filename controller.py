from pox.core import core
import pox.openflow.libopenflow_01 as open_flow
import pox.lib.packet as pkt
from pox.lib.util import dpid_to_str
import time

log = core.getLogger()
_flood_delay = 0

class Controller(object):

    tcp_packet = None
    udp_packet = None
    ip4_packet = None
    eth_packet = None
    arp_packet = None
    ip6_packet = None
    icmp_packet = None

    def __init__(self, event):
        self.mac_to_port = {}
        core.openflow.addListeners(self)
        self.connection = event.connection
        self.hold_down_expired = _flood_delay == 0
        self.connection.addListeners(self)
        self.event = event

    def _handle_PacketIn (self, event):
        """
        :type event: pox.openflow.ConnectionUp
        """
        packet = event.parsed
        src_port = event.port
        src_pid = event.dpid
        if not packet:
            log.warning("%i %i ignoring not parsed packet", src_pid, src_port)
            return
        self.icmp_packet = packet.find(pkt.icmp)
        self.arp_packet = packet.find(pkt.arp)
        self.eth_packet = packet.find(pkt.ethernet)
        self.ip4_packet = packet.find(pkt.ipv4)
        self.tcp_packet = packet.find(pkt.tcp)
        self.udp_packet = packet.find(pkt.udp)
        packets = [
            self.icmp_packet,
            self.tcp_packet,
            self.udp_packet,
            self.arp_packet
        ]
        if packets == [None] * 4:
            return
        self.flood(event=event)
        self.drop(event=event, packet=packet)

    def flood(self, message=None, event=None):
        msg = open_flow.ofp_packet_out()
        if time.time() - self.connection.connect_time >= _flood_delay:
            if self.hold_down_expired is False:
                self.hold_down_expired = True
                log.info("%s: Flood hold-down expired -- flooding",
                         dpid_to_str(event.dpid))

            if message is not None:
                log.debug(message)
            port = open_flow.OFPP_FLOOD
            msg.actions.append(open_flow.ofp_action_output(port=port))
        else:
            pass
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)


    def drop(self, duration=None, event=None, packet=None):
        if duration is not None:
            if not isinstance(duration, tuple):
                duration = (duration, duration)
            msg = open_flow.ofp_flow_mod()
            msg.match = open_flow.ofp_match.from_packet(packet)
            msg.idle_timeout = duration[0]
            msg.hard_timeout = duration[1]
            msg.buffer_id = event.ofp.buffer_id
            self.connection.send(msg)
        elif event.ofp.buffer_id is not None:
            msg = open_flow.ofp_packet_out()
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)

        # Update address/port table
        self.mac_to_port[packet.src] = event.port
        if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
            self.drop(event=event, packet=packet)
            return
        if packet.dst.is_multicast:
            self.flood(event=event)
        if packet.dst not in self.mac_to_port:
            message = "Port for %s unknown -- flooding" % packet.dst
            self.flood(message=message, event=event)
        dst_port = self.macToPort[packet.dst]
        dst_pid = event.dst
        if event.port == dst_port:
            data = (packet.src, packet.dst, dpid_to_str(event.dpid), dst_port)
            msg = "Same port for packet from %s -> %s on %s.%s.  Drop." % data
            log.warning(msg)
            self.drop(duration=10, event=event, packet=packet)
            return

        paths = self.get_minimum_paths(dst_pid)
        dst_port = self.find_dst_port(paths, dst_pid, dst_port)
        self.update_flow_table(dst_port, dst_pid)
        self.send_packet(event, dst_port)
        return

    def get_minimum_paths(self, dst_pid):
        adjacents = self.get_adjacents(dst_pid)
        paths = [[an_adjacent] for an_adjacent in adjacents]
        while not self.has_reached_dst(paths, dst_pid):
            for a_path in paths:
                adjacents_of_last_link = self.get_adjacents(a_path[-1].dpid2)
                for an_adjacent in adjacents_of_last_link:
                    paths.append(a_path + [an_adjacent])
        return self.filter_paths_not_reaches_dst(paths, dst_pid)

    def find_dst_port(self, paths, dst_pid, dst_port):
        if len(paths) == 1:
            return paths[0][0].port1
        if len(paths) == 0:
            return dst_port
        for a_path in paths:
            dst_port = a_path[-1].port1
            if dst_port not in self.mac_to_port[dst_pid]:
                return dst_port
        return dst_port

    def update_flow_table(self, dst_port, dst_pid):
        message = "Sending packet in switch: %s '\n'" % dpid_to_str(dst_pid)
        message += "eth:%s -> %s '\n'" % \
                   (self.eth_packet.src, self.eth_packet.dst)
        msg = open_flow.ofp_flow_mod()
        msg.match.dl_type = self.eth_packet.type
        msg.match.nw_src = self.ip4_packet.srcip
        msg.match.nw_dst = self.ip4_packet.dstip
        msg.match.nw_proto = self.ip4_packet.protocol
        message += "IPv4: %s -> %s" % \
                   (self.ip4_packet.srcip, self.ip4_packet.dstip)
        message += self.match_packet(self.tcp_packet, msg, "TCP")
        message += self.match_packet(self.udp_packet, msg, "UDP")
        msg.actions.append(open_flow.ofp_action_output(port=dst_port))
        self.connection.send(msg)
        print message
        self.mac_to_port[dst_pid] = dst_port

    def send_packet(self, event, dst_port):
        msg = open_flow.ofp_packet_out()
        msg.actions.append(open_flow.ofp_action_output(port=dst_port))
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)

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

    def get_adjacents(self, dpid):
        adjacents = []
        for an_adjacent in core.openflow_discovery.adjacency:
            if an_adjacent.dpid1 != dpid:
                continue
            adjacents.append(an_adjacent)
        return adjacents

class MyController(object):
    """
    Waits for OpenFlow switches to connect and makes them learning switches.
    """

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % event.connection)
        Controller(event)


def launch(hold_down=_flood_delay):
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")
    core.registerNew(MyController)

