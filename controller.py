from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.util import dpid_to_str

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
        self.build_table(event=event, packet=packet)

    def flood(self, message=None, event=None):
        """
        if time.time() - self.connection.connect_time >= _flood_delay:
            if self.hold_down_expired is False:
                self.hold_down_expired = True
                log.info("%s: Flood hold-down expired -- flooding",
                         dpid_to_str(event.dpid))
            if message is not None:
                log.debug(message)
        else:
            pass
        """
        msg = of.ofp_packet_out()
        if message is not None:
            log.debug(message)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)

    def drop(self, duration=None, event=None, packet=None):
        if duration is not None:
            msg = of.ofp_flow_mod()  # install a flow table entry.
            msg.match = of.ofp_match.from_packet(packet)
            msg.idle_timeout = duration
            msg.hard_timeout = duration
            msg.buffer_id = event.ofp.buffer_id
            self.connection.send(msg)
        elif event.ofp.buffer_id is not None:
            msg = of.ofp_packet_out()  # instructs a switch to send a packet.
            msg.buffer_id = event.ofp.buffer_id
            msg.in_port = event.port
            self.connection.send(msg)

    def build_table(self, event=None, packet=None):
        # Update address/port table
        self.mac_to_port[packet.src] = event.port
        if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
            self.drop(event=event, packet=packet)
            return
        """
        if packet.dst.is_multicast:
            msg = "Port for %s multicast -- flooding" % packet.dst
            self.flood(message=msg, event=event)
            return
        """
        if packet.dst not in self.mac_to_port:
            message = "Port for %s unknown -- flooding" % packet.dst
            self.flood(message=message, event=event)
            # paths = self.get_minimum_paths(event.dpid, self.connection.dpid)
            # dst_port = self.find_dst_port(paths, self.connection.dpid)
            # if dst_port is None:
                #return
            # self.mac_to_port[packet.dst] = dst_port
        dst_port = self.mac_to_port[packet.dst]
        if event.port == dst_port:
            data = (packet.src, packet.dst, dpid_to_str(event.dpid), dst_port)
            msg = "Same port for packet from %s -> %s on %s.%s.  Drop." % data
            log.warning(msg)
            self.drop(duration=10, event=event, packet=packet)
            return
        self.update_flow_table(dst_port, packet.dst)
        self.send_packet(event, dst_port)

    def print_msg(self, msg):
        print "++++++++++++++++++++++++++++++++++++++++++++++++++++"
        print msg
        print "++++++++++++++++++++++++++++++++++++++++++++++++++++"

    def get_minimum_paths(self, src_dpid, dst_dpid):
        adjacents = self.get_adjacents(src_dpid)
        if not adjacents:
            return []
        paths = [[an_adjacent] for an_adjacent in adjacents]
        exclude = src_dpid
        max_iterations = 1000
        i = 0
        while not self.has_reached_dst(paths, dst_dpid) and i < max_iterations:
            for a_path in paths:
                adjacents = self.get_adjacents(a_path[-1]["dpid"], exclude)
                for an_adjacent in adjacents:
                    paths.append(a_path + [an_adjacent])
                exclude = a_path[-1]["dpid"]
            i += 0
        return self.filter_paths_not_reaches_dst(paths, dst_dpid)

    def find_dst_port(self, paths, dst_pid, dst_port=None):
        if len(paths) == 1:
            return paths[0][0]["dpid"]
        if len(paths) == 0:
            return dst_port
        for a_path in paths:
            dst_port = a_path[0]["dpid"]  # es en cero? porque es el nex hob no?
            if dst_port not in self.mac_to_port[dst_pid]:
                return dst_port
        return dst_port

    def update_flow_table(self, dst_port, dst_addr):
        message = "Sending packet in switch: %s '\n'" % dpid_to_str(dst_addr)
        message += "eth:%s -> %s '\n'" % \
                   (self.eth_packet.src, self.eth_packet.dst)
        msg = of.ofp_flow_mod()
        msg.match.dl_type = self.eth_packet.type
        msg.match.nw_src = self.ip4_packet.srcip
        msg.match.nw_dst = self.ip4_packet.dstip
        msg.match.nw_proto = self.ip4_packet.protocol
        message += "IPv4: %s -> %s" % \
                   (self.ip4_packet.srcip, self.ip4_packet.dstip)
        message += self.match_packet(self.tcp_packet, msg, "TCP")
        message += self.match_packet(self.udp_packet, msg, "UDP")
        msg.actions.append(of.ofp_action_output(port=dst_port))
        self.connection.send(msg)
        print message

    def send_packet(self, event, dst_port):
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=dst_port))
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)

    def filter_paths_not_reaches_dst(self, paths, pid_dst):
        dst_paths = []
        for some_path in paths:
            if some_path[-1]["dpid"] != pid_dst:
                continue
            dst_paths.append(some_path)
        return dst_paths

    def has_reached_dst(self, paths, pid_dst):
        for some_path in paths:
            if some_path[-1]["dpid"] != pid_dst:
                continue
            return True
        return False

    def match_packet(self, packet, msg, protocol):
        if packet is None:
            return ""
        msg.match.tp_src = packet.srcport
        msg.match.tp_dst = packet.dstport
        return "\n%s: %s -> %s" % (protocol, packet.srcport, packet.dstport)

    def get_adjacents(self, dpid, exclude=None):
        adjacents = []
        # asi es el formato
        # {Link(dpid1=6, port1=1, dpid2=2, port2=4): 1542509517.675606}
        for an_adjacent in core.openflow_discovery.adjacency:
            if an_adjacent.dpid1 == dpid and an_adjacent.dpid1 != exclude:
                adjacents.append({
                    "dpid": an_adjacent.dpid2,
                    "port": an_adjacent.port2
                })
            elif an_adjacent.dpid2 == dpid and an_adjacent.dpid1 != exclude:
                adjacents.append({
                    "dpid": an_adjacent.dpid1,
                    "port": an_adjacent.port1
                })
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

