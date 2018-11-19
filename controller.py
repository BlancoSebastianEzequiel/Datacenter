from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.util import str_to_bool, dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from data_definitions import *
from entry import Entry
from time import time

log = core.getLogger()

class Controller(object):

    def __init__(self, fakeways=None, arp_for_unknowns=False):
        core.openflow.addListeners(self)

        # These are "fake gateways" -- we'll answer ARPs for them with MAC
        # of the switch they're connected to.
        self.fakeways = set(fakeways)

        # If this is true and we see a packet for an unknown
        # host, we'll ARP for it.
        self.arp_for_unknowns = arp_for_unknowns

        # (dpid,IP) -> expire_time
        # We use this to keep from spamming ARPs
        self.outstanding_arps = {}

        # (dpid,IP) -> [(expire_time, buffer_id,in_port), ...]
        # These are buffers we've gotten at this datapath for this IP which
        # we can't deliver because we don't know where they go.
        self.lost_buffers = {}

        # For each switch, we map IP addresses to Entries
        self.arp_table = {}

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))

    def print_msg(self, msg):
        print "++++++++++++++++++++++++++++++++++++++++++"
        print msg
        print "++++++++++++++++++++++++++++++++++++++++++"

    def _handle_PacketIn(self, event):
        self.event = event
        self.dpid = event.connection.dpid
        self.inport = event.port
        self.packet = event.parsed
        if not self.packet.parsed:
            log.warning("%i %i ignoring unparsed packet" %
                        (self.dpid, self.inport))
            return
        if self.dpid not in self.arp_table:
            self.create_empty_table()
        if self.packet.type == ethernet.LLDP_TYPE:
            return
        self.handle_ip_packet()
        self.handle_arp_packet()

    @staticmethod
    def dpid_to_mac(dpid):
        return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

    def create_empty_table(self):
        self.arp_table[self.dpid] = {}
        for fake in self.fakeways:
            entry = Entry(of.OFPP_NONE, self.dpid_to_mac(self.dpid))
            self.arp_table[self.dpid][IPAddr(fake)] = entry

    def handle_ip_packet(self):
        if not isinstance(self.packet.next, ipv4):
            return
        log.debug("%i %i IP %s => %s" %
                  (self.dpid, self.inport, self.packet.next.srcip,
                   self.packet.next.dstip))

        self._send_lost_buffers(
            self.dpid, self.packet.next.srcip, self.packet.src, self.inport)
        self.learn_or_update_port_mac_info(self.packet.next.srcip)

        dstaddr = self.packet.next.dstip
        if dstaddr in self.arp_table[self.dpid]:
            self.send(dstaddr)
        elif self.arp_for_unknowns:
            self.find_unknown_dst(dstaddr)

    def find_unknown_dst(self, dstaddr):
        if (self.dpid, dstaddr) not in self.lost_buffers:
            self.lost_buffers[(self.dpid, dstaddr)] = []
        bucket = self.lost_buffers[(self.dpid, dstaddr)]
        entry = (time() + MAX_BUFFER_TIME, self.event.ofp.buffer_id,
                 self.inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP:
            del bucket[0]
        self.outstanding_arps = {
            k: v for k, v in self.outstanding_arps.iteritems() if v > time()
        }
        if (self.dpid, dstaddr) in self.outstanding_arps:
            return
        self.outstanding_arps[(self.dpid, dstaddr)] = time() + 4
        self.handle_ip_reply(dstaddr)

    def handle_ip_reply(self, dstaddr):
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = self.packet.src
        r.protosrc = self.packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=self.packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (
            self.dpid, self.inport, str(r.protodst), str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = self.inport
        self.event.connection.send(msg)

    def send(self, dstaddr):
        prt = self.arp_table[self.dpid][dstaddr].port
        mac = self.arp_table[self.dpid][dstaddr].mac
        if prt == self.inport:
            msg = "%i %i not sending packet for %s back out of the input port"
            data = (self.dpid, self.inport, str(dstaddr))
            log.warning(msg % data)
            return
        msg = "%i %i installing flow for %s => %s out port %i"
        data = (self.dpid, self.inport, self.packet.next.srcip, dstaddr, prt)
        log.debug(msg % data)
        actions = [
            of.ofp_action_dl_addr.set_dst(mac),
            of.ofp_action_output(port=prt)
        ]
        match = of.ofp_match.from_packet(self.packet, self.inport)
        match.dl_src = None
        msg = of.ofp_flow_mod(
            command=of.OFPFC_ADD,
            idle_timeout=FLOW_IDLE_TIMEOUT,
            hard_timeout=of.OFP_FLOW_PERMANENT,
            buffer_id=self.event.ofp.buffer_id,
            actions=actions,
            match=of.ofp_match.from_packet(self.packet, self.inport))
        self.event.connection.send(msg.pack())

    def handle_arp_packet(self):
        if not isinstance(self.packet.next, arp):
            return
        a = self.packet.next
        self.log_flood_message(a)

        if a.prototype != arp.PROTO_TYPE_IP:
            self.flood_2(a)
            return
        if a.hwtype != arp.HW_TYPE_ETHERNET:
            return
        if a.protosrc == 0:
            return

        self.learn_or_update_port_mac_info(a.protosrc)

        self._send_lost_buffers(
            self.dpid, a.protosrc, self.packet.src, self.inport)

        if a.opcode != arp.REQUEST:
            return
        if a.protodst not in self.arp_table[self.dpid]:
            return
        if self.arp_table[self.dpid][a.protodst].is_expired():
            return
        self.handle_arp_reply(a)

    def handle_arp_reply(self, a):
        r = arp()
        r.hwtype = a.hwtype
        r.prototype = a.prototype
        r.hwlen = a.hwlen
        r.protolen = a.protolen
        r.opcode = arp.REPLY
        r.hwdst = a.hwsrc
        r.protodst = a.protosrc
        r.protosrc = a.protodst
        r.hwsrc = self.arp_table[self.dpid][a.protodst].mac
        mac = self.dpid_to_mac(self.dpid)
        e = ethernet(type=self.packet.type, src=mac, dst=a.hwsrc)
        e.set_payload(r)
        log.debug("%i %i answering ARP for %s" %
                  (self.dpid, self.inport, str(r.protosrc)))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = self.inport
        self.event.connection.send(msg)
        return

    def learn_or_update_port_mac_info(self, value):
        entry = self.arp_table[self.dpid]
        if value in entry:
            if entry[value] != (self.inport, self.packet.src):
                log.info("%i %i RE-learned %s", self.dpid, self.inport, value)
        else:
            log.debug("%i %i learned %s", self.dpid, self.inport, str(value))
        self.arp_table[self.dpid][value] = Entry(self.inport, self.packet.src)

    def log_flood_message(self, a):
        dicc = {arp.REQUEST: "request", arp.REPLY: "reply"}
        b = dicc.get(a.opcode, 'op:%i' % (a.opcode,))
        data = (self.dpid, self.inport, b, str(a.protosrc), str(a.protodst))
        log.debug("%i %i flooding ARP %s %s => %s" % data)

    def flood_2(self, a):
        self.log_flood_message(a)
        action = of.ofp_action_output(port=of.OFPP_FLOOD)
        msg = of.ofp_packet_out(in_port=self.inport, action=action)
        if self.event.ofp.buffer_id is of.NO_BUFFER:
            # Try sending the (probably incomplete) raw data
            msg.data = self.event.data
        else:
            msg.buffer_id = self.event.ofp.buffer_id
            self.event.connection.send(msg.pack())

    def _send_lost_buffers(self, dpid, ipaddr, macaddr, port):
        if (dpid, ipaddr) in self.lost_buffers:
            bucket = self.lost_buffers[(dpid, ipaddr)]
            del self.lost_buffers[(dpid, ipaddr)]
            log.debug("Sending %i buffered packets to %s from %s"
                      % (len(bucket), ipaddr, dpidToStr(dpid)))
            for _, buffer_id, in_port in bucket:
                po = of.ofp_packet_out(buffer_id=buffer_id, in_port=in_port)
                po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
                po.actions.append(of.ofp_action_output(port=port))
                core.openflow.sendToDPID(dpid, po)


def launch(fakeways="", arp_for_unknowns=None):
    fakeways = fakeways.replace(",", " ").split()
    fakeways = [IPAddr(x) for x in fakeways]
    if arp_for_unknowns is None:
        arp_for_unknowns = len(fakeways) > 0
    else:
        arp_for_unknowns = str_to_bool(arp_for_unknowns)
    core.registerNew(Controller, fakeways, arp_for_unknowns)
