import random
from pox.core import core

log = core.getLogger()


class ECMPTable(object):

    def __init__(self):
        self.table = {}

    def print_s(self, data, port):
        (ports, dpid, dst_dpid, protocol, src_addr, dst_addr) = data
        if dpid != 1:
            return
        log.info("SRC SWITCH %s, DST SWITCH %s, PROTOCOL %s, src_addr %s, dst_addr %s, port %s" % (dpid, dst_dpid, protocol, src_addr, dst_addr, port))

    def get_port_applying_ecmp(self, data):
        (ports, dpid, dst_dpid, protocol, src_addr, dst_addr) = data
        key = (dst_dpid, protocol, src_addr, dst_addr)
        if dpid not in self.table:
            self.table[dpid] = {}
            random.shuffle(ports)
            self.table[dpid][key] = ports[0]
            self.print_s(data, ports[0])
            return self.table[dpid][key]
        elif key not in self.table[dpid]:
            is_used = False
            for a_port in ports:
                for a_key in self.table[dpid]:
                    if a_port == self.table[dpid][a_key]:
                        is_used = True
                if not is_used:
                    self.table[dpid][key] = a_port
                    self.print_s(data, a_port)
                    return a_port
            random.shuffle(ports)
            self.table[dpid][key] = ports[0]
            self.print_s(data, ports[0])
            return ports[0]
        self.print_s(data, self.table[dpid][key])
        return self.table[dpid][key]

    def save_port(self, data):
        (dpid, dst_dpid, protocol, src_addr, dst_addr, port) = data
        key = (dst_dpid, protocol, src_addr, dst_addr)
        self.table[dpid][key] = port
