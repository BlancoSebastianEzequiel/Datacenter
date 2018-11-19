import time
import pox.openflow.libopenflow_01 as of
from data_definitions import ARP_TIMEOUT
from pox.lib.addresses import IPAddr, EthAddr


class Entry (object):
    def __init__(self, port, mac):
        self.timeout = time.time() + ARP_TIMEOUT
        self.port = port
        self.mac = mac

    def __eq__(self, other):
        if type(other) == tuple:
            return (self.port, self.mac) == other
        else:
            return (self.port, self.mac) == (other.port, other.mac)

    def __ne__(self, other):
        return not self.__eq__(other)

    def isExpired(self):
        if self.port == of.OFPP_NONE: return False
        return time.time() > self.timeout

    def dpid_to_mac(dpid):
        return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))
