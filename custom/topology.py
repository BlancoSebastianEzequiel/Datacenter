from mininet.topo import Topo
from math import log


class Topology(Topo):
    def __init__(self, number_of_levels):
        """
        :type number_of_levels: int
        """
        Topo.__init__(self)
        number_of_clients = 3
        devices = {}
        for i in range(0, number_of_levels-1):
            number_of_switches = 2 ** i
            self.add_links_between_switches(number_of_switches, devices)
            if i == 0:
                self.add_hosts(self, number_of_clients, devices, True)
            if i == number_of_levels-1:
                self.add_hosts(number_of_switches, devices, False)
            self.add_links_between_switches(number_of_switches, devices)

    def add_hosts(self, number_of_host, devices, is_root):
        for i in range(0, number_of_host-1):
            host_name = 'h%s' % (i + 1)
            devices[host_name] = self.addHost(host_name)
            self.add_host_links(i + 1, devices, is_root)

    def add_links_between_switches(self, number_of_switches, devices):
        for i in range(0, number_of_switches - 1):
            switch_name = 's%s' % (i + 1)
            devices[switch_name] = self.addSwitch(switch_name)
            some_device = devices[switch_name]
            for j in range(1, number_of_switches - 1):
                another_device = devices['s%s' % (j + 1)]
                self.addLink(some_device, another_device)

    def add_host_links(self, host_number, devices, is_root):
        host_name = 'h%s' % host_number
        if is_root:
            self.addLink(devices[host_name], devices["s1"])
            return
        switch_name = 's%s' % host_number
        self.addLink(devices[host_name], devices[switch_name])
