from mininet.topo import Topo


class Topology(Topo):
    def __init__(self, number_of_levels):
        """
        :type number_of_levels: int
        """
        Topo.__init__(self)
        number_of_clients = 3
        devices = {}
        h_offset = 1
        for i in range(0, number_of_levels):
            number_of_switches = 2 ** i
            self.add_links_and_switches(number_of_switches, devices)
            if i == 0:
                self.add_hosts(number_of_clients, devices, True, h_offset)
                h_offset += number_of_clients
            if i == number_of_levels - 1:
                self.add_hosts(number_of_switches, devices, False, h_offset)

    def add_hosts(self, number_of_host, devices, is_root, offset):
        for i in range(0, number_of_host):
            host_name = 'h%s' % (i + offset)
            devices[host_name] = self.addHost(host_name)

    def add_links_and_switches(self, number_of_switches, devices):
        for i in range(0, number_of_switches):
            switch_name = 's%s' % (i + number_of_switches)
            devices[switch_name] = self.addSwitch(switch_name)
            some_device = devices[switch_name]
            for j in range(0, number_of_switches/2):
                another_device = devices['s%s' % (j + number_of_switches/2)]
                self.addLink(some_device, another_device)

    def add_host_links(self, host_number, devices, is_root):
        host_name = 'h%s' % host_number
        if is_root:
            self.addLink(devices[host_name], devices['s1'])
            return
        self.addLink(devices[host_name], devices['s%s' % host_number])


topos = {
    'mytopo': (lambda: Topology(3))
}
