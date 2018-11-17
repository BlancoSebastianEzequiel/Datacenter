from mininet.topo import Topo


class Topology(Topo):
    def __init__(self, number_of_levels=3, number_of_clients=3):
        """
        :type number_of_levels: int
        """
        Topo.__init__(self)
        self.level_links = {}
        self.sw_num = 1
        self.h_num = 1
        self.number_of_levels = number_of_levels
        self.number_of_clients = number_of_clients
        self.add_clients()
        self.add_switches_and_links()
        self.add_content_providers()

    def add_clients(self):
        self.level_links[0] = []
        for i in range(0, self.number_of_clients):
            self.level_links[0].append(self.addHost('h%s' % self.h_num))
            self.h_num += 1

    def add_switches_and_links(self):
        for level in range(0, self.number_of_levels):
            next_level = level + 1
            number_of_switches_in_level = 2 ** level
            self.level_links[next_level] = []
            for i in range(0, number_of_switches_in_level):
                sw = self.addSwitch('s%s' % self.sw_num)
                self.level_links[next_level].append(sw)
                self.sw_num += 1
                for device in self.level_links[level]:
                    self.addLink(sw, device)

    def add_content_providers(self):
        for sw in self.level_links[self.number_of_levels]:
            self.addLink(sw, self.addHost('h%s' % self.h_num))
            self.h_num += 1


topos = {
    'mytopo': (lambda: Topology())
}
