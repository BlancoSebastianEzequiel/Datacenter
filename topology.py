from mininet.topo import Topo


class Topology(Topo):
    def __init__(self):
        # "create custom topo."
        # Initialize topology
        Topo.__init__(self)
        # Add host and swithes
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h4")
        h4 = self.addHost("h5")
        h5 = self.addHost("h6")
        h6 = self.addHost("h7")
        h7 = self.addHost("h8")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")
        s7 = self.addSwitch("s7")
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(s1, s2)
        self.addLink(s1, s3)

        self.addLink(h4, s4)
        self.addLink(h5, s5)
        self.addLink(h6, s6)

        self.addLink(s2, s4)
        self.addLink(s2, s5)
        self.addLink(s2, s6)
        self.addLink(s2, s7)

        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)
        self.addLink(s6, s7)
