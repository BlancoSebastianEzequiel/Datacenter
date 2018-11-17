def launch ():
    import pox.log.color
    pox.log.color.launch()
    import pox.log
    pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                          "@@@bold%(message)s@@@normal")
    from pox.core import core
    import pox.openflow.discovery
    pox.openflow.discovery.launch()

    import controller as c
    core.getLogger("openflow.spanning_tree").setLevel("INFO")
    core.getLogger().debug("Using forwarding: %s", c.__name__)
    c.launch()

    import pox.openflow.spanning_tree
    pox.openflow.spanning_tree.launch()

