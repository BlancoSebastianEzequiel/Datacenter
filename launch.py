def launch ():
    import pox.log.color
    import pox.log
    import pox.log.level
    import logging
    from pox.core import core
    import pox.openflow.discovery
    import pox.openflow.spanning_tree
    import pox.host_tracker
    import controller

    pox.log.color.launch()
    pox.log.launch(
        format=
        "[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")
    pox.openflow.discovery.launch()
    pox.log.level.launch(packet=logging.WARN, host_tracker=logging.INFO)
    core.getLogger("openflow.spanning_tree").setLevel("INFO")
    name = controller.MyController.__name__
    core.getLogger().debug("Using forwarding: %s", name)
    controller.launch()
    pox.openflow.spanning_tree.launch()
    pox.host_tracker.launch()
