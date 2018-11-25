def launch():
    import pox.log.color
    pox.log.color.launch()
    import pox.log
    pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " +
                          "@@@bold%(message)s@@@normal")
    from pox.core import core
    import pox.openflow.discovery
    pox.openflow.discovery.launch()
    core.getLogger("openflow.spanning_tree").setLevel("INFO")
    import pox.openflow.spanning_tree
    pox.openflow.spanning_tree.launch()
    from pox.host_tracker.host_tracker import host_tracker
    host_tracker_instance = core.registerNew(host_tracker)
    from controller import Controller
    core.registerNew(Controller, host_tracker_instance)
    from firewall import Firewall
    core.registerNew(Firewall)
