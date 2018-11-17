import pox.log.color
import pox.log
import pox.log.level
import logging
from pox.core import core
import pox.openflow.discovery
import pox.openflow.spanning_tree
import pox.host_tracker
from controller import Controller


def launch ():
    pox.log.color.launch()
    pox.log.launch(
        format=
        "[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")
    pox.log.level.launch(packet=logging.WARN, host_tracker=logging.INFO)
    pox.openflow.discovery.launch()
    core.registerNew(Controller)
    pox.openflow.spanning_tree.launch()
    pox.host_tracker.launch()
