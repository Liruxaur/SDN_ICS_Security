# type: ignore# type: ignore
from pox.core import core
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
import random

log = core.getLogger()


class TopologyDiscovery(object):
    links = []

    def __init__(self):
        self.mst_calculated = False

    def _handle_LinkEvent(self, event):
        link = event.link
        if link is not None:
            src_dpid = link.dpid1
            dst_dpid = link.dpid2
            src_port = link.port1
            dst_port = link.port2

            if src_dpid is not None and dst_dpid is not None:
                weight = random.randint(70, 90)
                for src, dst, sp, dp, w in TopologyDiscovery.links:
                    if src == src_dpid and dst == dst_dpid:
                        log.info("Link already exists between {} and {}".format(src_dpid, dst_dpid))
                        break
                else:
                    TopologyDiscovery.links.append((src_dpid, dst_dpid, src_port, dst_port, weight))
                    log.info(len(TopologyDiscovery.links))
                    log.info("Link added: {} - {} (srcport {}, dstport {}, Weight: {})".format(src_dpid, dst_dpid, src_port, dst_port, weight))

                if len(TopologyDiscovery.links) == 200 and not self.mst_calculated:
                    log.info("OpenFlow discovery stopped")
                    self.mst_calculated = True

    def _handle_ConnectionUp(self, event):
        switch = event.connection
        switch_dpid = str(switch.dpid)
        log.info("Connected switch with DPID {}".format(switch_dpid))

def launch():
    core.registerNew(TopologyDiscovery)
    core.openflow.addListenerByName("ConnectionUp", TopologyDiscovery()._handle_ConnectionUp)
    core.registerNew(Discovery)
    core.openflow_discovery.addListenerByName("LinkEvent", TopologyDiscovery()._handle_LinkEvent)
