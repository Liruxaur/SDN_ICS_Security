from pox.core import core
from pox.openflow.discovery import Discovery
import pox.openflow.libopenflow_01 as of

import networkx as nx
import matplotlib.pyplot as plt
import random
from pox.lib.addresses import EthAddr

log = core.getLogger()
mst_list=[]
mac_to_ip_mapping = {}

discovery_enabled = True
link_to_ports = {}
switch_to_host_ovsport={
"192.168.2.232":"1",
"192.168.2.199":"1",
"192.168.2.198":"1",
"192.168.2.158":"1"

}
host_to_switch_mapping={
   "192.168.2.232": "192.168.1.145",
   "192.168.2.199": "192.168.1.103",
   "192.168.2.198": "192.168.1.144",
   "192.168.2.158": "192.168.1.151"
}
not_connected_switches={
   "192.168.2.232": "192.168.1.151",
   "192.168.2.199": "192.168.1.144",
   "192.168.2.198": "192.168.1.103",
   "192.168.2.158": "192.168.1.145"
}
class KruskalController(object):
    switch_ip_mapping = {}
    links = []
    connected_switches=[]
    Compromised_link=()
    _ports=[]
    def __init__(self):
        core.openflow.addListeners(self)
        self.G = nx.Graph()
        #self.compromised_links = [
         #   ("192.168.2.232", "192.168.2.199")
        #]
        self.root_node = "192.168.2.232"
        self.mst_calculated = False
        self.mst_list = [] 
        
    def _handle_LinkEvent(self, event):
        global discovery_enabled
        global mst
        global down_link
        if not discovery_enabled : #or len(links) == 8:
            return

        link = event.link
        src_dpid = str(link.dpid1)
        src_port=str(link.port1)
        src_ip = KruskalController.switch_ip_mapping.get(src_dpid)
        dst_dpid = str(link.dpid2)
        dst_ip = KruskalController.switch_ip_mapping.get(dst_dpid)
        dst_port=str(link.port2)
        
        KruskalController._ports.append((src_ip, src_port))
        link_key = "Switch {} -> Switch {}".format(src_ip, dst_ip)
        link_to_ports[link_key] = src_port


        if src_ip is not None and dst_ip is not None:
            weight = random.randint(70, 90)
            for src, dst, sp, dp, w in KruskalController.links:
                if src == src_ip and dst == dst_ip:
                    log.info("already_in")
                    break
            else:
                KruskalController.links.append((src_ip, dst_ip, src_port, dst_port, weight))
                
            for src, dst, sp, dp,  w in  KruskalController.links:
                log.info("Link: {} - {}, srcport {}, dstport{}, Weight: {}".format(src, dst, sp, dp, w))
                
            

            if len(KruskalController.links) == 8 and not self.mst_calculated:
                try:
                    
                    down_link = random.choice(KruskalController.links)
                    src_ip, dst_ip, sp, dp, w = down_link 
                    KruskalController.Compromised_link=(src_ip, dst_ip)
                    log.debug("Source IP: %s", src_ip)
                    log.debug("Destination IP: %s", dst_ip)
                    log.debug("Source port: %s", sp)
                    log.debug("Destination port: %s", dp)
                    log.debug("Weight: %s", w)
                    discovery_enabled = False
                    log.info("OpenFlow discovery stopped")
                    self._calculate_minimum_spanning_tree()
                    for connection in self.connected_switches:
                      log.debug(connection)
                      self.install_flow_on_switch(connection)
                except KeyboardInterrupt:
                    self._cleanup()
                    sys.exit()

    def _handle_ConnectionUp(self, event):
        switch = event.connection
        switch_ip = switch.sock.getpeername()[0]
        switch_dpid = str(switch.dpid)
        KruskalController.switch_ip_mapping[switch_dpid] = switch_ip
        self.connected_switches.append(event.connection)
        log.info("Connected switch with DPID {} and IP address {}".format(switch_dpid, switch_ip))
        
    def install_flow_on_switch (self, connection):
      mst_list= self.get_mst_list()
      compromised_link=KruskalController.Compromised_link
      log.debug(compromised_link)
      links=KruskalController.links    
      
      f_links =  [tup for tup in links if not tup[:2] in [compromised_link, compromised_link[::-1]] ]
      switch_ip=connection.sock.getpeername()[0]
      for src, dst, sp, dp, w in links:
       #log.debug("src: {}, dst: {}, sp: {}, dp: {}, w: {}".format(src, dst, sp, dp, w))
       
       if switch_ip==src and ((switch_ip!=compromised_link[0] and switch_ip != compromised_link[1]) or ( switch_ip==compromised_link[0] and dst!=compromised_link[1] ) or ( switch_ip==compromised_link[1] and dst!=compromised_link[0] ) ):
         log.debug("normal")
         port=int(sp)
         msg = of.ofp_flow_mod()
         msg.match.dl_type = 0x800  
         msg.match.nw_proto = 6
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
         msg.match.nw_dst = host_to_switch_mapping[str(dst)]
         msg.actions.append(of.ofp_action_output(port = port))
         msg.hard_timeout = 0 
         msg.idle_timeout = 0
         connection.send(msg)
         
         
         msgo = of.ofp_flow_mod()
         msgo.match.dl_type = 0x800  
         msgo.match.nw_proto = 6
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
         msgo.match.nw_dst = not_connected_switches[str(src)]
         msgo.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
         msgo.hard_timeout = 0 
         msgo.idle_timeout = 0
         connection.send(msgo)
       
       elif switch_ip==src and (switch_ip==compromised_link[0] and dst==compromised_link[1]):
         
        single_element = None  
        for (src_ip, src_port) in KruskalController._ports:
            if src_ip == src and src_port != sp:
              single_element = int(src_port)
              break
        port= single_element
        
         
        msg2 = of.ofp_flow_mod()
        msg2.match.dl_type = 0x800  
        msg2.match.nw_proto = 6
         
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
        msg2.match.nw_dst = host_to_switch_mapping[str(dst)]
         
        msg2.actions.append(of.ofp_action_output(port = port))
        msg2.hard_timeout = 0 
        msg2.idle_timeout = 0
        connection.send(msg2)
        
        log.debug(src)
        log.debug(port)
        msgo = of.ofp_flow_mod()
        msgo.match.dl_type = 0x800  
        msgo.match.nw_proto = 6
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
        msgo.match.nw_dst = not_connected_switches[str(src)]
        msgo.actions.append(of.ofp_action_output(port  = of.OFPP_FLOOD))
        msgo.hard_timeout = 0 
        msgo.idle_timeout = 0
        connection.send(msgo)
       
       elif switch_ip==src and( switch_ip==compromised_link[1] and dst==compromised_link[0]):
        single_elemen = None  
        for (src_ip, src_port) in KruskalController._ports:
            if src_ip == src and src_port != sp:
              single_elemen = int(src_port)
              break
        port= single_elemen
         
        log.debug(src)
         
        log.debug(port)
        
         
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
        msg2 = of.ofp_flow_mod()
        msg2.match.dl_type = 0x800  
        msg2.match.nw_proto = 6
        msg2.match.nw_dst = host_to_switch_mapping[str(dst)]
         
        msg2.actions.append(of.ofp_action_output(port = port))
        msg2.hard_timeout = 0 
         
        msg2.idle_timeout = 0
        connection.send(msg2)
        
        msgo = of.ofp_flow_mod()
        msgo.match.dl_type = 0x800  
        msgo.match.nw_proto = 6
         #msg.match.nw_src = host_to_switch_mapping[str(src)]
        msgo.match.nw_dst = not_connected_switches[str(src)]
        msgo.actions.append(of.ofp_action_output(port =  of.OFPP_FLOOD))
        msgo.hard_timeout = 0 
        msgo.idle_timeout = 0
        connection.send(msgo)
         
       
       
       
       else :
        
         continue
       
       
      msg2 = of.ofp_flow_mod()
      msg2.match.dl_type = 0x800  
      msg2.match.nw_proto = 6
      porti=int(switch_to_host_ovsport[str(switch_ip)])
      msg2.match.nw_dst = host_to_switch_mapping[str(switch_ip)]
      msg2.actions.append(of.ofp_action_output(port = porti))
      msg2.hard_timeout = 0 
      msg2.idle_timeout = 0
      connection.send(msg2) 
      
      msgarp = of.ofp_flow_mod()
      msgarp.match.dl_type = 0x0806  # ARP packet
      msgarp.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      connection.send(msgarp)
      
      
      
      
      
     
        
      
      
    
    def _handle_PacketIn(self, event):
      packet = event.parsed        
        
      def flood (message = None):
        """ Floods the packet """
        msg = of.ofp_packet_out()
        if time.time() - self.connection.connect_time >= _flood_delay:
        
         if self.hold_down_expired is False:
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

         if message is not None: log.debug(message)
        
         msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        else:
          pass
        
        msg.data = event.ofp
        msg.in_port = event.port
        self.connection.send(msg)
      
        if packet.type == packet.LLDP_TYPE:
            lldp = packet.find("lldp")
            if lldp is not None:
                src_mac = EthAddr(packet.src)
                src_ip = KruskalController.switch_ip_mapping.get(str(event.dpid))
                mac_to_ip_mapping[src_mac] = src_ip
                for mac, ip in mac_to_ip_mapping.items():
                    log.info("MAC: {} - IP: {}".format(mac, ip))
        elif packet.type == packet.ARP_TYPE:
            flood()
            log.debug("flooding arp packet")
        elif packet.dst.is_multicast:
            flood()
                   
    def _calculate_minimum_spanning_tree(self):
        global links
        global down_link
        updated_mst = []
        for link in  KruskalController.links:
            #if link not in self.compromised_links:
                src, dst, sp, dp, weight = link
                edge_attributes = {
                        'sp': sp,
                        'weight': int(weight)}
                self.G.add_edge(src, dst,  weight=int(weight))
                
        src_ip, dst_ip, _, _, _ = down_link 
        self.G.remove_edge(src_ip, dst_ip)
        mst = self._kruskal_minimum_spanning_tree()

        root_mst = nx.dfs_tree(mst, source=self.root_node)

        sorted_mst = sorted(root_mst.edges(), key=lambda x: x[1])
        #sorted_mst.reverse()
 
        log.info("Minimum Spanning Tree with Root Node: %s", self.root_node)
        for src, dst in sorted_mst:
         for srrc, dstt, sp, dp, w in  KruskalController.links:
          if src == srrc and dst == dstt:
            updated_edge = (src, dst, sp, dp)  
            updated_mst.append(updated_edge)  
            log.info("Edge: %s -> %s, sp: %s, dp: %s", src, dst, sp, dp)  
        self.mst_list = updated_mst  
        
        self.mst_calculated = True
        return updated_mst
        pos = nx.spring_layout(self.G)
        plt.figure(figsize=(8, 6))
        nx.draw_networkx(self.G, pos, with_labels=True, node_size=1000, node_color="lightblue")
        nx.draw_networkx_edges(root_mst, pos, edge_color="red", width=2)
        plt.title("Minimum Spanning Tree with Root Node: " + self.root_node)
        plt.axis("off")
        plt.show()
        
        #self.mst = sorted_mst 
    def _cleanup(self):
        # Perform any necessary cleanup tasks here
        log.info("Controller stopped. Cleanup tasks completed.")

    def _kruskal_minimum_spanning_tree(self):
        parent = {}
        rank = {}

        def find(node):
            if parent[node] != node:
                parent[node] = find(parent[node])
            return parent[node]

        def union(node1, node2):
            root1 = find(node1)
            root2 = find(node2)
            if root1 != root2:
                if rank[root1] < rank[root2]:
                    parent[root1] = root2
                elif rank[root1] > rank[root2]:
                    parent[root2] = root1
                else:
                    parent[root2] = root1
                    rank[root1] += 1

        edges = []
        for u, v, weight in self.G.edges(data=True):
            edges.append((u, v, weight["weight"]))

        edges.sort(key=lambda x: x[2])

        mst = nx.Graph()

        for node in self.G.nodes():
            parent[node] = node
            rank[node] = 0

        for edge in edges:
            u, v, weight = edge
            if find(u) != find(v):
                union(u, v)
                mst.add_edge(u, v, weight=weight)

        return mst
  
    def get_mst_list(self):
        return self.mst_list
        
    def get_nw_links():
        global links
        return links
            
def launch():
    
    core.registerNew(KruskalController)
    core.openflow.addListenerByName("ConnectionUp", KruskalController()._handle_ConnectionUp)
    core.registerNew(Discovery)
    core.openflow_discovery.addListenerByName("LinkEvent", KruskalController()._handle_LinkEvent)
    core.openflow.addListenerByName("PacketIn", KruskalController()._handle_PacketIn)
    

if __name__ == "__main__":
    launch()
    
    






