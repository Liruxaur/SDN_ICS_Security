
# type: ignore
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time
from pox.openflow.discovery import Discovery
from mst_modified import KruskalController
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.tcp import tcp
from pox.openflow.libopenflow_01 import *
from scapy.all import *

log = core.getLogger()

_flood_delay = 0

mst_controller=KruskalController()
switch_to_host_ovsport={
"192.168.1.145":"1",
"192.168.1.103":"1",
"192.168.1.144":"1",
"192.168.1.151":"1"

}
host_to_switch_mapping={
    "192.168.1.145": "192.168.2.232",
    "192.168.1.103": "192.168.2.199",
    "192.168.1.144": "192.168.2.198",
    "192.168.1.151": "192.168.2.158"
}
#list_host=[  "192.168.1.145", "192.168.1.103", "192.168.1.144", "192.168.1.151"]
#compromised_link=("192.168.1.145", "192.168.1.103")
visited_link= set()
visited_linkback= set()
class LearningSwitch (object):
  switch_ip_mapping = {}
  def __init__ (self, connection, transparent):
    
    self.connection = connection
    self.transparent = transparent

    self.macToPort = {}
    self.macToPort = {}
    #self.m_to_port[event.connection.dpid][packet.src] =event.port
    connection.addListeners(self)
    
    self.hold_down_expired = _flood_delay == 0
    
    self.host_locations = {}
   
  
  
  
  def _handle_PacketIn (self, event):
  
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

    def drop (duration = None):
    
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)
        
    def clear_flow_table(connection):
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE) 
        msg.match = of.ofp_match()  
        connection.send(msg) 
    
    self.macToPort[packet.src] = event.port # 1
    
    if  packet.type == packet.ARP_TYPE:
       #log.debug ("arp packet")
       flood()
    
    elif  isinstance(packet.next, ipv4) and  isinstance(packet.next.next, tcp) and (packet.next.next.dstport == 12800 or packet.next.next.dstport != 12800 ) :
     tcp_packet= packet.next.next
     if tcp_packet.flags & 0x18 and packet.next.srcip == "192.168.0.145" :
      mst_list= mst_controller.get_mst_list()
    
      switch_dpid = str(event.connection.dpid)
      switch_ip=mst_controller.switch_ip_mapping[switch_dpid]
      src_ip=packet.find('ipv4').srcip
      dst_ip=packet.find('ipv4').dstip
      log.debug("TCP packet")
      #compromised_link=mst_controller.Compromised_link
      compromised_link=("192.168.2.232","192.168.2.199")
     
      src_switch=host_to_switch_mapping[str(src_ip)]
      dst_switch=host_to_switch_mapping[str(dst_ip)]
     
      if ((src_switch, dst_switch ) == compromised_link) :
      
          log.debug("Packet on compromised link")
       
          log.debug("Using the minimum spanning tree")
          
          for src, dst, sp, dp in mst_list:
           
            #log.info(" %s -> %s,  %s ", src, dst, prt)
            if (switch_ip == src and dst_switch!=switch_ip) and ( ((src, dst)) not in visited_link) :
               
               log.debug("Forwarding to next switch : %s", dst)
               port=int(sp)
               visited_link.add((src, dst))
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
               
               log.debug(visited_link)
               break
           
            elif switch_ip==dst_switch: 
               
               log.debug("Forwarding to the host : %s", switch_ip )
               log.debug("---------------------------------------------------------------")              
               port=int(switch_to_host_ovsport[str(dst_ip)])
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
               break
     
            elif ( switch_ip==dst and dst_switch!=switch_ip ) and ( ((src, dst)) not in visited_link):
               
               log.debug("Forwarding back to next switch : %s", src)
               
               visited_link.add((src, dst))
               port=int(dp)
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
      
               log.debug(visited_link)         
               break          
              
      elif  (dst_switch, src_switch) == compromised_link : 
          log.debug("Packet on compromised link ")
       
          log.debug("Using the minimum spanning tree")
          
          for src, dst, sp, dp in mst_list:
           
            #log.info(" %s -> %s,  %s ", src, dst, prt)
            if (switch_ip == src and dst_switch!=switch_ip) and ( ((src, dst)) not in visited_linkback) :
               
               log.debug("Forwarding to next switch : %s", dst)
               
               visited_linkback.add((src, dst))
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
               
               log.debug(visited_linkback)
               break
           
            elif switch_ip==dst_switch: 
               
               log.debug("Forwarding to the host: %s", switch_ip)
               log.debug("---------------------------------------------------------------")              
               port=int(switch_to_host_ovsport[str(dst_ip)])
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
               break
     
            elif ( switch_ip==dst and dst_switch!=switch_ip ) and ( ((src, dst)) not in visited_linkback):
               
               log.debug("Forwarding  to next switch: %s", src)
               
               visited_linkback.add((src, dst))
               port=int(dp)
               msg = of.ofp_flow_mod()
               msg.match = of.ofp_match.from_packet(packet, event.port)
               msg.actions.append(of.ofp_action_output(port = port))
               msg.hard_timeout = 0 
               msg.idle_timeout = 0
               msg.data = event.ofp 
               self.connection.send(msg)
      
               log.debug(visited_linkback)         
               break          
              
               
            
      elif ((packet.next.srcip, packet.next.dstip ) != compromised_link) or ((packet.next.dstip, packet.next.srcip ) != compromised_link) :
          log.debug("Normal packet")
          if packet.dst.is_multicast:
            flood()
          else:
              
              
              links=mst_controller.links
              dst_switch=host_to_switch_mapping[str(dst_ip)]
              log.debug("Forwarding... ")
              link_part = [(first, second) for first, second, _, _, _ in links]
              if ((switch_ip, dst_switch) in link_part) or (switch_ip==dst_switch):
               for src, dst, sp, dp, w in links:                
                   if switch_ip==src and dst_switch==dst:  
                  
                     log.debug("Link found  ")
                     log.debug("Forwarding  to next switch: %s", dst)
                     port=int(sp)
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 0 
                     msg.idle_timeout = 0 
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break
                   
                   elif switch_ip==dst_switch:
                     
                     log.debug("Forwarding to the host : %s", switch_ip)
                     log.debug("---------------------------------------------------------------")
                     port=int(switch_to_host_ovsport[str(dst_ip)])
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 0 
                     msg.idle_timeout = 0
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break
              else:  
                for src, dst, sp, dp, w in links:                
                   if switch_ip==src and dst_switch!=dst:
                    
                     log.debug("Link not found ")
                     log.debug("Forwarding to next switch : %s ", dst)                 
                     port=int(sp)
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 0 
                     msg.idle_timeout = 0
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break
               
     else: 
              mst_list= mst_controller.get_mst_list()
    
              switch_dpid = str(event.connection.dpid)
              switch_ip=mst_controller.switch_ip_mapping[switch_dpid]
              src_ip=packet.find('ipv4').srcip
              dst_ip=packet.find('ipv4').dstip
              log.debug("TCP connexion packet")
              compromised_link=mst_controller.Compromised_link
     
              src_switch=host_to_switch_mapping[str(src_ip)]
              dst_switch=host_to_switch_mapping[str(dst_ip)]
              links=mst_controller.links
              dst_switch=host_to_switch_mapping[str(dst_ip)]
              log.debug("Forwarding...")
              link_part = [(first, second) for first, second, _, _, _ in links]
              if ((switch_ip, dst_switch) in link_part) or (switch_ip==dst_switch):
               for src, dst, sp, dp, w in links:                
                   if switch_ip==src and dst_switch==dst:  
                     log.debug("Forwarding to next switch : %s ", dst)  
                     port=int(sp)
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 5
                     msg.idle_timeout = 10
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break
                   
                   elif switch_ip==dst_switch:
                     
                     log.debug("Forwarding to the host : %s", switch_ip)
                     log.debug("--------------------------------------------------------------")
                     port=int(switch_to_host_ovsport[str(dst_ip)])
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 5
                     msg.idle_timeout = 10
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break
              else:  
                for src, dst, sp, dp, w in links:                
                   if switch_ip==src and dst_switch!=dst:
                     
                     log.debug("Forwarding to next switch : %s ", dst)               
                     port=int(sp)
                     msg = of.ofp_flow_mod()
                     msg.match = of.ofp_match.from_packet(packet, event.port)
                     msg.actions.append(of.ofp_action_output(port = port))
                     msg.hard_timeout = 5
                     msg.idle_timeout = 10
                     msg.data = event.ofp 
                     self.connection.send(msg)
                     break             
                  
              #log.debug("enter")     
                   
                   
    else: 
     if packet.dst.is_multicast:
            flood()
     else: 
       if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
       else:
        port = self.macToPort[packet.dst]
        
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)
    


class l2_learning (object):
 
  def __init__ (self, transparent, ignore = None):
  
    core.openflow.addListeners(self)
    self.transparent = transparent
    self.ignore = set(ignore) if ignore else ()
    self.connected_switches = set()
    
  def clear_flow_table(self, connection):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)  
    msg.match = of.ofp_match()  
    connection.send(msg) 
                
  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignoring connection %s" % (event.connection,))
      return
    log.debug("Connection %s" % (event.connection,))
    self.clear_flow_table(event.connection)
    LearningSwitch(event.connection, self.transparent)
    
    
   
        
def launch (transparent=False, hold_down=_flood_delay, ignore = None):
  
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)
    
  core.registerNew(l2_learning, str_to_bool(transparent), ignore)
  core.registerNew(Discovery)
  core.openflow_discovery.addListenerByName("LinkEvent", mst_controller._handle_LinkEvent)
  
  

  
