#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin


class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ip_mac_port = {1: ('255.255.255.0','00:00:00:00:01:01','192.168.1.1'),
		       2: ('255.255.255.0','00:00:00:00:01:02','192.168.2.1'),
		       3: ('255.255.255.0','00:00:00:00:01:03','192.168.3.1'),
		       4: ('255.255.255.0','00:00:00:00:01:04','192.168.4.1')}
    
    #  Inserta una entrada a la tabla de flujo.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
	if buffer_id:
		mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
			priority=priority, match=match,
			instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
	else:
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
			match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
	print(mod)
	datapath.send_msg(mod)

    def send_packet(self, datapath, port, pkt):
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	pkt.serialize()
	data = pkt.data
	actions = [parser.OFPActionOutput(port=port)]
	out = parser.OFPPacketOut(datapath=datapath,
			  buffer_id=ofproto.OFP_NO_BUFFER,
			  in_port=ofproto.OFPP_CONTROLLER,
			  actions=actions,
			  data=data)
	datapath.send_msg(out)
	
    def ARPPacket(self,arp_msg,in_port,datapath):
		if (self.ip_mac_port[in_port][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
			e = ethernet.ethernet(dst=arp_msg.src_mac,
					      src=self.ip_mac_port[in_port][1],
					      ethertype=ether.ETH_TYPE_ARP)
			a = arp.arp(opcode=arp.ARP_REPLY,
				    src_mac=self.ip_mac_port[in_port][1], src_ip=arp_msg.dst_ip,
				    dst_mac=arp_msg.src_mac, dst_ip=arp_msg.src_ip)
			p = packet.Packet()
			p.add_protocol(e)
			p.add_protocol(a)
			self.send_packet(datapath, in_port,p)
    
    def ICMPPacket(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
      if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
	eer=ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
						dst=pkt_ethernet.src,
						src=self.ip_mac_port[in_port][1])
						
	iper=ipv4.ipv4(dst=pkt_ipv4.src,
				    src=self.ip_mac_port[in_port][2],
				    proto=pkt_ipv4.proto)
				    
	icmper=icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
				    code=icmp.ICMP_ECHO_REPLY_CODE,
				    csum=0,
				    data=pkt_icmp.data)
	p = packet.Packet()
	p.add_protocol(eer)
	p.add_protocol(iper)
	p.add_protocol(icmper)
	
	self.send_packet(datapath, in_port, p)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
      
	msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.
	#print(in_port)

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

	if eth.ethertype==0x0800: #PAQUETE IP
	  pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
	  if self.ip_mac_port.get(in_port)[2]==pkt_ipv4.dst: #SI ES PARA EL ROUTER
	    pkt_icmp=pkt.get_protocol(icmp.icmp)
	    if pkt_icmp:
	      self.ICMPPacket(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
	    #else	      
        elif eth.ethertype==ether.ETH_TYPE_ARP:
	  	pkt_arp=pkt.get_protocol(arp.arp)
		self.ARPPacket(pkt_arp,in_port,datapath)
	  
	#else
	  #FAIL
