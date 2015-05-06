#!/usr/bin/python
#coding=utf-8

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib import mac
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from netaddr import *
import Queue #Libreria de cola
import ipaddr
import ipaddress
#h1 ifconfig h1-eth0 192.168.1.2
#h1 route add default gw 192.168.1.1

#if ipaddr.IPAddress('192.168.1.50') in ipaddr.IPv4Network('192.168.1.1'+'/'+ '255.255.255.0'):
#	print "true"
ip_mac_port = {1: ('255.255.255.0','00:00:00:00:01:01','192.168.1.1'),
		       2: ('255.255.255.0','00:00:00:00:01:02','192.168.2.1'),
		       3: ('255.255.255.0','00:00:00:00:01:03','192.168.3.1'),
		       4: ('255.255.255.0','00:00:00:00:01:04','192.168.4.1')}
		       
e = ethernet.ethernet(dst=mac.BROADCAST_STR,
		      src=ip_mac_port[1][1],
		      ethertype=ether.ETH_TYPE_ARP)
a = arp.arp(opcode=arp.ARP_REQUEST,
	    src_mac=ip_mac_port[1][1], src_ip='192.168.1.0',
	    dst_mac=ip_mac_port[2][1], dst_ip='192.168.1.1')


p = packet.Packet()
p.add_protocol(e)
p.add_protocol(a)

print p.data
print p.get_protocol
		
#IMPORTANTE HAY QUE DESARROLLAR LA LISTA DE PAQUETES EN ESPERA
#Y EL MENSAJE DE ARP_REQUEST Y LUEGO UNA FUNCION PARA SACAR DE LA 
#COLA PARA ENVIAR EL PAQUETE CON LA MAC CORRESPONDIENTE
class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ip_mac_port = {1: ('255.255.255.0','00:00:00:00:01:01','192.168.1.1'),
		       2: ('255.255.255.0','00:00:00:00:01:02','192.168.2.1'),
		       3: ('255.255.255.0','00:00:00:00:01:03','192.168.3.1'),
		       4: ('255.255.255.0','00:00:00:00:01:04','192.168.4.1')}
    colaespera = [] #Atributo que guarda la cola
    #  Inserta una entrada a la tabla de flujo.
    def ARPREQUESTPacket(self,dest_ip,source_ip,port,datapath):
		print port
		#if (self.ip_mac_port[in_port][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
		e = ethernet.ethernet(dst=mac.BROADCAST_STR ,
				      src=self.ip_mac_port.get(port)[1],
				      ethertype=ether.ETH_TYPE_ARP)
		a = arp.arp(opcode=arp.ARP_REQUEST,
			    src_mac=self.ip_mac_port.get(port)[1], src_ip=source_ip, dst_ip=dest_ip)
		
		
		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(a)

		self.send_packet(datapath, port,p)
    
    
    
    def IPPACKET(self, datapath, port,mac_dst, pkt):
		pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
		pkt_icmp=pkt.get_protocol(icmp.icmp)
		#suponiendo que port es el puerto por el que va a salir
		
				#poner la ip de destino
		print pkt_ipv4.dst
		print pkt_ipv4.src
		e = ethernet.ethernet(dst=mac_dst,
				      src=self.ip_mac_port[port][1],
				      ethertype=0x0800)
		iper=ipv4.ipv4(dst=pkt_ipv4.dst,
			    src=pkt_ipv4.src,
			    proto=pkt_ipv4.proto)
		icmper=icmp.icmp(type_=pkt_icmp.type,
                                    code=pkt_icmp.code,
                                    csum=0,
                                    data=pkt_icmp.data)

		p = packet.Packet()
		p.add_protocol(e)
		p.add_protocol(iper)
		p.add_protocol(icmper)
		self.send_packet(datapath, port, p)
       
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
		#Procesar un ARPReply para hacer enrutamiento
		elif arp_msg.opcode==arp.ARP_REPLY:
			print "gay"
			for paquetes in self.colaespera: #Buscamos en la lista para ver si hay paquetes en espera
				pkt_ipv4=paquetes.get_protocol(ipv4.ipv4) 
				if(pkt_ipv4):
					if (pkt_ipv4.dst==arp_msg.src_ip): #Si la ip de destino del paquete coincide con quien envio esa ip
						print "puta"
						self.IPPACKET(datapath,in_port,arp_msg.src_mac,paquetes )
						self.colaespera.remove(paquetes)
						
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
			comprobacion=0 
			pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
			entradas_router = self.ip_mac_port.keys()
			for entradas in entradas_router :
				if self.ip_mac_port.get(entradas)[2]==pkt_ipv4.dst: #SI ES PARA EL ROUTER
					pkt_icmp=pkt.get_protocol(icmp.icmp)
					comprobacion=1
					if pkt_icmp:
						self.ICMPPacket(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
			if comprobacion==0:
				for entradas in entradas_router :
					if  ipaddr.IPv4Address(pkt_ipv4.dst) in  ipaddr.IPv4Network(self.ip_mac_port.get(entradas)[2]+"/"+ self.ip_mac_port.get(entradas)[0]):
						self.colaespera.append(pkt)
						self.ARPREQUESTPacket(pkt_ipv4.dst,pkt_ipv4.src,entradas,datapath)
		elif eth.ethertype==ether.ETH_TYPE_ARP:
			pkt_arp=pkt.get_protocol(arp.arp)
			self.ARPPacket(pkt_arp,in_port,datapath)
		  #ipnetwork e ipaddres te dice si una ip esta en una red. lo que estabamos viendo el otro dia en
		  #clase
			#else
			  #FAIL