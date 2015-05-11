#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin

# 802.1q VLAN

#The following actions encapsulate / decapsulate packets into 802.1q VLAN headers.

#class openfaucet.ofaction.ActionSetVlanVid

#    An OFPAT_SET_VLAN_VID action, which sets the 802.1q VLAN ID of packets.

#    vlan_vid
#        The 802.1q VLAN ID to set in packets.

#class openfaucet.ofaction.ActionSetVlanPcp

#    An OFPAT_SET_VLAN_PCP action, which sets the 802.1q VLAN priority of packets.

#    vlan_pcp
#        The VLAN 802.1q priority to set in packets, as an 8-bit unsigned integer. Only the 3 least significant bits may be set to 1. All other bits must be set to 0.

#class openfaucet.ofaction.ActionStripVlan
#    An OFPAT_STRIP_VLAN action, which strips the 802.1q header from packets. This action has no attribute.


class L2Forwarding(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	mac_to_port = dict()
	tabla_vlan = { 1: '10',
				   2: '10',
				   3: '20',
				   4: '20'}
	

	def __init__(self, *args, **kwargs):
		super(L2Forwarding, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
		datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
		ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

		ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

		in_port = msg.match['in_port'] # Puerto de entrada.

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)

        # Extraemos la MAC de destino

		dst = eth.dst  
        
		#Extramos la MAC de origen
        
		src = eth.src
        
		if src not in self.mac_to_port.keys():
			self.mac_to_port[src]=in_port
	
		if haddr_to_bin(dst) == mac.BROADCAST or mac.is_multicast(haddr_to_bin(dst)):
			print("BROADCAST")
			# Creamos el conjunto de acciones: FLOOD
			actions = []
	
			for j in self.tabla_vlan.keys():
				print("Puerto? ", j)
				if self.tabla_vlan.get(j)==self.tabla_vlan.get(in_port) and j !=in_port :
					actions.append(ofp_parser.OFPActionOutput(j))
					print("Vlan ", self.tabla_vlan.get(j),"puerto de entrada", in_port, "otros puertos ", j)
			
			# Ahora creamos el match  
			# fijando los valores de los campos 
			# que queremos casar.
			match = ofp_parser.OFPMatch(eth_dst=dst)
	
			# Creamos el conjunto de instrucciones.
			inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
	
			# Creamos el mensaje OpenFlow 
			mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
	
			# Enviamos el mensaje.
			datapath.send_msg(mod)
	
		elif dst not in self.mac_to_port.keys():
			#actions = [ofp_parser.OFPPacketOut(ofproto.OFPP_FLOOD)]
			actions = []
			print("NO CONOZCO LA MAC ", dst)
			
			for i in self.tabla_vlan.keys():
				if self.tabla_vlan.get(i)==self.tabla_vlan.get(in_port) and i !=in_port :
					actions.append(ofp_parser.OFPActionOutput(i))
					print i
			
			print("QUIEN DE LA VLAN ", self.tabla_vlan.get(in_port), " TIENE LA MAC ", dst,"?")
			#Aqui esta el fallo en buffer id os dejo el mensaje que sale
			
			req = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
			datapath.send_msg(req)
			
		elif self.tabla_vlan.get(self.mac_to_port.get(src)) == self.tabla_vlan.get(self.mac_to_port.get(dst)) :
			actions = [ofp_parser.OFPActionOutput(self.mac_to_port[dst])]
			print("Pasando paquetes de la vlan ", self.tabla_vlan.get(self.mac_to_port.get(src)))
			# Ahora creamos el match  
			# fijando los valores de los campos 
			# que queremos casar.
			match = ofp_parser.OFPMatch(eth_dst=dst)
	
			# Creamos el conjunto de instrucciones.
			inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
	
			# Creamos el mensaje OpenFlow 
			mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
	
			# Enviamos el mensaje.
			datapath.send_msg(mod)
			
		else: #Si no son de la misma vlan, tira el paquete
			actions = []
			print("Tirando paquete!!")
	
			# Ahora creamos el match  
			# fijando los valores de los campos 
			# que queremos casar.
			match = ofp_parser.OFPMatch(eth_dst=dst)
	
			# Creamos el conjunto de instrucciones.
			inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
	
			# Creamos el mensaje OpenFlow 
			mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
	
			# Enviamos el mensaje.
			datapath.send_msg(mod)