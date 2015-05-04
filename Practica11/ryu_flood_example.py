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
		
# Enviar un paquete construido en el controlador
# hacia el switch
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




	if eth.ethertype==ether.ETH_TYPE_ARP:
		arp_msg= pkt.get_protocol(arp.arp)
		if (arp_msg.dst_ip == self.interfaces[in_port][0] and arp_msg.opcode==arp.ARP_REQUEST):
			e = ethernet.ethernet(dst=src,
			src=self.macs[in_port],
			ethertype=ether.ETH_TYPE_ARP)
			a = arp.arp(opcode=arp.ARP_REPLY,
			src_mac=self.macs[in_port], src_ip=arp_msg.dst_ip,
			dst_mac=src, dst_ip=arp_msg.src_ip)
			p = packet.Packet()
			p.add_protocol(e)
			p.add_protocol(a)
			self.send_packet(datapath, in_port,p)


class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    mac_to_port = dict()
    ip_mac_port = dict('192.168.1.1':('255.255.255.0','00:00:01:01'),
		       '192.168.2.1':('255.255.255.0','00:00:01:02'),
		       '192.168.3.1':('255.255.255.0','00:00:01:03'),
		       '192.168.4.1':('255.255.255.0','00:00:01:04'))

    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

    def isaValidadSubnet(ipdest,ipsrc):
        
        if ipdest in self.ip_mac_port.keys():
            masc= self.ip_mac_port[ipdest][0]
            hola = haddr_to_bin(masc)
            ip1bin = haddr_to_bin(ipdest)
            ip2bin = haddr_to_bin(ipsrc)
            for i in hola
                if(i==1)
                    if ip1bin[i]!=ip2bin[i]
                        return false
            return true

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.

        destination_ip = msg.match['arp_tpa']
        origen_ip = msg.match['arp_spa']

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
		# Creamos el conjunto de acciones: FLOOD
		actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

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
		actions = [ofp_parser.OFPPacketOut(outproto.OFPP_FLOOD)]
		req = ofp_parser.OFPPacketOut(datapath, buffer_id, in_port, actions, data=msg.data)
		datapath.send_msg(req)

	else: 
		actions = [ofp_parser.OFPActionOutput(self.mac_to_port[dst])]

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

