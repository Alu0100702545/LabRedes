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
from ryu.ofproto import ether
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.mac import haddr_to_bin
from netaddr import *
import Queue #Libreria de cola
import ipaddr
import ipaddress

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    mac_to_port = dict()
    tabla_vlan = { 1: '10',
                   2: '10',
                   3: '20',
                   4: '20'}
    port_ip_mac =dict()
    interfaces_virtuales = { '10': ('00:00:00:00:01:01','255.255.255.0','192.168.1.1'), #'10': ('00:00:00:00:01:01','192.168.1.1'),
                    '20': ('00:00:00:00:01:02','255.255.255.0','192.168.2.1'), #'20': ('00:00:00:00:01:02','192.168.2.1'),
                    '30': ('00:00:00:00:01:03','255.255.255.0','192.168.3.1'), #'30': ('00:00:00:00:01:03','192.168.3.1'),
                    '40': ('00:00:00:00:01:04','255.255.255.0','192.168.4.1')} #'40': ('00:00:00:00:01:04','192.168.4.1')}
                    
    tabla_enrutamiento = {}
    colaespera = [] #Atributo que guarda la cola
    
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)
        
    def compare(self,MASK_LIST):
        cont=0
        maximo=0
        port=0
        for MASK in MASK_LIST:
            for i in range(len(MASK[0])):
                if(MASK[0][i]=='1'):
                    cont=cont+1
            if(cont>maximo):
                maximo=cont
                port=MASK[1]
                
        return port
        
    def paraipinterfaz(self,ip):
        presente=False
        for INTERFACE in self.interfaces_virtuales.keys():
            if self.interfaces_virtuales.get(INTERFACE)[2]==ip:
                presente=True
        return presente
        
    def paramacinterfaz(self,mac):
        presente=False
        for INTERFACE in self.interfaces_virtuales.keys():
            if self.interfaces_virtuales.get(INTERFACE)[0]==mac:
                presente=True
        return presente
    
    def add_flow(self, datapath, priority, match, actions,table_id=0 ,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match,
                instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
            match=match,table_id=table_id, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        print(mod)
        datapath.send_msg(mod)

    def ARPREQUESTPacket(self,dest_ip,source_ip,port,datapath):
        print port
        #if (self.interfaces_virtuales[in_port][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
        e = ethernet.ethernet(dst=mac.BROADCAST_STR ,
                      src=self.interfaces_virtuales.get(self.tabla_vlan[port])[0],
                      ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REQUEST,
                src_mac=self.interfaces_virtuales.get(self.tabla_vlan[port])[0], src_ip=source_ip, dst_ip=dest_ip)
        
        
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        
        self.send_packet(datapath, port,p)

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
        if arp_msg.opcode==arp.ARP_REQUEST:
        #if (self.interfaces_virtuales[self.tabla_vlan[in_port]][2]==arp_msg.dst_ip and arp_msg.opcode==arp.ARP_REQUEST):
            #Si va pa la interfaz coño    
            e = ethernet.ethernet(dst=arp_msg.src_mac,
                          src=self.interfaces_virtuales[self.tabla_vlan[in_port]][0],
                          ethertype=ether.ETH_TYPE_ARP)
            a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=self.interfaces_virtuales[self.tabla_vlan[in_port]][0], src_ip=arp_msg.dst_ip,
                    dst_mac=arp_msg.src_mac, dst_ip=arp_msg.src_ip)
            p = packet.Packet()
            p.add_protocol(e)
            p.add_protocol(a)
            self.send_packet(datapath, in_port,p)
        #Procesar un ARPReply para hacer enrutamiento
        elif arp_msg.opcode==arp.ARP_REPLY:
            for paquetes in self.colaespera: #Buscamos en la lista para ver si hay paquetes en espera
                pkt_ipv4=paquetes.get_protocol(ipv4.ipv4) 
                if(pkt_ipv4):
                    if (pkt_ipv4.dst==arp_msg.src_ip): #Si la ip de destino del paquete coincide con quien envio esa ip
                        self.tabla_enrutamiento[pkt_ipv4.dst]=arp_msg.src_mac
                        #self.ReenvioPro(self,datapath,pkt_ipv4.dst,in_port,self.interfaces_virtuales[in_port][1],arp_msg.src_mac,paquetes)
                        #self.IPPACKET(datapath,in_port,arp_msg.src_mac,paquetes )
                        self.colaespera.remove(paquetes)
                        ofproto = datapath.ofproto
                        ofp_parser = datapath.ofproto_parser
                        actions =[ofp_parser.OFPActionSetField(eth_dst=self.tabla_enrutamiento[pkt_ipv4.dst]),
                                      ofp_parser.OFPActionSetField(eth_src=self.interfaces_virtuales[self.tabla_vlan[in_port]][0]),
                                      ofp_parser.OFPActionDecNwTtl(),
                                      ofp_parser.OFPActionOutput(in_port)]
                        paquetes.serialize()
                        data = paquetes.data
                        out = ofp_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
                        datapath.send_msg(out)
                        
    def ICMPPacket(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            eer=ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                        dst=pkt_ethernet.src,
                        src=self.interfaces_virtuales[self.tabla_vlan[in_port]][0])
                        
            iper=ipv4.ipv4(dst=pkt_ipv4.src,
                    src=self.interfaces_virtuales[self.tabla_vlan[in_port]][2],
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
              
    def paquete_para_enrutar(self, ev):
      
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
        pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
        
        #src = eth.src
        port =in_port
        if port not in self.port_ip_mac.keys():
            self.port_ip_mac[port]=(pkt_ipv4.src,eth.src)
        
        
        print("Oh is a packet!")
        #print(eth);
        if eth.ethertype==0x0800: #Si es IP
            entradas_router = self.interfaces_virtuales.keys()
            listacoincide=[]
            for entradas in entradas_router :
                if  ipaddr.IPv4Address(pkt_ipv4.dst) in  ipaddr.IPv4Network(self.interfaces_virtuales.get(entradas)[2]+"/"+ self.interfaces_virtuales.get(entradas)[1]):
                    mask=IPAddress(self.interfaces_virtuales.get(entradas)[1]).bin
                    listacoincide.append((mask,entradas))
                        
            entradas=self.compare(listacoincide)
            if(pkt_ipv4.src not in self.tabla_enrutamiento): 
                self.tabla_enrutamiento[pkt_ipv4.src]=eth.src
            if(pkt_ipv4.dst not in self.tabla_enrutamiento):
                print("I don't know that mac :c")
                self.colaespera.append(pkt)
                for puertos in self.tabla_vlan.keys() :
                    if self.tabla_vlan.get(puertos)==entradas:
                        print("MANDARÉ UN ARP PARA DESCUBRIR EL DESTINO")
                        self.ARPREQUESTPacket(pkt_ipv4.dst,pkt_ipv4.src,puertos,datapath)
            else: #Si tenemos la mac en cache
                #self.ReenvioPro(datapath, entradas, pkt_ipv4.dst, self.interfaces_virtuales[entradas][1], self.tabla_enrutamiento[ipv4], pkt)
                print entradas
                print("I will flow that")

                for puerto_salida in self.port_ip_mac.keys():
                    if self.port_ip_mac.get(puerto_salida)[0]==pkt_ipv4.dst:
                        actions =[ofp_parser.OFPActionSetField(eth_dst=self.tabla_enrutamiento[pkt_ipv4.dst]),
                                    ofp_parser.OFPActionSetField(eth_src=self.interfaces_virtuales.get(entradas)[0]),
                                    ofp_parser.OFPActionDecNwTtl(),
                                    ofp_parser.OFPActionOutput(puerto_salida)]
                                    
                        match = ofp_parser.OFPMatch(ipv4_dst=pkt_ipv4.dst,eth_type=ether.ETH_TYPE_IP)
                        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                        mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=0, match=match,table_id=1,instructions=inst,buffer_id=msg.buffer_id)
                        datapath.send_msg(mod)
        elif eth.ethertype==ether.ETH_TYPE_ARP: #Si es ARP
                pkt_arp=pkt.get_protocol(arp.arp)
                self.ARPPacket(pkt_arp,in_port,datapath)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
                       # correspondiente
        print("===========================================================================")
        print("PAQUETE ENTRANTE")
        in_port = msg.match['in_port'] # Puerto de entrada.
        print("PUERTO: ", in_port)
        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        print("ETH: ", eth)
        # Extraemos la MAC de destino

        dst = eth.dst  
        print("MAC DE DESTINO: ", dst)
        #Extramos la MAC de origen
        src = eth.src
        print("MAC DE ORIGEN: ", src)
        
        if src not in self.mac_to_port.keys():
            print("NO TENGO EL ORIGEN")
            self.mac_to_port[src]=in_port
        
        
        if haddr_to_bin(dst) == mac.BROADCAST or mac.is_multicast(haddr_to_bin(dst)):
            # Creamos el conjunto de acciones: FLOOD PENE
            
            if eth.ethertype==ether.ETH_TYPE_ARP:
                pkt_arp=pkt.get_protocol(arp.arp)
                print("ARP POR BROADCAST!!")
                #for INTERFACE in self.interfaces_virtuales.keys():
                if self.paraipinterfaz(pkt_arp.dst_ip):
                    print("ES PA TI RESPONDE A ESE ARP MARICONA")
                    self.ARPPacket(pkt_arp,in_port,datapath)
                else: 
                    print("Retransmito ese arp cual swtich normal")
                    actions = []
                    print("-------------------------------------------------------")
                    for j in self.tabla_vlan.keys():
                        print("Puerto? ", j)
                        if self.tabla_vlan.get(j)==self.tabla_vlan.get(in_port) and j !=in_port :
                            actions.append(ofp_parser.OFPActionOutput(j))
                            print("Vlan ", self.tabla_vlan.get(j),"puerto de entrada", in_port, "otros puertos ", j)
                    # Ahora creamos el match  
                    # fijando los valores de los campos 
                    # que queremos casar.
                    match = ofp_parser.OFPMatch(eth_dst=dst,eth_src=src)
                    # Creamos el conjunto de instrucciones.
                    inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    # Creamos el mensaje OpenFlow 
                    mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
                    # Enviamos el mensaje.
                    datapath.send_msg(mod)
            else: 
                print("BROADCAST NORMAL")
                actions = []
                print("-------------------------------------------------------")
                for j in self.tabla_vlan.keys():
                    print("Puerto? ", j)
                    if self.tabla_vlan.get(j)==self.tabla_vlan.get(in_port) and j !=in_port :
                        actions.append(ofp_parser.OFPActionOutput(j))
                        print("Vlan ", self.tabla_vlan.get(j),"puerto de entrada", in_port, "otros puertos ", j)
                print("-------------------------------------------------------")
                # Ahora creamos el match  
                # fijando los valores de los campos 
                # que queremos casar.
                match = ofp_parser.OFPMatch(eth_dst=dst,eth_src=src)
                # Creamos el conjunto de instrucciones.
                inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                # Creamos el mensaje OpenFlow 
                mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
                # Enviamos el mensaje.
                datapath.send_msg(mod)
                
        elif self.paramacinterfaz(dst):
              #eth = pkt.get_protocol(ethernet.ethernet)
            pkt_arp=pkt.get_protocol(arp.arp)
            #PROCESAR ARPREPLY PARA LAS INTERFACES VIRTUALES <---------
            print("Para la interfaz virtual")
            for INTERFACE in self.interfaces_virtuales.keys():
               if(self.interfaces_virtuales.get(INTERFACE)[0]==dst):
                    if eth.ethertype==0x0800: #Si es IP
                        pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
                        if self.paraipinterfaz(pkt_ipv4.dst):
                            pkt_icmp=pkt.get_protocol(icmp.icmp)
                            if (pkt_icmp): #Si es ICMP
                                print("ESE IP ES PARA MI, RESPONDERE")
                                self.ICMPPacket(datapath, in_port, eth, pkt_ipv4, pkt_icmp)
                        else:
                            print("ESTO PAQUETE IP NO ES PA MI, LO ENRUTARE")
                            match = ofp_parser.OFPMatch(eth_dst=self.interfaces_virtuales.get(INTERFACE)[0],ipv4_dst=pkt_ipv4.dst)
                            goto = ofp_parser.OFPInstructionGotoTable(1)
                            mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=0,match=match,table_id=0,instructions=[goto],buffer_id=msg.buffer_id)
                            #mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=0, match=match,table_id=0,instructions=[goto])
                            datapath.send_msg(mod)
                            self.paquete_para_enrutar(ev)

                    elif eth.ethertype==ether.ETH_TYPE_ARP:
                        print("UN ARP CON MI NOMBRE :O")
                        pkt_arp=pkt.get_protocol(arp.arp)
                        self.ARPPacket(pkt_arp,in_port,datapath)
               
        elif dst not in self.mac_to_port.keys() :
            #actions = [ofp_parser.OFPPacketOut(ofproto.OFPP_FLOOD)]
               # Creamos el conjunto de acciones: FLOOD PENE
            pkt_arp=pkt.get_protocol(arp.arp)
            if(pkt_arp):
                for INTERFACE in self.interfaces_virtuales.keys():
                    if eth.ethertype==ether.ETH_TYPE_ARP and self.interfaces_virtuales.get(INTERFACE)[2]==pkt_arp.dst_ip:
                        print("AL ENRUTAMOVIL! PIRIRIRIRIRIRI")
                        self.ARPPacket(pkt_arp,in_port,datapath)
            else: 
                actions = []
                print("NO CONOZCO LA MAC ", dst)
                
                for i in self.tabla_vlan.keys():
                    if self.tabla_vlan.get(i)==self.tabla_vlan.get(in_port) and i !=in_port :
                        actions.append(ofp_parser.OFPActionOutput(i))
                        print i
                
                print("QUIEN DE LA VLAN ", self.tabla_vlan.get(in_port), " TIENE LA MAC ", dst,"?")
                #Aqui esta el fallo en buffer id os dejo el mensaje que sale
                
                req = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
                print("MANDAMOS REQ")
                datapath.send_msg(req)
                print("MANDADO!")
            
        elif self.tabla_vlan.get(self.mac_to_port.get(src)) == self.tabla_vlan.get(self.mac_to_port.get(dst)) :
            actions = [ofp_parser.OFPActionOutput(self.mac_to_port[dst])]
            print("PASANDO PAQUETES DENTRO DE LA VLAN ", self.tabla_vlan.get(self.mac_to_port.get(src)))
            # Ahora creamos el match  
            # fijando los valores de los campos 
            # que queremos casar.
            match = ofp_parser.OFPMatch(eth_dst=dst,eth_src=src)
    
            # Creamos el conjunto de instrucciones.
            inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    
            # Creamos el mensaje OpenFlow 
            #mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, buffer_id=msg.buffer_id)
            mod = ofp_parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst, idle_timeout=30, buffer_id=msg.buffer_id)
    
            # Enviamos el mensaje.
            datapath.send_msg(mod)
        else: #Si no son de la misma vlan, tira el paquete
            #eth = pkt.get_protocol(ethernet.ethernet)
            pkt_arp=pkt.get_protocol(arp.arp)
            #PROCESAR ARPREPLY PARA LAS INTERFACES VIRTUALES <---------
            print("ESTOY EN EL ELSE")

