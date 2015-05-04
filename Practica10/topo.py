#!/usr/bin/python
#coding=utf−8

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI

class SingleSwitchTopo(Topo):
    "Un switch sencillo conectado a n hosts."
    def build(self, n=2):
        switch = self.addSwitch('s1')
        #range (N) generara los numeros 0..N−1
        for h in range (n) :
            host = self.addHost ('h%s' % (h + 1 ))
            self.addLink(host, switch)

topos = { 'MyTopo4':( lambda : SingleSwitchTopo(4) ) , 'MyTopo6':( lambda :
SingleSwitchTopo (6) )}


class Treetopo(topo)
    def build(self,n, fanout)
	switch = self.addSwitch('s1')
	cswitch=1
	chost=0
	recursivo(self,switch, n-1,fanout,cswitch+1,chost)
	
    def recursivo(self, switch, n, fanout,cswitch, host,chost )
	if(n!=0)
	  for i in range(cswitch,cswitch+fanout)
	    nswitch = self.addSwitch('s%s' % i)
	    cswitch=cswitch+1
	    self.addLink(nswitch,switch)
	    recursivo(self,nswitch,n-1,fanout,cswitch+1,host,chost) 
	else
	  for h in range(chost,chost+fanout) :
	    host = self.addHost ('h%s' % (h + 1))
	    chost=chost+1
            self.addLink(host, switch)