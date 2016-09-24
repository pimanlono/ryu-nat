# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp 

from ryu.ofproto import ether
from ryu.ofproto import inet

from netaddr import IPNetwork, IPAddress
from apps import App

class NAT(App):

    def __init__(self, *args, **kwargs):
        super(NAT, self).__init__(*args, **kwargs)
        self.ip_map = {} 
        self.IDLE_TIME = 130
        self.mac_to_port = {}
        self.nat_map = {}
        self.address = {'addr': '10.6.10.1', 'mac': '00:00:00:00:00:01' }
        self.ports = range(20000,60000)
        self.external_ips = {"patch1": "10.0.4.15",}      
        self.rules = [
                    ('10.6.10.0/24', 0, '10.0.4.15', 0, 'both'),
                    ('10.6.10.3', 0, '10.0.4.15', 8000, 'both'),
                
                    ]

    def multidatapathswitch_register(self, dp, enter_leave=True):
        dpid = dp.dp.id
        self.logger.info(str(dpid)+ " :")
        self.ip_map.setdefault(dpid, {})
        self.mac_to_port.setdefault(dpid, {})
        for port in dp.ports:
            if port.name in self.external_ips:
                self.ip_map[dpid][self.external_ips[port.name]] = port.port_no
                self.mac_to_port[dpid][port.port_no] = port.hw_addr 
            self.logger.info("\t"+str(port.hw_addr)+ "\t"+str(port.name)+"\t"+ str(port.port_no)+ "\t")

    def add_flow(self, datapath,  match, actions, priority=0, idle_timeout=64,
                 buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=idle_timeout,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=idle_timeout,
                                    priority=priority,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def event_switch_enter_handler(self, ev):

        dp = ev.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.logger.info("Switch connected %s", dp)
 
        # do address translation for following types of packet
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(eth_type= 0x0800) # Ipv4
        self.add_flow(dp, match, actions)

    def learn_mac(self, msg, eth, pkt_ipv4):
        dpid = msg.datapath.id
        port_in = in_port = msg.match['in_port']
        if port_in not in self.ip_map:
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][eth.src] = in_port
            self.mac_to_port[dpid][in_port] = (eth.src, pkt_ipv4.src)

    def get_ip_network(self, ip):
        if "/" not in ip:
            return IPAddress(ip)
        return IPNetwork(ip)

    def cmp_networks(self, net1, net2):
        try:
            return net1 == net2 or net1 in net2 
        except:
            return False

    def get_ip_port(self, datapath, pkg, ethernet_pkt, ofproto, pkt_icmp=None, port={}, _type='both'):
        """ Check if can apply one nat rule
            Nat type could be:
                * 0: snat outgoin
                * 1: snat incoming or dnat incoming
            return: None if not rule apply
            return: destination ip, out_put port, nat_type
        """
        for src, ps, dst, pd, rtype in self.rules:
            if self.cmp_networks(self.get_ip_network(pkg.src), self.get_ip_network(src)): 
                # is icmp so not port or outport and type match 
                if pkt_icmp is not None or (port['dst'] == pd and (rtype==_type or rtype=='both')):
                    return dst, self.ip_map[datapath.id][dst], 0 #if  pkg.dst != dst else 3

            if self.get_ip_network(pkg.dst) == self.get_ip_network(dst):
                
                if pkt_icmp is not None:
                    if pkt_icmp.code in self.mac_to_port[datapath.id]:                   
                        return self.mac_to_port[datapath.id][pkt_icmp.code][1], pkt_icmp.code, 1
                elif port['dst'] in self.nat_map:
                    key = "%s_%d"%(self.nat_map[port['dst']], port['src'])
                    return self.nat_map[port['dst']], self.nat_map[key][2], 1


            #FIXME: this case is when you ping your external ip from internal host, for now its not working   
#            if (self.get_ip_network(pkg.dst) == self.get_ip_network(dst)) and (self.get_ip_network(pkg.dst) == self.get_ip_network(src)):
#                return pkg.dst, ofproto.OFPP_FLOOD, 2
            
    def packet_in_handler(self, ev):
        print "NAT: Packet in"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        if not any((pkt_ipv4, pkt_icmp)):
            return

        self.learn_mac(msg, pkt_ethernet, pkt_ipv4)
        if pkt_icmp:
            return self.process_icmp(msg,datapath,ofproto, parser, pkt,pkt_ethernet, pkt_ipv4, pkt_icmp)
        
        self.process_nat(msg,datapath,ofproto, parser, pkt,pkt_ethernet, pkt_ipv4)

        return 

    def process_icmp(self, msg,datapath,ofproto, parser, pkt,pkt_ethernet, pkt_ipv4, pkt_icmp):
       if  self.ip_map[datapath.id]:
            dest = self.get_ip_port(datapath, pkt_ipv4, pkt_ethernet, ofproto, pkt_icmp=pkt_icmp)
            
            if dest:
                dst_addr, out_port, nat_type = dest
                if nat_type==0: # to external  
                    pkt_icmp.code = msg.match['in_port']
                    pkt_icmp.csum = 0
                    pkt_ipv4.src = dst_addr
                elif nat_type==1: # to internal
                    addr = self.mac_to_port[datapath.id][pkt_icmp.code][0]
                    pkt_ethernet.dst = addr
                    pkt_icmp.code = 0
                    pkt_ipv4.dst = dst_addr

                newpkt = self.get_new_package(pkt_ethernet,[pkt_ipv4, pkt_icmp])
                actions = [ parser.OFPActionOutput(out_port)  ]
                out = parser.OFPPacketOut(datapath=datapath, 
                            buffer_id= 0xffffffff, #FIXME: use a constant
                            data=newpkt.data, 
                            in_port=msg.match['in_port'],
                            actions=actions)
                datapath.send_msg(out)
                return True


    def process_nat(self, msg,datapath,ofproto, parser, pkt,pkt_ethernet, pkt_ipv4):

        #print pkt.src, " --> ", pkt.dst
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)
        tcp_udp =  _tcp  if _tcp else _udp
        ports={
            'dst': _tcp.dst_port if _tcp else _udp.dst_port,
            'src': _tcp.src_port if _tcp else _udp.src_port
        }
        print pkt_ipv4.src, " --> ", pkt_ipv4.dst, ports
#        print "**"*10, "\n", pkt, "\n\n"
        port_info = self.get_ip_port(datapath, pkt_ipv4, pkt_ethernet, ofproto, port=ports, _type='tcp' if _tcp else 'udp' )
        if port_info:
            dst_addr, out_port, nat_type = port_info
            if nat_type == 0:
                print "NAT T0"
                key = "%s_%d"%(pkt_ipv4.src, ports['dst'])
                port = self.ports.pop()
                self.nat_map[key] = (port, ports['src'],  msg.match['in_port'])
                
                self.nat_map[port] = pkt_ipv4.src
                self.nat_map[pkt_ipv4.src] = tcp_udp.src_port
                in_port=msg.match['in_port']

                # TCP for now
                match = parser.OFPMatch(in_port=in_port,
                                    eth_type=ether.ETH_TYPE_IP,
                                    ip_proto=inet.IPPROTO_TCP,
                                    ipv4_src=pkt_ipv4.src,
                                    ipv4_dst=pkt_ipv4.dst,
                                    tcp_src=tcp_udp.src_port,
                                    tcp_dst=tcp_udp.dst_port)

                actions = [#parser.OFPActionSetField(eth_src=self.address['mac']),
                       parser.OFPActionSetField(ipv4_src=dst_addr),
                       parser.OFPActionSetField(tcp_src=port),
                       parser.OFPActionOutput(out_port)]

                match_back = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                             ip_proto=inet.IPPROTO_TCP,
                                             #ipv4_src=pkt_ipv4.dst,
                                             ipv4_dst=dst_addr,
                                             tcp_src=tcp_udp.dst_port,
                                             tcp_dst=port)

                actions_back = [parser.OFPActionSetField(eth_dst=pkt_ethernet.src),
                                parser.OFPActionSetField(ipv4_dst=pkt_ipv4.src),
                                parser.OFPActionSetField(tcp_dst=tcp_udp.src_port),
                                parser.OFPActionOutput(in_port)]


                self.add_flow(datapath, match, actions, priority=10)
                self.add_flow(datapath, match_back, actions_back, priority=10)  
              
            elif nat_type == 1:
                print "NAT T1"
                if dst_addr in self.nat_map:
                    match = parser.OFPMatch(in_port=msg.match['in_port'],
                                        eth_type=ether.ETH_TYPE_IP,
                                        ip_proto=inet.IPPROTO_TCP,
                                        ipv4_src=pkt_ipv4.src,
                                        ipv4_dst=pkt_ipv4.dst,
                                        tcp_src=tcp_udp.src_port,
                                        tcp_dst=tcp_udp.dst_port)

                    actions = [parser.OFPActionSetField(eth_dst=self.mac_to_port[datapath.id][out_port][0] ),
                           parser.OFPActionSetField(ipv4_dst=dst_addr),
                           parser.OFPActionSetField(tcp_dst=self.nat_map[dst_addr]),
                           parser.OFPActionOutput(out_port)]

                    self.add_flow(datapath, match, actions, priority=10)
                else:
                    return
            buffer_id=msg.buffer_id
            data=msg.data
            d = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                d = data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                      in_port=msg.match['in_port'], actions=actions, data=d)
            datapath.send_msg(out)
            return True
                
        print "dev  ", port_info



    def get_new_package(self, pkt_ethernet, protocols, pkt=None):
        if pkt is None:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=pkt_ethernet.dst,
                                               src=pkt_ethernet.src))
            for proto in protocols:        
                pkt.add_protocol(proto)
        pkt.serialize()
#        print "##"*5, "\n",pkt," \n\n"
        return pkt


