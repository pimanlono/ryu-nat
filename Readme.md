Controller handle events and pass the events to other services in order nat,host,switch.

To run use
    $ ryu-manager controller.py


Email for Help
===============

I am trying to implement nat service (I hope rest_nat) but I am having some problems.
When request a http package I receive a lot of retransmission packages (see attached image).
I receive a corrupted html file. 

ICMP is working.
Attached the app code, but put special attention to 

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


Environment:
	$ ovs-vsctl --version
		ovs-vsctl (Open vSwitch) 2.3.0
		Compiled Mar 28 2016 10:28:28
		DB Schema 7.6.0

	$ uname -a
		Linux ovs1 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt25-2+deb8u3 (2016-07-02) i686 GNU/Linux

	I can not use ryu.ofproto.ofproto_v1_3_parser.NXActionNAT because requires ovs 2.5+ and linux 4.2+

External host:  192.168.1.200:8000  
	Running:  python -m SimpleHTTPServer 8000 

External Ip: 10.0.4.15  gateway 10.0.4.2 (nat virtualbox).
Local network : 10.6.10.0 gateway 10.6.10.1
Nat server:  response icmp 10.6.10.1
Local Host: 10.6.10.3
	Running: wget http://192.168.1.200:8000/  --tries 1

Result Flow table 

$ ovs-ofctl dump-flows ovsbr0

NXST_FLOW reply (xid=0x4):
1) cookie=0x0, duration=5.526s, table=0, n_packets=7, n_bytes=494, idle_timeout=64, idle_age=5, priority=10,tcp,in_port=1,nw_src=10.6.10.3,nw_dst=192.168.1.200,tp_src=52952,tp_dst=8000 actions=mod_nw_src:10.0.4.15,mod_tp_src:59999,output:3

2) cookie=0x0, duration=10.474s, table=0, n_packets=0, n_bytes=0, idle_timeout=64, idle_age=10, priority=0,ip actions=CONTROLLER:65535
3) cookie=0x0, duration=10.480s, table=0, n_packets=2, n_bytes=116, idle_age=5, priority=0 actions=CONTROLLER:65535

4) cookie=0x0, duration=5.526s, table=0, n_packets=9, n_bytes=5071, idle_timeout=64, idle_age=1, priority=10,tcp,nw_dst=10.0.4.15,tp_src=8000,tp_dst=59999 actions=mod_dl_dst:9a:2b:5c:5a:c9:20,mod_nw_dst:10.6.10.3,mod_tp_dst:52952,output:1

An observation about the flow is the order, because are set in this order 3,2,1,4. So I think 4 is never called because package is passed to controller.
