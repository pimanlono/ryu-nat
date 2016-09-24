
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0

import nat
import simple_switch_13
import host

class NATController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NATController, self).__init__(*args, **kwargs)
        self.switch = simple_switch_13.SimpleSwitch13(*args, **kwargs)
        self.nat = nat.NAT(*args, **kwargs)
        self.host = host.Host(*args, **kwargs)

    @set_ev_cls(dpset.EventDP, CONFIG_DISPATCHER)
    def multidatapathswitch_register(self, dp, enter_leave=True):
        self.nat.multidatapathswitch_register(dp, enter_leave=enter_leave)
        self.switch.multidatapathswitch_register(dp, enter_leave=enter_leave)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.switch.switch_features_handler(ev)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def _event_switch_enter_handler(self, ev):
        self.nat.event_switch_enter_handler(ev)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        dev = self.host.packet_in_handler(ev)
        if not dev:
            dev = self.nat.packet_in_handler(ev)
        if not dev:
            pass
            #self.switch.packet_in_handler(ev)
