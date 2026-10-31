"""network/ryu_base.py — the bare Ryu controller for br-twin (Person A).

Installs one rule when the switch connects: priority 0, NORMAL switching. So with the
controller running everything still flows; Person D adds higher-priority rules
(drop = quarantine, meter = rate-limit) through the REST API started alongside it:

    ryu-manager ryu.app.ofctl_rest network/ryu_base.py      # REST on http://127.0.0.1:8080
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3


class TwinBase(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connected(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [p.OFPActionOutput(ofp.OFPP_NORMAL)])]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=0, match=p.OFPMatch(), instructions=inst))
        self.logger.info("switch %d connected - default rule: normal switching", dp.id)
