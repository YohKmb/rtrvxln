#
# vxlrtr packet library module
#

from scapy.fields import ByteField, BitField, IPField, \
    ByteEnumField, IntField
from scapy.layers.inet import Packet, IP, Ether, ARP, ICMP, \
    Emph, DestMACField
from scapy.layers.ntp import FixedPointField
from scapy.data import IP_PROTOS

from codes import MsgCode

IP_PROTO_ICMP = IP_PROTOS.icmp


class IP_Stop(IP):
    
    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        
        payl,_pad = self.extract_padding(s)
        self.add_payload(payl)
        
        if self.proto == IP_PROTOS.icmp:
            self.decode_payload_as(ICMP)


class ARP_Stop(ARP):
    
    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        
        payl,_pad = self.extract_padding(s)
        self.add_payload(payl)


class Ether_Stop(Ether):
    
    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
#         Ether.__init__(self, _pkt, post_transform, _internal, _underlayer)
        super(Ether_Stop, self).__init__(_pkt, post_transform, _internal, _underlayer)
        
    payload_guess = [
                     ({'type': 2054}, ARP_Stop),
                     ({'type': 2048}, IP_Stop)
                    ]


class Vxlan (Packet):
    
    name = "Vxlan Packet"

    payload_guess = [({'flag' : 8}, Ether_Stop)]
    fields_desc = [
                   ByteField("flag", 8),
                   BitField("reserved_pre", 0, 24),
                   BitField("vni", 1, 24),
                   BitField("reserved_post", 0, 8)
                   ]


class L3CacheMsg(Packet):
    
    fields_desc = [
                   ByteEnumField("code", MsgCode.set, {MsgCode.set : "set",MsgCode.get : "get",
                                                       MsgCode.arp : "arp"}),
                   IntField("ref", 0),
                   IntField("vni", 1),
#                    ByteField("code", MsgCode.set),
                   Emph(IPField("host", "0.0.0.0")),
                   DestMACField("hwaddr"),
                   Emph(IPField("vtep", "0.0.0.0")),
                   FixedPointField("timeout", 0.0, 64, 32)
                   ]
# L3CacheMsg().show()
# print len(L3CacheMsg() )
LEN_MSGSTRUCT = len(L3CacheMsg() )
