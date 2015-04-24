#! /usr/bin/env python

#
# Copyright 2015 Yoh Kamibayashi
#


from multiprocessing import Process, Pipe, cpu_count, current_process
from collections import deque, defaultdict
from enum import Enum, IntEnum
# from enum import IntEnum
import time
# from datetime import time
# from datetime import datetime, timedelta as tdelta
# from enum34 import import Enum

from contextlib import closing
import socket

import argparse
import json
from netaddr import IPAddress, IPNetwork, smallest_matching_cidr
import sys

# from scapy.data import *
from scapy.fields import ByteField, BitField, IPField, \
    ByteEnumField, IntField
from scapy.layers.inet import Packet, IP, Ether, ARP, ICMP, icmptypes, Raw, Emph
from scapy.layers.ntp import FixedPointField
from scapy.data import ETHER_TYPES, IP_PROTOS

from scapy.arch import get_if_hwaddr, linux
from random import randint
# from scapy.arch.linux import get_if_list
# from ryu.app.rest_router import ICMP


PORT_DST_VXLAN = 4789
PORT_BIND_CACHE = 54789

TIMEOUT_L3CACHE = 300
TIMEOUT_RECV_CACHE = 0.05
INTERVAL_REFRESH = 50

ADDRESS_BIND = ""

BUFFLEN_RECV = 10
BITELEN_RECV = 9000

MAC_MODULER = 2 ** 48
MAX_REFID = 2 ** 24 - 1



class RouterVxlan (object):
    
    def __init__ (self):
        pass


class ActionCode(Enum):
    flood = 0x00
    arp = 0x01


class MsgCode(IntEnum):
    set = 0x00
    get = 0x01
    arp = 0x10


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
                   Emph(IPField("vtep", "0.0.0.0")),
                   FixedPointField("timeout", 0.0, 64, 32)
                   ]
# L3CacheMsg().show()
# print len(L3CacheMsg() )
LEN_MSGSTRUCT = len(L3CacheMsg() )


class PduProcessor(Process):

    def __init__(self, pipes, maps):

        super(PduProcessor, self).__init__()
        
        self.daemon = True
        self.pipes = pipes
        self.maps = maps
        
#         self.l3cache = {}
        self.l3cache = defaultdict(lambda: (None, None, None))
#         self.set_cache_timeout()
#     
# 
#     def set_cache_timeout(self, secs=300):
#         self.intvl_tout = secs

   
    def run(self):

        debug_info("{0} starts. : pid = {1}".format(current_process().name, \
                                                    current_process().pid ), 1)
        
        conn_r, conn_s = self.pipes
        conn_s.close()
        
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ) \
                    as self.sock:
#                 self.sock.settimeout(0.05)
                
                while conn_r.poll() != None:
                    try:
    #                     udp_data= conn_r.recv()
                        udp_data, endp = conn_r.recv()
                        endp_ip, _endp_port = endp
#                         print(str(endp) )
            #             hexdump(udp_data)
                        pdu = Vxlan(udp_data)
            #             pdu.show()
                        e_type = pdu[Ether_Stop].type
                        vni_in = pdu[Vxlan].vni
                        
                        map_in = self.maps[vni_in]
            
                        if e_type == ETHER_TYPES.ARP:
                            self._arp_reply(pdu, map_in, endp_ip)
                            
                            ip_src = pdu[ARP_Stop].psrc
                            if not ip_src in self.l3cache:
                                self._regist_l3cache(vni_in, ip_src, endp_ip)
                        
                        elif e_type == ETHER_TYPES.IPv4:
#                             debug_info("IP arrived.", 1)
                            ip_src, ip_dst = pdu[IP_Stop].src, pdu[IP_Stop].dst
                            if not ip_src in self.l3cache:
                                self._regist_l3cache(vni_in, ip_src, endp_ip)
                            
                            
                            if ip_dst != str(map_in["gw_ip"]):
                                
                                self._route_packet(ip_dst, pdu)
#                             if pdu[IP_Stop].dst != str(map_in["gw_ip"]):
#                                 debug_info("A packet to be routed arrived.", 1)
#                                 vni, vtep_dst, tout = self._lookup_l3cache(ip_dst)
#                                 vni_dst = self._lookup_longest_subnet(ip_dst)
#                                 debug_info("dst = {0}, gw = {1}, cmp = {2}".format( \
#                                                 str(pdu[IP_Stop].dst), map_in["gw_ip"],
#                                                 str(pdu[IP_Stop].dst) == map_in["gw_ip"]), 2)
                                # Routing process
                            
                            elif pdu[IP_Stop].proto == IP_PROTOS.icmp:
                                # Act like forwarding to loopback address
                                self._icmp_reply(pdu, map_in, endp_ip)
            #                 sub_mtched = smallest_matching_cidr(pdu[IP_Stop].dst, cidrs)
            #             print "Pid = " + str(current_process().pid) + " took timestamp of " + msg
                    except EOFError as _excpt:
                        debug_info("[%s] : Its connection was closed." % current_process().name, 2)
                        break
                    
                    except KeyboardInterrupt as _excpt:
                        print ""
                        debug_info("[%s] : Interrupt was detected." % current_process().name, 3)
                        break
                    
                    except Exception as excpt:
                        debug_info("Encontered an unknown error!", 3)
                        print excpt
                        sys.exit(1)
    
        except socket.error as excpt:
            print(excpt)
            sys.exit(1)


    def _route_packet(self, ip_dst, pdu):
        
        vni_dst, vtep_dst, tout = self._lookup_l3cache(ip_dst)
        
        if vtep_dst == ActionCode.arp:
            vni_dst = self._lookup_longest_subnet(ip_dst)
            vtep_dst = self._arp_request(vni_dst, ip_dst)
        
        debug_info("route method dummy : {0}".format( (vni_dst, vtep_dst, tout) ), 2)
        

    def _arp_reply(self, pdu, map_in, endp_ip):
#         debug_info("ARP arrived.", 1)
        arp_in = pdu[ARP_Stop]
#         arp_in.show()
        if arp_in.pdst == str( map_in["gw_ip"] ):
            rep = Vxlan(vni=map_in["vni"])/Ether(src=map_in["hwaddr"], \
                                        dst=arp_in.hwsrc)/ \
                                    ARP(op=ARP.is_at, hwdst=arp_in.hwsrc, \
                                        hwsrc=map_in["hwaddr"], pdst=arp_in.psrc, \
                                        psrc=arp_in.pdst)
                                    
            self.sock.sendto(str(rep), (endp_ip, map_in["vteps"][endp_ip]) )
    
    
    def _icmp_reply(self, pdu, map_in, endp_ip):
#         debug_info("ICMP echo to GW arrived.", 1)
        icmp_in = pdu[IP_Stop][ICMP]
#         icmp_in.show()
        
        if icmptypes[icmp_in.type] == "echo-request" \
            and pdu[IP_Stop].dst == str(map_in["gw_ip"]) \
            and pdu[Ether_Stop].dst == map_in["hwaddr"]:
#             eth_in = pdu[Ether_Stop]
            
            rep = Vxlan(vni=map_in["vni"])/Ether(src=map_in["hwaddr"], \
                                        dst=pdu[Ether_Stop].src)/ \
                                    IP(dst=pdu[IP_Stop].src, src=pdu[IP_Stop].dst)/ \
                                    ICMP(type=0, id=icmp_in.id, seq=icmp_in.seq)/icmp_in[Raw]
#                                     ICMP(type=0, id=icmp_in.id, seq=icmp_in.seq)
#                                     Raw("0" * 32)
#             rep.show2()
            self.sock.sendto(str(rep), (endp_ip, map_in["vteps"][endp_ip]) )

#         pass

    def _regist_l3cache(self, vni, host, endp_ip):
#         vni_c, host_c, tout_c = self.l3cache[host]
        tout = time.time() + TIMEOUT_L3CACHE
        self.l3cache[host] = (int(vni), endp_ip, tout) 
#         self.l3cache[(int(vni), host)] = (endp_ip, tout)

        msg = L3CacheMsg(code=MsgCode.set, vni=int(vni), host=host, \
                            vtep=endp_ip, timeout=tout)
        
        self.sock.sendto(str(msg), ('127.0.0.1', PORT_BIND_CACHE) )
        
        debug_info("local cache was updated : {0}".format( \
                                                str(self.l3cache) ), 2)


    def _lookup_longest_subnet(self, ip_dst):
        
        try:
            f1 = lambda (vni, dic): smallest_matching_cidr(ip_dst, dic["subnet"]) is not None
            mtchs = {dic["subnet"] : vni for (vni, dic) in filter(f1, self.maps.items()) }
            
            if not len(mtchs):
                debug_info("No route was matched.", 2)
                return None
        
        except KeyError as excpt:
            debug_info("Routing lookup encoutered an error : {0}".format(excpt), 3)
            return None
            
        return mtchs[smallest_matching_cidr(ip_dst, mtchs.keys())]
#         return self.maps[smallest_matching_cidr(ip_dst, mtchs.keys())]
#         f2 = lambda (vni, dic): ()

    def _arp_request(self, vni, ip_dst):
        debug_info("This is a stab of _arp_request method.", 2)


    def _lookup_l3cache(self, ip_dst):
        
        vni, vtep, tout = self.l3cache[ip_dst]
#         vtep, tout = self.l3cache[(vni, pdu[IP_Stop].dst)]
        
        if vtep is None:
            debug_info("No local l3cache was found.", 1)
            vni, vtep, tout = self._query_remote_cache(ip_dst)
        
        else:
            ts = time.time()
            
            if tout <= ts: 
                del self.l3cache[ip_dst]
    #             self._query_remote_cache(vni, pdu)
                vni, vtep, tout = (None, ActionCode.arp, None)
#                 tout = 0.0
            
            elif tout <= ts + INTERVAL_REFRESH:
                self._regist_l3cache(vni, ip_dst, vtep)
#                 ts = ts + TIMEOUT_L3CACHE
#                 self.l3cache[(vni, pdu[IP_Stop].dst)] = (vtep, ts)
        # a valid local cache was found
        debug_info("The result of cache looking up : {0}".format((vni, vtep, tout) ), 2)
        return (vni, vtep, tout)


    def _query_remote_cache(self, ip_dst):
        
        ref = randint(1, MAX_REFID)
        req = L3CacheMsg(code=MsgCode.get, ref=ref, host=ip_dst)
#         req = L3CacheMsg(code=MsgCode.get, ref=ref, vni=vni, host=ip_dst)
        
        cache = (None, ActionCode.arp, None)
#         cache = None
        try:
            self.sock.sendto(str(req), ("127.0.0.1", PORT_BIND_CACHE))

            self.sock.settimeout(TIMEOUT_RECV_CACHE)
            rep, _server = self.sock.recvfrom(LEN_MSGSTRUCT)
            msg = L3CacheMsg(rep)
            
            if msg.code != MsgCode.arp:
                cache = (msg.vni, msg.vtep, msg.timeout)
            
            else:
                debug_info("No remote cache was found. Fallback to ARP resolution.", 2)


        except socket.timeout as excpt:
            print excpt
            debug_info("Socket timeout occurred. Fallback to ARP resolution.", 2)
#             cache = (ActionCode.arp, None)
        return cache


class L3CacheServer(Process):
    
    def __init__(self, port):
        super(L3CacheServer, self).__init__()

        self.daemon = True
        self.port = port
        
        self.l3cache = defaultdict(lambda: (0, "0.0.0.0", 0.0) )
#         self.set_cache_timeout()
#     def set_cache_timeout(self, secs=300):
#         self.intvl_tout = secs
# #         self.timeout = tdelta(seconds=secs)

    def run(self):

        debug_info("{0} starts. : pid = {1}".format(current_process().name, \
                                                    current_process().pid ), 1)
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ) as \
                    self.sock:
                
                self.sock.bind( ("", self.port) )
            
                try:   
                    while True:
                        msg, client = self.sock.recvfrom(LEN_MSGSTRUCT)
                        msg = L3CacheMsg(msg)
                        
                        if msg.code == MsgCode.set:
                            # process set message
                            self._process_set(msg)
#                             self.l3cache[(msg.vni, msg.host)] = (msg.vtep, msg.timeout)
#                             debug_info("remote cache was updated : {0}".format( \
#                                                             str(self.l3cache) ), 2)
                        else:
                            # process query request
                            self._process_get(msg, client)
#                             vtep, tout = self.l3cache[(msg.vni, msg.host)]
#                             if tout <= time.time():
#                                 # remove obsolete cache
#                                 del self.l3cache[(msg.vin, msg.host)]
#                                 vtep = ActionCode.flood
#                                 tout = 0.0
#                             
#                             rep = L3CacheMsg(code=MsgCode.set, vni=msg.vni, host=msg.host, 
#                                             vtep=vtep, timeout=tout)
#                             self.sock.sendto(str(rep), client)
#                             
#                             debug_info("replyed : {0}".format(rep), 2)
                            
                
                except KeyboardInterrupt as excpt:
                    debug_info("Keyboard Interrupt occur. Program will exit.", 3)
                    sys.exit(0)
                
                except Exception as excpt:
                    debug_info("Encontered an unknown error!", 3)
                    print excpt
                    sys.exit(1)

        except socket.error as excpt:
            print(excpt)
            sys.exit(1)


    def _process_set(self, msg):
        self.l3cache[msg.host] = (msg.vni, msg.vtep, msg.timeout)
        debug_info("remote cache was updated : {0}".format( \
                                                        str(self.l3cache) ), 2)


    def _process_get(self, msg, client):
#         if msg.host in self.l3cache
        code = MsgCode.set
        vni, vtep, tout = self.l3cache[msg.host]
        if tout <= time.time():
            # remove obsolete cache
            del self.l3cache[msg.host]
            vni, vtep, tout = self.l3cache[msg.host]
            code = MsgCode.arp
#             vni, vtep, tout = (0, ActionCode.arp, 0.0)
        
        rep = L3CacheMsg(code=code, vni=vni, host=msg.host, 
                        vtep=vtep, timeout=tout)
        self.sock.sendto(str(rep), client)
#         debug_info("replyed : {0}".format(rep), 2)


def server_loop(srcip, lport, cache, maps):
    
    try:
        print(str(maps) )
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ) as sock_rcv:
            sock_rcv.bind( (srcip, lport) )
        
            debug_info("Server starts listening on {0}:{1}".format(srcip, lport), 2)
#             sock_rcv.listen(BUFFLEN_RECV)
            
            procs = []
            n_proc = min(cpu_count(), 8)
#             n_proc = 1
            
            conn_q = deque()
            
            try:
                for c in xrange(n_proc):
                    conns = Pipe(False)
                    conn_q.append(conns)
                    procs.append(PduProcessor(conns, maps.copy()) )
#                     conns = Pipe(False)
#                     conn_q.append(conns)
#                     procs.append(Process(target=vxpdu_handler, args=(conns, maps.copy() )) )
                
                for c in xrange(n_proc):
                    p = procs[c]
#                     p.daemon = True
#                     debug_info("{0} starts.".format(p.name),2)
                    p.start()
                    conn_q[c][0].close()
                
                srv_cache = L3CacheServer(cache)
                srv_cache.start()
            
            except Exception as excpt:
                print(excpt)
                sys.exit(1)

            try:            
                while True:
                    udp_data, endp = sock_rcv.recvfrom(BITELEN_RECV)
                    
                    conns = conn_q[0]
                    conn_q.rotate()
                    
#                     conns[1].send(udp_data)
                    conns[1].send( (udp_data, endp) )
#                     sock_clnt, addr = sock_rcv.accept()
#                     debug_info("Connection from {0}:{1} was accepted".format(addr[0], addr[1]), 1)
                    
#                     thrd_prxy = Process(target=proxy_handler,
#                                                   args=(sock_clnt, dstip, dport, is_recvfirst))
    #                 threads.append(thrd_prxy)
#                     thrd_prxy.start()
                
            except KeyboardInterrupt as excpt:
                # print(excpt)
                debug_info("Keyboard Interrupt occur. Program will exit.", 3)
                sys.exit(0)
                
    except socket.error as excpt:
        print(excpt)
        sys.exit(1)


def debug_info (msg, pri=1):
    
    print("[" + ("*" * pri) + "] " + msg)


def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x))  for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.'  for x in s])
        result.append( b"%04X   %-*s   %s" % (i, length*(digits + 1), hexa, text) )

    print b'\n'.join(result)


def is_valid_ipv4(ipv4):

    res = True
    try:
        a, b, c, d = map(lambda x: int(x), ipv4.split('.'))
        if (a < 0 or a > 255 or b < 0 or b > 255 or c < 0 or c > 255 or d < 0 or d > 255):
            res = False
    except ValueError:
        res = False

    return res


def is_valid_vni(vni):
    
    res = True
    try:
        if 0 >= vni or vni >= 2 ** 24:
            res = False
    except ValueError:
        res = False

    return res


def get_parser():
    
    desc = "Vxlan Router"
    parser = argparse.ArgumentParser(description=desc)
    
    parser.add_argument("-l", "--lport", dest="lport", type=int, required=False, default=PORT_DST_VXLAN)
    parser.add_argument("-s", "--srcip", dest="srcip", type=str, required=False, default=ADDRESS_BIND)
    parser.add_argument("--cache", dest="cache", type=int, required=False, default=PORT_BIND_CACHE)
    parser.add_argument("-c", "--config", dest="config", type=str, required=True)
   
    return parser


def parse_config(filepath):
    
    mac_base_int = int(get_if_hwaddr(linux.get_if_list()[0]).replace(":", ""), 16)
#     mac_base_int = [int(sec, 16) for sec in get_if_hwaddr().split(":")]
    attrs_valid = set(["vni", "subnet", "gw_ip", "vteps"])
#     attrs_valid = set(["vlan", "vni", "subnet", "gw_ip"])
    
    try:
        with open(filepath) as f:
            maps = json.load(f)
            for m in maps:
                assert set(m.keys() ) == attrs_valid, "Invalid json key/value was discovered."

                m["subnet"] = IPNetwork(m["subnet"])
                m["gw_ip"] = IPAddress(m["gw_ip"])
                is_inc = smallest_matching_cidr(m["gw_ip"], m["subnet"])
                assert is_inc is not None, "The subnet and gw_ip mismatch."
                
                assert all( [is_valid_ipv4(vtep[0]) for vtep in m["vteps"].items() ] ), \
                    "There are some invalid representations of IPv4 address."
                
                assert is_valid_vni(m["vni"]), "Out of the valid VNI range. (0 < VNI < 2 ** 24)"
                mac_int = (mac_base_int + m["vni"]) % MAC_MODULER
                mac_hex = "{0:012x}".format(mac_int)
                m["hwaddr"] = ":".join( [mac_hex[idx:idx+2] for idx in xrange(len(mac_hex) ) if idx % 2 == 0] )
#                 mac_int[-1] = (mac_int[-1] + m["vni"]) % 256
#                 m["hwaddr"] = ":".join( ["%02x" % sec for sec in mac_int] )
                
        maps = { m["vni"] : m for m in maps}
        return maps

    except AssertionError as excpt:
        print excpt
        print("Program exits.")
        sys.exit(1)
        
    except Exception as excpt:
        print excpt
        sys.exit(1)


def main ():
    
    parser = get_parser()
    args = parser.parse_args()
    
    kwargs = vars(args)
    maps = parse_config(kwargs["config"])
    kwargs["maps"] = maps

    del kwargs["config"]
    server_loop(**kwargs)
    
    exit(0)


if __name__ == "__main__":
    main()

