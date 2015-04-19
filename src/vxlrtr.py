#! /usr/bin/env python

#
# Copyright 2015 Yoh Kamibayashi
#


from multiprocessing import Process, Pipe, cpu_count, current_process
from collections import deque

from contextlib import closing
import socket

import argparse
import json
from netaddr import IPAddress, IPNetwork, smallest_matching_cidr
import sys

# from scapy.data import *
from scapy.fields import ByteField, BitField
from scapy.layers.inet import IP, Ether, Packet, ARP
from scapy.data import ETHER_TYPES, IP_PROTOS

from scapy.arch import get_if_hwaddr
from scapy.arch.linux import get_if_list


PORT_DST_VXLAN = 4789
ADDRESS_BIND = ""

BUFFLEN_RECV = 10
BITELEN_RECV = 9000

MAC_MODULER = 2 ** 48



class RouterVxlan (object):
    
    def __init__ (self):
        pass


class IP_Stop(IP):
    
    def dissect(self, s):
        s = self.pre_dissect(s)
        s = self.do_dissect(s)
        s = self.post_dissect(s)
        
        payl,_pad = self.extract_padding(s)
        self.add_payload(payl)


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


class PduProcessor(Process):

    def __init__(self, pipes, maps):
        super(PduProcessor, self).__init__()
        
#         self.conn_r, self.conn_s = pipes
        self.pipes = pipes
        self.maps = maps
        
        self.l3cache = {}
    
    
    def run(self):

        debug_info("{0} starts.".format(current_process().name),2)
        
        conn_r, conn_s = self.pipes
        conn_s.close()
        
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ) \
                as self.sock:
            #     while True:
                while conn_r.poll() != None:
                    try:
    #                     udp_data= conn_r.recv()
                        udp_data, endp = conn_r.recv()
                        endp_ip, _endp_port = endp
    
                        print(str(endp) )
            #             hexdump(udp_data)
                        pdu = Vxlan(udp_data)
            #             pdu.show()
                        e_type = pdu[Ether_Stop].type
                        vni_in = pdu[Vxlan].vni
                        
                        map_in = self.maps[vni_in]
            
                        if e_type == ETHER_TYPES.ARP:
                            self.arp_reply(pdu, vni_in, map_in, endp_ip)
                        
                        elif e_type == ETHER_TYPES.IPv4:
                            debug_info("IP arrived.", 1)

                            if pdu[IP_Stop].dst != map_in["gw_ip"]:
                                # Routing process
                                pass
                            elif pdu[IP_Stop].proto == IP_PROTOS.icmp:
                                # Act like forwarding to loopback address
                                pass
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


    def arp_reply(self, pdu, vni_in, map_in, endp_ip):
        
        debug_info("ARP arrived.", 1)
        arp_in = pdu[ARP_Stop]
#         arp_in.show()
    #                 arp_targ = pdu[ARP_Stop].psdt
        if arp_in.pdst == str( map_in["gw_ip"] ):
            rep = Vxlan(vni=vni_in)/Ether(src=map_in["hwaddr"], \
                                        dst=arp_in.hwsrc)/ \
                                    ARP(op=ARP.is_at, hwdst=arp_in.hwsrc, \
                                        hwsrc=map_in["hwaddr"], pdst=arp_in.psrc, \
                                        psrc=arp_in.pdst)
                                    
            self.sock.sendto(str(rep), (endp_ip, map_in["vteps"][endp_ip]) )
    
    
    def icmp_reply(self):
        
        debug_info("ICMP arrived.", 1)

        pass


    def lookup_l3cache(self):
        pass


def server_loop(srcip, lport, maps):
    
    try:
        print(str(maps) )
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM) ) as sock_rcv:
            sock_rcv.bind( (srcip, lport) )
        
            debug_info("Server starts listening on {0}:{1}".format(srcip, lport), 2)
#             sock_rcv.listen(BUFFLEN_RECV)
            
            procs = []
#             n_proc = min(cpu_count(), 8)
            n_proc = 1
            
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
                    p.daemon = True
#                     debug_info("{0} starts.".format(p.name),2)
                    p.start()
                    conn_q[c][0].close()
            
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
    parser.add_argument("-c", "--config", dest="config", type=str, required=True)
   
    return parser


def parse_config(filepath):
    
    mac_base_int = int(get_if_hwaddr(get_if_list()[0]).replace(":", ""), 16)
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

