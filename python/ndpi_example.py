"""
------------------------------------------------------------------------------------------------------------------------
ndpi_example.py
Copyright (C) 2011-22 - ntop.org
This file is part of nDPI, an open source deep packet inspection library.
nDPI is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
nDPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

from collections import namedtuple
from ndpi import NDPI, NDPIFlow, ffi
import argparse
import socket
import dpkt


FLOW_KEY = "{} {}:{} <-> {}:{}"
FLOW_STR = "   {} {} [protocol:{}] [category:{}] [confidence:{}] [{} packets/{} bytes]"


PROTOCOL_UNKNWON = 0


class Flow(object):
    __slots__ = ("index",
                 "pkts",
                 "bytes",
                 "detected_protocol",
                 "ndpi_flow")

    def __init__(self):
        self.pkts = 0
        self.detected_protocol = None
        self.bytes = 0
        self.ndpi_flow = None


ppacket = namedtuple('ParsedPacket', ['src_ip',
                                      'src_port',
                                      'dst_ip',
                                      'dst_port',
                                      'protocol',
                                      'ip_version',
                                      'ip_bytes'])


def inet_to_str(inet):
    """ get string representation of IP address """
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def parse_packet(pkt):
    """ parse packet and extract 5 tuple and IP bytes """
    try:
        l2 = dpkt.ethernet.Ethernet(pkt)
        if isinstance(l2.data, dpkt.ip.IP):
            ip_version = 4
        elif isinstance(l2.data, dpkt.ip6.IP6):
            ip_version = 6
        else:
            return
    except dpkt.dpkt.NeedData:
        return

    l3 = l2.data
    stop_decoding = False
    while not stop_decoding:
        if isinstance(l3.data, dpkt.tcp.TCP):
            l4 = l3.data
            proto = "TCP"
            stop_decoding = True
        elif isinstance(l3.data, dpkt.udp.UDP):
            l4 = l3.data
            proto = "UDP"
            stop_decoding = True
        elif isinstance(l3.data, dpkt.ip6.IP6):
            l3 = l3.data
        else:
            return

    return ppacket(src_ip=inet_to_str(l3.src), src_port=l4.sport,
                   dst_ip=inet_to_str(l3.dst), dst_port=l4.dport,
                   protocol=proto, ip_version=ip_version,
                   ip_bytes=bytes(l3))


def ppkt_to_flow_key(ppkt):
    """ create a consistent direction agnostic flow keyfrom a parsed packet """
    if ppkt.src_ip < ppkt.dst_ip:
        k = FLOW_KEY.format(ppkt.protocol, ppkt.src_ip, ppkt.src_port, ppkt.dst_ip, ppkt.dst_port)
    else:
        if ppkt.src_ip == ppkt.dst_ip:
            if ppkt.src_port <= ppkt.dst_port:
                k = FLOW_KEY.format(ppkt.protocol, ppkt.src_ip, ppkt.src_port, ppkt.dst_ip, ppkt.dst_port)
            else:
                k = FLOW_KEY.format(ppkt.protocol, ppkt.dst_ip, ppkt.dst_port, ppkt.src_ip, ppkt.src_port)
        else:
            k = FLOW_KEY.format(ppkt.protocol, ppkt.dst_ip, ppkt.dst_port, ppkt.src_ip, ppkt.src_port)
    return k


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="input pcap file path")
    parser.add_argument('-u', '--include-unknowns', action='store_true')
    return parser.parse_args()


if __name__ == "__main__":
    nDPI = NDPI()  # As simple as that. :)
    flow_cache = {}  # We store the flows in a dictionary.
    flow_count = 0  # Flow counter
    print("Using nDPI {}".format(nDPI.revision))
    args = parse_arguments()

    with open(args.input, 'rb') as pcap_file:
        capture = dpkt.pcap.Reader(pcap_file)  # We use dpkt pcap capture handler
        for time, packet in capture:
            time_ms = int(time * 1000) # Convert packet timestamp to milliseconds
            ppkt = parse_packet(packet)
            if ppkt is not None:  # If we succeed to parse the packet
                key = ppkt_to_flow_key(ppkt)
                try:  # Try a Flow update
                    flow = flow_cache[key]
                    flow.detected_protocol = nDPI.process_packet(flow.ndpi_flow, ppkt.ip_bytes, time_ms, ffi.NULL)
                    flow.pkts += 1
                    flow.bytes += len(packet)
                except KeyError:  # New Flow
                    flow = Flow()
                    flow.index = flow_count
                    flow_count += 1
                    flow.ndpi_flow = NDPIFlow()  # We create an nDPIFlow object per Flow
                    flow.detected_protocol = nDPI.process_packet(flow.ndpi_flow, ppkt.ip_bytes, time_ms, ffi.NULL)
                    flow.pkts += 1
                    flow.bytes += len(packet)
                    flow_cache[key] = flow

    print(" Detected flows:")
    unknown_flows = []
    for key, flow in flow_cache.items():  # Iterate over all flows in flow cache
        if flow.detected_protocol.app_protocol == PROTOCOL_UNKNWON:  # Didn't succeed to identigy it using DPI
            flow.detected_protocol = nDPI.giveup(flow.ndpi_flow)  # We try to guess it (port matching, LRU, etc.)
        FLOW_EXPORT = FLOW_STR.format(flow.index,
                                      key,
                                      nDPI.protocol_name(flow.detected_protocol),
                                      nDPI.protocol_category_name(flow.detected_protocol),
                                      flow.ndpi_flow.confidence.name,
                                      flow.pkts,
                                      flow.bytes)
        if flow.detected_protocol.app_protocol != PROTOCOL_UNKNWON:
            print(FLOW_EXPORT)  # We start by printing detected flows
        else:
            # Format it for later
            unknown_flows.append(FLOW_EXPORT)
    if args.include_unknowns:
        print(" Unknown flows:")
        for unknown_flow in unknown_flows:  # Dump unknown flows
            print(unknown_flow)
