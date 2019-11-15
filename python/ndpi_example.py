#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: ndpi_example.py
This file is part of nDPI.

Copyright (C) 2011-19 - ntop.org
Copyright (C) 2019 - Zied Aouini <aouinizied@gmail.com> (Incremental improvements)

nDPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nDPI is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nDPI.
If not, see <http://www.gnu.org/licenses/>.
"""

from ndpi_typestruct import *
from ctypes import *
from scapy.all import *
import sys

# ------- return type & pcapstruct to declare -------


class WorkFlow(Structure):
    _fields_ = [("src_ip", c_uint32),
                ("dst_ip", c_uint32),
                ("src_port", c_uint16),
                ("dst_port", c_uint16),
                ("protocol", c_uint8),
                ("packets", c_uint32),
                ("detected_protocol", NDPIProtocol),
                ("detection_completed", c_uint8),
                ("id", c_uint32),
                ("src_id", POINTER(NDPIIdStruct)),
                ("dst_id", POINTER(NDPIIdStruct)),
                ("flow", POINTER(NDPIFlowStruct))]


CMCFUN = CFUNCTYPE(c_int, c_void_p, c_void_p)
GUESS = CFUNCTYPE(None, c_void_p, c_int32, c_int, c_void_p)
FREE = CFUNCTYPE(None, c_void_p)


def node_proto_guess_walker(nodo, which, depth, user_data):
    global ndpi_info_mod

    flow = cast(nodo, POINTER(POINTER(WorkFlow))).contents.contents
    if which == 0 or which == 3:  # execute only preorder operation of the tree
        if flow.detection_completed == 0:  # order for tree operation
            flow.detected_protocol = ndpi.ndpi_detection_giveup(ndpi_info_mod,
                                                                flow.flow,
                                                                1,
                                                                cast(addressof(c_uint8(0)), POINTER(c_uint8)))
        count_protocol[flow.detected_protocol.app_protocol] += flow.packets


def py_cmp_fun(a, b):
    fa = cast(a, POINTER(WorkFlow))
    fb = cast(b, POINTER(WorkFlow))

    if fa.contents.src_ip < fb.contents.src_ip: return -1
    elif fa.contents.src_ip > fb.contents.src_ip: return 1
    if fa.contents.src_port < fb.contents.src_port: return -1
    elif fa.contents.src_port > fb.contents.src_port: return 1
    if fa.contents.dst_ip < fb.contents.dst_ip: return -1
    elif fa.contents.dst_ip > fb.contents.dst_ip: return 1
    if fa.contents.dst_port < fb.contents.dst_port: return -1
    elif fa.contents.dst_port > fb.contents.dst_port: return 1
    if fa.contents.protocol < fb.contents.protocol: return -1
    elif fa.contents.protocol > fb.contents.protocol: return 1
    return 0


def freer(a):
    pass


cmp_func = CMCFUN(py_cmp_fun)
guess_walker = GUESS(node_proto_guess_walker)
free_walk = FREE(freer)

# --------------------------------------

# number of analyzed packet
packet_number = 0
flow_count = 0
max_num_udp_dissected_pkts = 16
max_num_tcp_dissected_pkts = 10
flows_root = c_void_p(None)
flows_root_ref = pointer(flows_root)
count_protocol = (c_int32 * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + ndpi.ndpi_wrap_ndpi_max_num_custom_protocols() + 1))()
lista = []  # used to avoid impropriate memory deallocation from python


# check ndpi version
if ndpi.ndpi_get_api_version() != ndpi.ndpi_wrap_get_api_version():
    print("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n")
    sys.exit(-1)

# create data structure of ndpi
ndpi_info_mod = ndpi.ndpi_init_detection_module()
if ndpi_info_mod is None:
    sys.exit(-1)
else:
    ndpi_ndpi_finalize_initalization(ndpi_info_mod)


def ip2int(ip):
    """
    Convert an IP string to long and then c_uint32
    """
    packedIP = socket.inet_aton(ip)
    return int(struct.unpack("!I", packedIP)[0])


def get_flow(pkt):
    global flows_root
    global flows_root_ref
    global flow_count

    ip_packet = pkt[1]
    ip_protocol = ip_packet.proto
    transport_packet = None

    if ip_protocol == 6 or ip_protocol == 17:
        transport_packet = pkt[2]
    if transport_packet is not None:
        # to avoid two nodes in one binary tree for a flow
        ip_src = ip2int(ip_packet.src)
        ip_dst = ip2int(ip_packet.dst)
        src_port = transport_packet.sport
        dst_port = transport_packet.dport
    else:
        return None
    # set flows to correct type and data
    ndpi_flow = pointer(NDPIFlowStruct())
    memset(ndpi_flow, 0, sizeof(NDPIFlowStruct))
    if ip_src > ip_dst:
        flow = WorkFlow(ip_src, ip_dst, src_port, dst_port, int(ip_packet.proto), 0, NDPIProtocol(), 0, 0,
                        pointer(NDPIIdStruct()), pointer(NDPIIdStruct()), ndpi_flow)
    else:
        flow = WorkFlow(ip_dst, ip_src, dst_port, src_port, int(ip_packet.proto), 0, NDPIProtocol(), 0, 0,
                        pointer(NDPIIdStruct()), pointer(NDPIIdStruct()), ndpi_flow)
    flow_ref = pointer(flow)
    res = ndpi.ndpi_tfind(flow_ref, flows_root_ref, cmp_func)
    if res is None:
        ndpi.ndpi_tsearch(flow_ref, pointer(flows_root), cmp_func)  # add
        lista.append(flow)
        flow_count += 1
        return pointer(flow)
    flow = cast(res, POINTER(POINTER(WorkFlow))).contents
    return flow


def packetcaptured(pkt):
    global packet_number
    global ndpi_info_mod

    flow = None
    h = PcapPktHdr()

    # getting flow
    try:
        flow = get_flow(pkt)
    except AttributeError:
        pass  # ignore packet
    if flow is None: return

    # filling pcap_pkthdr
    h.len = h.caplen = len(pkt)
    h.ts.tv_sec = int(pkt["IP"].time/1000000)
    h.ts.tv_usec = int(pkt["IP"].time)

    # real work
    if int(pkt[1].frag) == 0:  # not fragmented packet
        flow.contents.packets += 1
        packet_number += 1
        # get ndpi_iphdr address
        iphdr_addr = cast(c_char_p(pkt[1].build()), c_void_p)
        ndpi_flow = flow.contents.flow

        if flow.contents.detection_completed is 0:
            flow.contents.detected_protocol = ndpi.ndpi_detection_process_packet(ndpi_info_mod,
                                                                                 ndpi_flow,
                                                                                 cast(iphdr_addr, POINTER(c_uint8)),
                                                                                 int(pkt[1].len),
                                                                                 h.ts.tv_usec,
                                                                                 flow.contents.src_id,
                                                                                 flow.contents.dst_id)

            flow1 = flow.contents.detected_protocol

            valid = False

            if flow.contents.protocol == 6: valid = flow.contents.packets > max_num_tcp_dissected_pkts
            elif flow.contents.protocol == 17: valid = flow.contents.packets > max_num_udp_dissected_pkts

            # should we continue anylizing packet or not?
            if valid or flow1.app_protocol is not 0:
                if valid or flow1.master_protocol is not 91:  # or # 91 is NDPI_PROTOCOL_TLS
                    flow.contents.detection_completed = 1  # protocol found
                    if flow1.app_protocol is 0:
                        flow.contents.detected_protocol = ndpi.ndpi_detection_giveup(ndpi_info_mod,
                                                                                     ndpi_flow,
                                                                                     1,
                                                                                     cast(addressof(c_uint8(0)),
                                                                                          POINTER(c_uint8)))


def result():
    global flows_root_ref
    global ndpi_info_mod
    print('\nnumber of analyzed packet: ' + str(packet_number))
    print('number of flows: ' + str(flow_count))

    ndpi.ndpi_twalk(flows_root_ref.contents, guess_walker, None)

    print('\nDetected protocols:')
    for i in range(0, ndpi.ndpi_get_num_supported_protocols(ndpi_info_mod)):
        if count_protocol[i] > 0:
            print("{}: {} packets".format(
                cast(ndpi.ndpi_get_proto_name(ndpi_info_mod, i), c_char_p).value.decode('utf-8'),
                str(count_protocol[i])))


def free(ndpi_struct):
    ndpi.ndpi_tdestroy(flows_root, free_walk)
    ndpi.ndpi_exit_detection_module(ndpi_struct)


def initialize(ndpi_struct):
    all = NDPIProtocolBitMask()
    ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL(pointer(all))
    ndpi.ndpi_set_protocol_detection_bitmask2(ndpi_struct, pointer(all))


print('Using nDPI ' + cast(ndpi.ndpi_revision(), c_char_p).value.decode("utf-8"))

initialize(ndpi_info_mod)

if len(sys.argv) != 2:
    print("\nUsage: ndpi_example.py <device>")
    sys.exit(0)

if "." in sys.argv[1]:
    print('Reading pcap from file ' + sys.argv[1] + '...')
    scapy_cap = None
    try:
        scapy_cap = rdpcap(sys.argv[1])
    except FileNotFoundError:
        print("\nFile not found")
    except Scapy_Exception:
        print("\nBad pcap")
    else:
        for packet in scapy_cap:
            packetcaptured(packet)
else:
    print('Capturing live traffic from device ' + sys.argv[1] + '...')
    try:
        sniff(iface=sys.argv[1], prn=packetcaptured)
    except KeyboardInterrupt:
        print('\nInterrupted\n')
    except PermissionError:
        sys.exit('\nRoot privilege required for live capture on interface: {}\n'.format(sys.argv[1]))


result()
free(ndpi_info_mod)
