#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
file: ndpi_typestruct.py
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

from ctypes import CDLL, Structure, c_uint16, c_int, c_ulong, c_uint32, CFUNCTYPE, c_void_p, POINTER, c_char_p, c_uint8
from ctypes import c_char, c_uint, c_int16, c_longlong, c_size_t, Union, c_ubyte, c_uint64, c_int32, c_ushort, cast
from os.path import abspath, dirname
ndpi = CDLL(dirname(abspath(__file__)) + '/ndpi_wrap.so')

# ----------------------------------------------- Structures -----------------------------------------------------------


class NDPIDetectionModuleStruct(Structure):
    pass


class NDPIFlowStruct(Structure):
    pass


class NDPIProtocol(Structure):
    _fields_ = [
        ("master_protocol", c_uint16),
        ("app_protocol", c_uint16),
        ("category", c_int)
    ]


class TimeVal(Structure):
    _fields_ = [("tv_sec", c_ulong), ("tv_usec", c_ulong)]


class PcapPktHdr(Structure):
    _fields_ = [("ts", TimeVal), ("caplen", c_uint32), ("len", c_uint32)]


class NDPIMask(Structure):
    _fields_ = [("fds_bits", c_uint32)]


class NDPIProtocolBitMask(Structure):
    _fields_ = [("fds_bits", NDPIMask * ndpi.ndpi_wrap_ndpi_num_fds_bits())]


class NDPISubprotocolConfStruct(Structure):
    _fields_ = [("func", CFUNCTYPE(c_void_p, POINTER(NDPIDetectionModuleStruct), c_char_p, c_char_p, c_int))]


class NDPIAutoma(Structure):
    _fields_ = [
        ("ac_automa", c_void_p),
        ("ac_automa_finalized", c_uint8)
    ]


class NDPINode(Structure):
    pass


NDPINode._fields_ = [
    ('key', POINTER(c_char)),
    ('left', POINTER(NDPINode)),
    ('right', POINTER(NDPINode)),
]


class NDPICallFunctionStruct(Structure):
    _fields_ = [
        ("detection_bitmask", NDPIProtocolBitMask),
        ("excluded_protocol_bitmask", NDPIProtocolBitMask),
        ("ndpi_selection_bitmask", c_uint32),
        ("func", CFUNCTYPE(None, POINTER(NDPIDetectionModuleStruct), POINTER(NDPIFlowStruct))),
        ("detection_feature", c_uint8)
    ]


class NDPIProtoDefaultsT(Structure):
    _fields_ = [
        ("protoName", c_char_p),
        ("protoCategory", c_uint),
        ("can_have_a_subprotocol", c_uint8),
        ("protoId", c_uint16),
        ("protoIdx", c_uint16),
        ("master_tcp_protoId", c_uint16 * 2),
        ("master_udp_protoId", c_uint16 * 2),
        ("protoBreed", c_uint),
        ("func", CFUNCTYPE(None, POINTER(NDPIDetectionModuleStruct), POINTER(NDPIFlowStruct))),
    ]


class NDPIDefaultsPortsTreeNodeT(Structure):
    _fields_ = [
        ("proto", NDPIProtoDefaultsT),
        ("customUserProto", c_uint8),
        ("default_port", c_int16)
    ]


class SpinlockT(Structure):
    _fields_ = [("val", c_int)]


class AtomicT(Structure):
    _fields_ = [("counter", c_int)]


class TimeT(Structure):
    _fields_ = [("counter", c_longlong)]


class HashIp4pNode(Structure):
    pass


HashIp4pNode._fields_ = [
    ("next", POINTER(HashIp4pNode)),
    ("prev", POINTER(HashIp4pNode)),
    ("lchg", TimeT),
    ("port", c_uint16),
    ("count", c_uint16, 12),
    ("flag", c_uint16, 4),
    ("ip", c_uint32)
]


class HashIp4p(Structure):
    _fields_ = [
        ("top", POINTER(HashIp4pNode)),
        ("lock",SpinlockT),
        ("len", c_size_t)
    ]


class HashIp4pTable(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("ipv6", c_int),
        ("lock", SpinlockT),
        ("count", AtomicT),
        ("tbl", HashIp4p)
    ]


class BtAnnounce(Structure):
    _fields_ = [
        ("hash", c_uint32 * 5),
        ("ip", c_uint32 * 4),
        ("time", c_uint32),
        ("port", c_uint16),
        ("name_len", c_uint8),
        ("name", c_uint8 * 149)
    ]


class NDPILruCacheEntry(Structure):
    _fields_ = [
        ("key", c_uint32),
        ("is_full", c_uint32, 1),
        ("value", c_uint32, 16),
        ("pad", c_uint32, 15)
    ]


class NDPILruCache(Structure):
    _fields_ = [
        ("num_entries", c_uint32),
        ("entries", POINTER(NDPILruCacheEntry)),
    ]


class CacheEntry(Structure):
    pass


CacheEntry._fields_ = [
    ("item", c_void_p),
    ("item_size", c_uint32),
    ("prev", POINTER(CacheEntry)),
    ("next", POINTER(CacheEntry))
]


class CacheEntryMap(Structure):
    pass


CacheEntryMap._fields_ = [
    ("entry", POINTER(CacheEntry)),
    ("next", POINTER(CacheEntryMap)),
]


class Cache(Structure):
    _fields_ = [
        ("size", c_uint32),
        ("max_size", c_uint32),
        ("head", POINTER(CacheEntry)),
        ("tail", POINTER(CacheEntry)),
        ("map", POINTER(POINTER(CacheEntryMap)))
    ]


class CustomCategories(Structure):
    _fields_ = [
        ("hostnames", NDPIAutoma),
        ("hostnames_shadow", NDPIAutoma),
        ("ipAddresses", c_void_p),
        ("ipAddresses_shadow", c_void_p),
        ("categories_loaded", c_uint8),
    ]


NDPIDetectionModuleStruct._fields_ = [
    ("detection_bitmask", NDPIProtocolBitMask),
    ("generic_http_packet_bitmask", NDPIProtocolBitMask),
    ("current_ts", c_uint32),
    ("ticks_per_second", c_uint32),
    ("custom_category_labels",
     (c_char * ndpi.ndpi_wrap_num_custom_categories()) * ndpi.ndpi_wrap_custom_category_label_len()),
    ("callback_buffer", NDPICallFunctionStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size", c_uint32),
    ("callback_buffer_tcp_no_payload", NDPICallFunctionStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_tcp_no_payload", c_uint32),
    ("callback_buffer_tcp_payload", NDPICallFunctionStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_tcp_payload", c_uint32),
    ("callback_buffer_udp", NDPICallFunctionStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_udp", c_uint32),
    ("callback_buffer_non_tcp_udp", NDPICallFunctionStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_non_tcp_udp", c_uint32),
    ("tcpRoot", POINTER(NDPIDefaultsPortsTreeNodeT)),
    ("udpRoot", POINTER(NDPIDefaultsPortsTreeNodeT)),
    ("ndpi_log_level", c_uint),
    ("tcp_max_retransmission_window_size", c_uint32),
    ("directconnect_connection_ip_tick_timeout", c_uint32),
    ("subprotocol_conf", NDPISubprotocolConfStruct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("ndpi_num_supported_protocols", c_uint),
    ("ndpi_num_custom_protocols", c_uint),
    ("host_automa", NDPIAutoma),
    ("content_automa", NDPIAutoma),
    ("subprotocol_automa", NDPIAutoma),
    ("bigrams_automa", NDPIAutoma),
    ("impossible_bigrams_automa", NDPIAutoma),
    ("custom_categories", CustomCategories),
    ("protocols_ptree", c_void_p),
    ("irc_timeout", c_uint32),
    ("gnutella_timeout", c_uint32),
    ("battlefield_timeout", c_uint32),
    ("thunder_timeout", c_uint32),
    ("soulseek_connection_ip_tick_timeout", c_uint32),
    ("rtsp_connection_timeout", c_uint32),
    ("tvants_connection_timeout", c_uint32),
    ("orb_rstp_ts_timeout", c_uint32),
    ("yahoo_detect_http_connections", c_uint8),
    ("yahoo_lan_video_timeout", c_uint32),
    ("zattoo_connection_timeout", c_uint32),
    ("jabber_stun_timeout", c_uint32),
    ("jabber_file_transfer_timeout", c_uint32),
    ("ip_version_limit", c_uint8),
    ("bt_ht", POINTER(HashIp4pTable)),
    ("bt6_ht", POINTER(HashIp4pTable)),
    ("bt_ann", POINTER(BtAnnounce)),
    ("bt_ann_len", c_int),
    ("ookla_cache", POINTER(NDPILruCache)),
    ("tinc_cache", POINTER(Cache)),
    ("proto_defaults", NDPIProtoDefaultsT * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() +
                                             ndpi.ndpi_wrap_ndpi_max_num_custom_protocols())),
    ("http_dont_dissect_response", c_uint8, 1),
    ("dns_dont_dissect_response", c_uint8, 1),
    ("direction_detect_disable", c_uint8, 1),
    ("disable_metadata_export", c_uint8, 1),
    ("hyperscan", c_void_p)
]


class U6Addr(Union):
    _fields_ = [
        ("u6_addr8", c_uint8 * 16),
        ("u6_addr16", c_uint16 * 8),
        ("u6_addr32", c_uint32 * 4),
        ("u6_addr64", c_uint64 * 2)
    ]


class NDPIIn6Addr(Structure):
    _pack_ = 1
    _fields_ = [("u6_addr", U6Addr)]


class NDPIIpAddrT(Union):
    _fields_ = [
        ('ipv4', c_uint32),
        ('ipv4_u_int8_t', c_uint8 * 4),
        ('ipv6', NDPIIn6Addr),
    ]


class NDPIIdStruct(Structure):
    _fields_ = [
        ('detected_protocol_bitmask', NDPIProtocolBitMask),
        ('rtsp_ip_address', NDPIIpAddrT),
        ('yahoo_video_lan_timer', c_uint32),
        ('irc_port', c_uint16 * 8),
        ('last_time_port_used', c_uint32 * 8),
        ('irc_ts', c_uint32),
        ('gnutella_ts', c_uint32),
        ('battlefield_ts', c_uint32),
        ('thunder_ts', c_uint32),
        ('rtsp_timer', c_uint32),
        ('oscar_last_safe_access_time', c_uint32),
        ('zattoo_ts', c_uint32),
        ('jabber_stun_or_ft_ts', c_uint32),
        ('directconnect_last_safe_access_time', c_uint32),
        ('soulseek_last_safe_access_time', c_uint32),
        ('detected_directconnect_port', c_uint16),
        ('detected_directconnect_udp_port', c_uint16),
        ('detected_directconnect_ssl_port', c_uint16),
        ('bt_port_t', c_uint16 * 8),
        ('bt_port_u', c_uint16 * 8),
        ('jabber_voice_stun_port', c_uint16 * 6),
        ('jabber_file_transfer_port', c_uint16 * 2),
        ('detected_gnutella_port', c_uint16),
        ('detected_gnutella_udp_port1', c_uint16),
        ('detected_gnutella_udp_port2', c_uint16),
        ('soulseek_listen_port', c_uint16),
        ('irc_number_of_port', c_uint8),
        ('oscar_ssl_session_id', c_uint8 * 33),
        ('jabber_voice_stun_used_ports', c_uint8),
        ('yahoo_video_lan_dir', c_uint32, 1),
        ('yahoo_conf_logged_in', c_uint32, 1),
        ('yahoo_voice_conf_logged_in', c_uint32, 1),
        ('rtsp_ts_set', c_uint32, 1),
    ]


class NDPIFlowTcpStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ('smtp_command_bitmask', c_uint16),
        ('pop_command_bitmask', c_uint16),
        ('qq_nxt_len', c_uint16),
        ('wa_matched_so_far', c_uint8),
        ('tds_login_version', c_uint8),
        ('irc_stage', c_uint8),
        ('irc_port', c_uint8),
        ('h323_valid_packets', c_uint8),
        ('gnutella_msg_id', c_uint8 * 3),
        ('irc_3a_counter', c_uint32, 3),
        ('irc_stage2', c_uint32, 5),
        ('irc_direction', c_uint32, 2),
        ('irc_0x1000_full', c_uint32, 1),
        ('soulseek_stage', c_uint32, 2),
        ('tds_stage', c_uint32, 3),
        ('usenet_stage', c_uint32, 2),
        ('imesh_stage', c_uint32, 4),
        ('http_setup_dir', c_uint32, 2),
        ('http_stage', c_uint32, 2),
        ('http_empty_line_seen', c_uint32, 1),
        ('http_wait_for_retransmission', c_uint32, 1),
        ('gnutella_stage', c_uint32, 2),
        ('mms_stage', c_uint32, 2),
        ('yahoo_sip_comm', c_uint32, 1),
        ('yahoo_http_proxy_stage', c_uint32, 2),
        ('msn_stage', c_uint32, 3),
        ('msn_ssl_ft', c_uint32, 2),
        ('ssh_stage', c_uint32, 3),
        ('vnc_stage', c_uint32, 2),
        ('telnet_stage', c_uint32, 2),
        ('tls_srv_cert_fingerprint_ctx', c_void_p),
        ('tls_seen_client_cert', c_uint8, 1),
        ('tls_seen_server_cert', c_uint8, 1),
        ('tls_seen_certificate', c_uint8, 1),
        ('tls_srv_cert_fingerprint_found', c_uint8, 1),
        ('tls_srv_cert_fingerprint_processed', c_uint8, 1),
        ('tls_stage', c_uint8, 2),
        ('tls_record_offset', c_int16),
        ('tls_fingerprint_len', c_int16),
        ('tls_sha1_certificate_fingerprint', c_uint8 * 20),
        ('postgres_stage', c_uint32, 3),
        ('ddlink_server_direction', c_uint32, 1),
        ('seen_syn', c_uint32, 1),
        ('seen_syn_ack', c_uint32, 1),
        ('seen_ack', c_uint32, 1),
        ('icecast_stage', c_uint32, 1),
        ('dofus_stage', c_uint32, 1),
        ('fiesta_stage', c_uint32, 2),
        ('wow_stage', c_uint32, 2),
        ('veoh_tv_stage', c_uint32, 2),
        ('shoutcast_stage', c_uint32, 2),
        ('rtp_special_packets_seen', c_uint32, 1),
        ('mail_pop_stage', c_uint32, 2),
        ('mail_imap_stage', c_uint32, 3),
        ('mail_imap_starttls', c_uint32, 2),
        ('skype_packet_id', c_uint8),
        ('citrix_packet_id', c_uint8),
        ('lotus_notes_packet_id', c_uint8),
        ('teamviewer_stage', c_uint8),
        ('prev_zmq_pkt_len', c_uint8),
        ('prev_zmq_pkt', c_char * 10),
        ('ppstream_stage', c_uint32, 3),
        ('memcached_matches', c_uint8),
        ('nest_log_sink_matches', c_uint8),
    ]


class NDPIFlowUdpStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ('battlefield_msg_id', c_uint32),
        ('snmp_msg_id', c_uint32),
        ('battlefield_stage', c_uint32, 3),
        ('snmp_stage', c_uint32, 2),
        ('ppstream_stage', c_uint32, 3),
        ('halflife2_stage', c_uint32, 2),
        ('tftp_stage', c_uint32, 1),
        ('aimini_stage', c_uint32, 5),
        ('xbox_stage', c_uint32, 1),
        ('wsus_stage', c_uint32, 1),
        ('skype_packet_id', c_uint8),
        ('teamviewer_stage', c_uint8),
        ('eaq_pkt_id', c_uint8),
        ('eaq_sequence', c_uint32),
        ('rx_conn_epoch', c_uint32),
        ('rx_conn_id', c_uint32),
        ('memcached_matches', c_uint8),
        ('wireguard_stage', c_uint8),
        ('wireguard_peer_index', c_uint32 * 2),
    ]


class L4(Union):
    _fields_ = [("tcp", NDPIFlowTcpStruct), ("udp", NDPIFlowUdpStruct)]


class Http(Structure):
    _fields_ = [
        ("method", c_int),
        ("url", c_char_p),
        ("content_type", c_char_p),
        ("num_request_headers", c_uint8),
        ("num_response_headers", c_uint8),
        ("request_version", c_uint8),
        ("response_status_code", c_uint16),
    ]


class Dns(Structure):
    _fields_ = [
        ("num_queries", c_uint8),
        ("num_answers", c_uint8),
        ("reply_code", c_uint8),
        ("is_query", c_uint8),
        ("query_type", c_uint16),
        ("query_class", c_uint16),
        ("rsp_type", c_uint16),
        ("rsp_addr", NDPIIpAddrT)
    ]


class Ntp(Structure):
    _fields_ = [("request_code", c_uint8),
                ("version", c_uint8)]


class Kerberos(Structure):
    _fields_ = [("cname", c_char * 24),
                ("realm", c_char * 24)]


class Ssl(Structure):
    _fields_ = [
        ("ssl_version", c_uint16),
        ("client_certificate", c_char * 64),
        ("server_certificate", c_char * 64),
        ("server_organization",  c_char * 64),
        ('notBefore', c_uint32),
        ('notAfter', c_uint32),
        ("ja3_client", c_char * 33),
        ("ja3_server", c_char * 33),
        ("server_cipher", c_uint16),
        ("server_unsafe_cipher", c_int)
    ]


class Stun(Structure):
    _fields_ = [
        ("num_udp_pkts", c_uint8),
        ("num_processed_pkts", c_uint8),
        ("num_binding_requests", c_uint8),
    ]


class StunSsl(Structure):
    _fields_ = [("ssl", Ssl), ("stun", Stun)]


class Ssh(Structure):
    _fields_ = [
        ("client_signature", c_char * 48),
        ("server_signature", c_char * 48),
        ("hassh_client", c_char * 33),
        ("hassh_server", c_char * 33)
    ]


class Imo(Structure):
    _fields_ = [
        ("last_one_byte_pkt", c_uint8),
        ("last_byte", c_uint8)
    ]


class Mdns(Structure):
    _fields_ = [("answer", c_char * 96)]


class Ubntac2(Structure):
    _fields_ = [("version", c_char * 32)]


class Http2(Structure):
    _fields_ = [
        ("detected_os", c_char * 32),
        ("nat_ip", c_char * 24)
    ]


class Bittorrent(Structure):
    _fields_ = [("hash", c_char * 20)]


class Dhcp(Structure):
    _fields_ = [
        ("fingerprint", c_char * 48),
        ("class_ident", c_char * 48)
    ]


class Protos(Union):
    _fields_ = [
        ("dns", Dns),
        ("kerberos", Kerberos),
        ("stun_ssl", StunSsl),
        ("ssh", Ssh),
        ("imo", Imo),
        ("mdns", Mdns),
        ("ubntac2", Ubntac2),
        ("http", Http2),
        ("bittorrent", Bittorrent),
        ("dhcp", Dhcp)
    ]


class TincCacheEntry(Structure):
    _pack_ = 1
    _fields_ = [
        ('src_address', c_uint32),
        ('dst_address', c_uint32),
        ('dst_port', c_uint16),
    ]


class NDPIIntOneLineStruct(Structure):
    _fields_ = [
        ('ptr', POINTER(c_uint8)),
        ('len', c_uint16),
    ]


class NDPIIphdr(Structure):
    _pack_ = 1
    _fields_ = [
        ('ihl', c_uint8, 4),
        ('version', c_uint8, 4),
        ('tos', c_uint8),
        ('tot_len', c_uint16),
        ('id', c_uint16),
        ('frag_off', c_uint16),
        ('ttl', c_uint8),
        ('protocol', c_uint8),
        ('check', c_uint16),
        ('saddr', c_uint32),
        ('daddr', c_uint32)]


class NDPIIp6Hdrctl(Structure):
    _pack_ = 1
    _fields_ = [
        ('ip6_un1_flow', c_uint32),
        ('ip6_un1_plen', c_uint16),
        ('ip6_un1_nxt', c_uint8),
        ('ip6_un1_hlim', c_uint8),
    ]


class NDPIIpv6hdr(Structure):
    _pack_ = 1
    _fields_ = [
        ('ip6_hdr', NDPIIp6Hdrctl),
        ('ip6_src', NDPIIn6Addr),
        ('ip6_dst', NDPIIn6Addr),
    ]


class NDPITcpHdr(Structure):
    _pack_ = 1
    _fields_ = [
        ('source', c_uint16),
        ('dest', c_uint16),
        ('seq', c_uint32),
        ('ack_seq', c_uint32),
        ('res1', c_uint16, 4),
        ('doff', c_uint16, 4),
        ('fin', c_uint16, 1),
        ('syn', c_uint16, 1),
        ('rst', c_uint16, 1),
        ('psh', c_uint16, 1),
        ('ack', c_uint16, 1),
        ('urg', c_uint16, 1),
        ('ece', c_uint16, 1),
        ('cwr', c_uint16, 1),
        ('window', c_uint16),
        ('check', c_uint16),
        ('urg_ptr', c_uint16),
    ]


class NDPIUdpHdr(Structure):
    _pack_ = 1
    _fields_ = [
        ('source', c_uint16),
        ('dest', c_uint16),
        ('len', c_uint16),
        ('check', c_uint16),
    ]


class NDPIPacketStructStack(Structure):
    _pack_ = 1
    _fields_ = [
        ('detected_subprotocol_stack', c_uint8 * ndpi.ndpi_wrap_ndpi_procol_size()),
        ('protocol_stack_info', c_uint16)
    ]


class NDPIPacketStruct(Structure):
    _fields_ = [
        ('iph', POINTER(NDPIIphdr)),
        ('iphv6', POINTER(NDPIIpv6hdr)),
        ('tcp', POINTER(NDPITcpHdr)),
        ('udp', POINTER(NDPIUdpHdr)),
        ('generic_l4_ptr', POINTER(c_uint8)),
        ('payload', POINTER(c_uint8)),
        ('tick_timestamp', c_uint32),
        ('tick_timestamp_l', c_uint64),
        ('detected_protocol_stack', c_uint16 * ndpi.ndpi_wrap_ndpi_procol_size()),
        ('ndpi_packet_stack', NDPIPacketStructStack),
        ('line', NDPIIntOneLineStruct * 64),
        ('host_line', NDPIIntOneLineStruct),
        ('forwarded_line', NDPIIntOneLineStruct),
        ('referer_line', NDPIIntOneLineStruct),
        ('content_line', NDPIIntOneLineStruct),
        ('accept_line', NDPIIntOneLineStruct),
        ('user_agent_line', NDPIIntOneLineStruct),
        ('http_url_name', NDPIIntOneLineStruct),
        ('http_encoding', NDPIIntOneLineStruct),
        ('http_transfer_encoding', NDPIIntOneLineStruct),
        ('http_contentlen', NDPIIntOneLineStruct),
        ('http_cookie', NDPIIntOneLineStruct),
        ('http_origin', NDPIIntOneLineStruct),
        ('http_x_session_type', NDPIIntOneLineStruct),
        ('server_line', NDPIIntOneLineStruct),
        ('http_method', NDPIIntOneLineStruct),
        ('http_response', NDPIIntOneLineStruct),
        ('http_num_headers', c_uint8),
        ('l3_packet_len', c_uint16),
        ('l4_packet_len', c_uint16),
        ('payload_packet_len', c_uint16),
        ('actual_payload_len', c_uint16),
        ('num_retried_bytes', c_uint16),
        ('parsed_lines', c_uint16),
        ('parsed_unix_lines', c_uint16),
        ('empty_line_position', c_uint16),
        ('tcp_retransmission', c_uint8),
        ('l4_protocol', c_uint8),
        ('ssl_certificate_detected', c_uint8, 4),
        ('ssl_certificate_num_checks', c_uint8, 4),
        ('packet_lines_parsed_complete', c_uint8, 1),
        ('packet_direction', c_uint8, 1),
        ('empty_line_position_set', c_uint8, 1),
        ('pad', c_uint8, 5),
    ]


class NDPIFlowStructStack(Structure):
    _pack_ = 1
    _fields_ = [
        ("detected_protocol_stack", c_uint16 * ndpi.ndpi_wrap_ndpi_procol_size()),
        ("protocol_stack_info", c_uint16)
    ]


NDPIFlowStruct._fields_ = [
    ("ndpi_flow_stack", NDPIFlowStructStack),
    ("guessed_protocol_id", c_uint16),
    ("guessed_host_protocol_id", c_uint16),
    ("guessed_category", c_uint16),
    ("guessed_header_category", c_uint16),
    ("l4_proto", c_uint8),
    ("protocol_id_already_guessed", c_uint8, 1),
    ("host_already_guessed", c_uint8, 1),
    ("init_finished", c_uint8, 1),
    ("setup_packet_direction", c_uint8, 1),
    ("packet_direction", c_uint8, 1),
    ("check_extra_packets", c_uint8, 1),
    ("next_tcp_seq_nr", c_uint32 * 2),
    ("max_extra_packets_to_check", c_uint8),
    ("num_extra_packets_checked", c_uint8),
    ("num_processed_pkts", c_uint8),
    ("extra_packets_func", CFUNCTYPE(c_int, POINTER(NDPIDetectionModuleStruct), POINTER(NDPIFlowStruct))),
    ("l4", L4),
    ("server_id", POINTER(NDPIIdStruct)),
    ("host_server_name", c_ubyte * 256),
    ("http", Http),
    ("protos", Protos),
    ("excluded_protocol_bitmask", NDPIProtocolBitMask),
    ("category", c_int),
    ('redis_s2d_first_char', c_uint8),
    ('redis_d2s_first_char', c_uint8),
    ('packet_counter', c_uint16),
    ('packet_direction_counter', c_uint16 * 2),
    ('byte_counter', c_uint16 * 2),
    ('bittorrent_stage', c_uint8),
    ('directconnect_stage', c_uint8, 2),
    ('sip_yahoo_voice', c_uint8, 1),
    ('http_detected', c_uint8, 1),
    ('http_upper_protocol', c_uint16),
    ('http_lower_protocol', c_uint16),
    ('rtsprdt_stage', c_uint8, 2),
    ('rtsp_control_flow', c_uint8, 1),
    ('yahoo_detection_finished', c_uint8, 2),
    ('zattoo_stage', c_uint8, 3),
    ('qq_stage', c_uint8, 3),
    ('thunder_stage', c_uint8, 2),
    ('oscar_ssl_voice_stage', c_uint8, 3),
    ('oscar_video_voice', c_uint8, 1),
    ('florensia_stage', c_uint8, 1),
    ('socks5_stage', c_uint8, 2),
    ('socks4_stage', c_uint8, 2),
    ('edonkey_stage', c_uint8, 2),
    ('ftp_control_stage', c_uint8, 2),
    ('rtmp_stage', c_uint8, 2),
    ('pando_stage', c_uint8, 3),
    ('steam_stage1', c_uint16, 3),
    ('steam_stage2', c_uint16, 2),
    ('steam_stage3', c_uint16, 2),
    ('pplive_stage1', c_uint8, 3),
    ('pplive_stage2', c_uint8, 2),
    ('pplive_stage3', c_uint8, 2),
    ('starcraft_udp_stage', c_uint8, 3),
    ('ovpn_session_id', c_uint8 * 8),
    ('ovpn_counter', c_uint8),
    ('tinc_state', c_uint8),
    ('TincCacheEntry', TincCacheEntry),
    ('csgo_strid', c_uint8 * 18),
    ('csgo_state', c_uint8),
    ('csgo_s2', c_uint8),
    ('csgo_id2', c_uint32),
    ('kxun_counter', c_uint16),
    ('iqiyi_counter', c_uint16),
    ('packet', NDPIPacketStruct),
    ('flow', POINTER(NDPIFlowStruct)),
    ('src', POINTER(NDPIIdStruct)),
    ('dst', POINTER(NDPIIdStruct))
]

# ----------------------------------------------- nDPI APIs ------------------------------------------------------------

""" ndpi_detection_giveup: Function to be called before we give up with detection for a given flow.
                           This function reduces the NDPI_UNKNOWN_PROTOCOL detection. """
ndpi.ndpi_detection_giveup.restype = NDPIProtocol
ndpi.ndpi_detection_giveup.argtypes = [POINTER(NDPIDetectionModuleStruct),
                                      POINTER(NDPIFlowStruct), c_uint8,
                                      POINTER(c_uint8)]

""" ndpi_detection_process_packet: Processes one packet and returns the ID of the detected protocol.
                                   This is the MAIN PACKET PROCESSING FUNCTION. """
ndpi.ndpi_detection_process_packet.restype = NDPIProtocol
ndpi.ndpi_detection_process_packet.argtypes = [POINTER(NDPIDetectionModuleStruct),
                                               POINTER(NDPIFlowStruct),
                                               POINTER(c_ubyte),
                                               c_ushort,
                                               c_uint64,
                                               POINTER(NDPIIdStruct),
                                               POINTER(NDPIIdStruct)]

""" ndpi_ssl_version2str : Converts ssl version to readable string """
ndpi.ndpi_ssl_version2str.restype = c_char_p
ndpi.ndpi_ssl_version2str.argtypes = [c_int16, POINTER(c_uint8)]

""" ndpi_init_detection_module: Returns a new initialized detection module.
    Note that before you can use it you can still load hosts and do other things. As soon as you are ready to use 
    it do not forget to call first ndpi_finalize_initalization() """
ndpi.ndpi_init_detection_module.restype = POINTER(NDPIDetectionModuleStruct)


def ndpi_ndpi_finalize_initalization(detection_module):
    """ ndpi_finalize_initalization: Completes the initialization (ndpi_revision >= 3.1)"""
    if cast(ndpi.ndpi_revision(), c_char_p).value.decode("utf-8")[:3] >= '3.1':
        ndpi.ndpi_finalize_initalization.restype = c_void_p
        ndpi.ndpi_finalize_initalization.argtypes = [POINTER(NDPIDetectionModuleStruct)]
        return ndpi.ndpi_finalize_initalization(detection_module)
    else:
        # ignore it
        return None


""" ndpi_tfind: find a node, or return 0. """
ndpi.ndpi_tfind.restype = c_void_p

""" ndpi_tsearch: ftp://ftp.cc.uoc.gr/mirrors/OpenBSD/src/lib/libc/stdlib/tsearch.c
                  find or insert datum into search tree. """
ndpi.ndpi_tsearch.restype = c_void_p
ndpi.ndpi_tsearch.argtypes = [c_void_p, POINTER(c_void_p), CFUNCTYPE(c_int, c_void_p, c_void_p)]

""" ndpi_revision: Get the nDPI version release. """
ndpi.ndpi_revision.restype = c_void_p

""" ndpi_get_proto_name: Get the protocol name associated to the ID."""
ndpi.ndpi_get_proto_name.restype = c_void_p

""" ndpi_category_get_name: Get protocol category as string."""
ndpi.ndpi_category_get_name.restype = c_void_p

""" ndpi_get_num_supported_protocols: Get the total number of the supported protocols."""
ndpi.ndpi_get_num_supported_protocols.restype = c_uint

""" ndpi_wrap_NDPI_BITMASK_SET_ALL: memset((char *)(p), 0xFF, sizeof(*(p)))"""
ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL.argtypes = [POINTER(NDPIProtocolBitMask)]

""" ndpi_set_protocol_detection_bitmask2: Sets the protocol bitmask2."""
ndpi.ndpi_set_protocol_detection_bitmask2.argtypes = [POINTER(NDPIDetectionModuleStruct),
                                                      POINTER(NDPIProtocolBitMask)]

""" ndpi_twalk: Walk the nodes of a tree. """
ndpi.ndpi_twalk.argtypes = [c_void_p, CFUNCTYPE(None, c_void_p, c_int32, c_int, c_void_p), c_void_p]

""" ndpi_tdestroy: node destroy. """
ndpi.ndpi_tdestroy.argtypes = [c_void_p, CFUNCTYPE(None, c_void_p)]