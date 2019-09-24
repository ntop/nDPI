#
# ndpi_typestruct.h
#
# Copyright (C) 2019 - ntop.org
#
# nDPI is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nDPI is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
#


import os
from ctypes import *

ndpi = CDLL('./ndpi_wrap.so')

# NDPI_SELECTION_BITMASK_PROTOCOL_SIZE = c_uint32
# ndpi_protocol_category_t, ndpi_protocol_breed_t e ndpi_log_level_t are enum and are imported as c_int

class ndpi_detection_module_struct(Structure):
    pass

class ndpi_flow_struct(Structure):
    pass

class ndpi_protocol(Structure):
    _fields_ = [
        ("master_protocol", c_uint16),
        ("app_protocol", c_uint16),
        ("category", c_int)

    ]

class timeval(Structure):
    _fields_ = [("tv_sec", c_ulong), ("tv_usec", c_ulong)]

class pcap_pkthdr(Structure):
    _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]

#dal file ../src/include/ndpi_tydedefs.h
class ndpi_ndpi_mask(Structure):
    _fields_ = [("fds_bits", c_uint32)]

class NDPI_PROTOCOL_BITMASK(Structure):
    _fields_ = [("fds_bits", ndpi_ndpi_mask * ndpi.ndpi_wrap_ndpi_num_fds_bits())]

class ndpi_subprotocol_conf_struct(Structure):
    _fields_ = [("func", CFUNCTYPE(c_void_p,POINTER(ndpi_detection_module_struct),c_char_p,c_char_p,c_int))]

class ndpi_automa(Structure):
    _fields_ = [
        ("ac_automa", c_void_p), #Real type is AC_AUTOMATA_t
        ("ac_automa_finalized", c_uint8)
    ]

class struct_node_t(Structure):
    pass
struct_node_t._fields_ = [
    ('key', POINTER(c_char)),
    ('left', POINTER(struct_node_t)),
    ('right', POINTER(struct_node_t)),
]

class ndpi_call_function_struct(Structure):
    _fields_ = [
        ("detection_bitmask", NDPI_PROTOCOL_BITMASK),
        ("excluded_protocol_bitmask",NDPI_PROTOCOL_BITMASK),
        ("ndpi_selection_bitmask", c_uint32),
        ("func", CFUNCTYPE(None, POINTER(ndpi_detection_module_struct), POINTER(ndpi_flow_struct))),
        ("detection_feature", c_uint8)
    ]

class ndpi_proto_defaults_t(Structure):
    _fields_ = [
        ("protoName", POINTER(c_char)),
        ("protoCategory",c_uint),
        ("can_have_a_subprotocol", c_uint8),
        ("protoId", c_uint16),
        ("protoIdx", c_uint16),
        ("master_tcp_protoId", c_uint16 * 2),
        ("master_udp_protoId", c_uint16 * 2),
        ("protoBreed", c_uint),
        ("func", CFUNCTYPE(None, POINTER(ndpi_detection_module_struct), POINTER(ndpi_flow_struct))),
    ]

class ndpi_default_ports_tree_node_t(Structure):
    _fields_ = [
        ("proto", ndpi_proto_defaults_t),
        ("customUserProto",c_uint8),
        ("default_port", c_int16)
    ]

# NDPI_PROTOCOL_BITTORRENT
class spinlock_t(Structure):
    _fields_ = [("val", c_int)] #missing volatile

class atomic_t(Structure):
    _fields_ = [("counter", c_int)] #missing volatile

class time_t(Structure):
    _fields_ = [("counter", c_longlong)] # piattaform dependent

class hash_ip4p_node(Structure):
    pass

hash_ip4p_node._fields_ = [
    ("next", POINTER(hash_ip4p_node)),
    ("prev", POINTER(hash_ip4p_node)),
    ("lchg", time_t),
    ("port", c_uint16),
    ("count", c_uint16, 12),
    ("flag", c_uint16, 4),
    ("ip", c_uint32)
]

class hash_ip4p(Structure):
    _fields_ = [
        ("top", POINTER(hash_ip4p_node)),
        ("lock",spinlock_t),
        ("len", c_size_t)
    ]

class hash_ip4p_table(Structure):
    _fields_ = [
        ("size", c_size_t),
        ("ipv6",c_int),
        ("lock", spinlock_t),
        ("count", atomic_t),
        ("tbl", hash_ip4p)
    ]

class bt_announce(Structure): # 192 bytes
    _fields_ = [
        ("hash", c_uint32 * 5),
        ("ip", c_uint32 * 4),
        ("time", c_uint32),
        ("port", c_uint16),
        ("name_len", c_uint8),
        ("name", c_uint8 * 149) # 149 bytes
    ]

class ndpi_lru_cache(Structure): # 192 bytes
    _fields_ = [
        ("num_entries", c_uint32),
        ("entries", POINTER(c_uint32)),
    ]

class cache_entry(Structure):
    pass

cache_entry._fields_ = [
    ("item", c_void_p),
    ("item_size", c_uint32),
    ("prev", POINTER(cache_entry)),
    ("next", POINTER(cache_entry))
]

class cache_entry_map(Structure):
    pass

cache_entry_map._fields_ = [
    ("entry", POINTER(cache_entry)),
    ("next", POINTER(cache_entry_map)),
]

class cache(Structure):  # 192 bytes
    _fields_ = [
        ("size", c_uint32),
        ("max_size", c_uint32),
        ("head", POINTER(cache_entry)),
        ("tail", POINTER(cache_entry)),
        ("map", POINTER(POINTER(cache_entry_map)))
    ]

class custom_categories(Structure):
    _fields_ =[
        #Hyperscam
        #("hostnames", POINTER(hs)),
        #("num_to_load", c_uint),
        #("to_load", POINTER(hs_list)),
        ("hostnames", ndpi_automa),
        ("hostnames_shadow", ndpi_automa),
        ("hostnames_hash", c_void_p),
        ("ipAddresses", c_void_p),
        ("ipAddresses_shadow", c_void_p), # Patricia
        ("categories_loaded", c_uint8),
    ]


ndpi_detection_module_struct._fields_ = [
    ("detection_bitmask", NDPI_PROTOCOL_BITMASK),
    ("generic_http_packet_bitmask", NDPI_PROTOCOL_BITMASK),

        ("current_ts", c_uint32),

        ("ticks_per_second", c_uint32),

        #("user_data", c_void_p), debug

        ("custom_category_labels", (c_char * ndpi.ndpi_wrap_num_custom_categories()) * ndpi.ndpi_wrap_custom_category_label_len()),

        #callback function buffer
        ("callback_buffer", ndpi_call_function_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size", c_uint32),

        ("callback_buffer_tcp_no_payload", ndpi_call_function_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_tcp_no_payload", c_uint32),

        ("callback_buffer_tcp_payload", ndpi_call_function_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_tcp_payload", c_uint32),

        ("callback_buffer_udp", ndpi_call_function_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_udp", c_uint32),

        ("callback_buffer_non_tcp_udp", ndpi_call_function_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),
    ("callback_buffer_size_non_tcp_udp", c_uint32),

        ("tcpRoot", POINTER(ndpi_default_ports_tree_node_t)),
    ("udpRoot", POINTER(ndpi_default_ports_tree_node_t)),

        ("ndpi_log_level", c_uint), #default error

    # ifdef NDPI_ENABLE_DEBUG_MESSAGES
    #debug callback, only set whendebug is used * /
    #ndpi_debug_function_ptr ndpi_debug_printf;
    #const char * ndpi_debug_print_file;
    #const char * ndpi_debug_print_function;
    #u_int32_t ndpi_debug_print_line;
    #NDPI_PROTOCOL_BITMASK debug_bitmask;
    # endif

    #misc parameters
        ("tcp_max_retransmission_window_size", c_uint32),

        ("directconnect_connection_ip_tick_timeout", c_uint32),

    #subprotocol registration handler
        ("subprotocol_conf", ndpi_subprotocol_conf_struct * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + 1)),

        ("ndpi_num_supported_protocols", c_uint),
    ("ndpi_num_custom_protocols", c_uint),

    #HTTP / DNS / HTTPS host matching * /
        ("host_automa", ndpi_automa), #Used for DNS / HTTPS
    ("content_automa", ndpi_automa), # Used for HTTP subprotocol_detection
    ("subprotocol_automa", ndpi_automa), # Used for HTTP subprotocol_detection
    ("bigrams_automa", ndpi_automa), #TOR
    ("impossible_bigrams_automa", ndpi_automa), # TOR

        ("custom_categories", custom_categories),
    #IP-based protocol detection
        ("protocols_ptree", c_void_p),

    #irc parameters
        ("irc_timeout", c_uint32),
    #gnutella parameters
        ("gnutella_timeout", c_uint32),
    #battlefield parameters
        ("battlefield_timeout", c_uint32),
    # thunder parameters
        ("thunder_timeout", c_uint32),
    # SoulSeek parameters
        ("soulseek_connection_ip_tick_timeout", c_uint32),
    # rtsp parameters
        ("rtsp_connection_timeout", c_uint32),
    # tvants parameters
        ("tvants_connection_timeout", c_uint32),
    # rstp
        ("orb_rstp_ts_timeout", c_uint32),
    # yahoo
        ("yahoo_detect_http_connections", c_uint8),
    ("yahoo_lan_video_timeout", c_uint32),
    ("zattoo_connection_timeout", c_uint32),
    ("jabber_stun_timeout", c_uint32),
    ("jabber_file_transfer_timeout", c_uint32),

    # ifdef NDPI_ENABLE_DEBUG_MESSAGES
    # define NDPI_IP_STRING_SIZE 40
    #char ip_string[NDPI_IP_STRING_SIZE];
    # endif

        ("ip_version_limit", c_uint8),
    #NDPI_PROTOCOL_BITTORRENT
        ("bt_ht", POINTER(hash_ip4p_table)),
    # ifdef NDPI_DETECTION_SUPPORT_IPV6
        ("bt6_ht", POINTER(hash_ip4p_table)),
    # endif

    # BT_ANNOUNCE
        ("bt_ann", POINTER(bt_announce)),
    ("bt_ann_len", c_int),

    # NDPI_PROTOCOL_OOKLA
        ("ookla_cache", POINTER(ndpi_lru_cache)),

    # NDPI_PROTOCOL_TINC
        ("tinc_cache", POINTER(cache)),

        ("proto_defaults", ndpi_proto_defaults_t * (ndpi.ndpi_wrap_ndpi_max_supported_protocols() + ndpi.ndpi_wrap_ndpi_max_num_custom_protocols())),

        ("http_dont_dissect_response", c_uint8, 1),
    ("dns_dont_dissect_response", c_uint8, 1),
    ("direction_detect_disable", c_uint8, 1), # disable internal detection of packet direction
    ("disable_metadata_export", c_uint8, 1), # No metadata is exported
    ("enable_category_substring_match", c_uint8, 1), # Default is perfect match

        ("hyperscan", c_void_p) # Intel Hyperscan
]

class u6_addr(Union): # 128-bit IP6 address
    _fields_ = [
        ("u6_addr8",c_uint8 * 16),
        ("u6_addr16",c_uint16 * 8),
        ("u6_addr32",c_uint32 * 4)
    ]

class ndpi_in6_addr(Structure):
    _fields_ = [("u6_addr", u6_addr)]


class ndpi_ip_addr_t(Union):
    _fields_ = [
        ('ipv4', c_uint32),
        ('ipv4_u_int8_t', c_uint8 * 4),
        ('ipv6', ndpi_in6_addr),
    ]

class ndpi_id_struct(Structure):
    _fields_ = [
        ('detected_protocol_bitmask', NDPI_PROTOCOL_BITMASK),
        ('rtsp_ip_address', ndpi_ip_addr_t),
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

#struct flow
class ndpi_flow_tcp_struct(Structure):
    _fields_ = [
        # NDPI_PROTOCOL_MAIL_SMTP
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
        ('ssl_seen_client_cert', c_uint8, 1),
        ('ssl_seen_server_cert', c_uint8, 1),
        ('ssl_seen_certificate', c_uint8, 1),
        ('ssl_stage', c_uint8, 2),
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
        ('prev_zmq_pkt', c_ubyte * 10),
        ('ppstream_stage', c_uint32, 3),
        ('memcached_matches', c_uint8),
        ('nest_log_sink_matches', c_uint8),
    ]

class ndpi_flow_udp_struct(Structure):
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
    ]

# the tcp / udp / other l4 value union used to reduce the number of bytes for tcp or udp protocol states
class l4(Union):
    _fields_ = [("tcp", ndpi_flow_tcp_struct),("udp", ndpi_flow_udp_struct)]

class http(Structure):
    _fields_ = [
        ("method", c_int),
        ("url", c_char_p),
        ("content_type", c_char_p),
        ("num_request_headers", c_uint8), ("num_response_headers", c_uint8),
        ("request_version", c_uint8), # 0=1.0 and 1=1.1. Create an enum for this?
        ("response_status_code", c_uint16), # 200, 404, etc.
    ]

class dns(Structure): # the only fields useful for nDPI and ntopng
    _fields_ = [
        ("num_queries", c_uint8), ("num_answers", c_uint8), ("reply_code", c_uint8),
        ("query_type", c_uint16), ("query_class", c_uint16), ("rsp_type", c_uint16),
        ("rsp_addr", ndpi_ip_addr_t) # The first address in a DNS response packet
    ]

class ntp(Structure):
    _fields_ = [("request_code", c_uint8), ("version", c_uint8)]

class ssl(Structure):
    _fields_ = [
        ("ssl_version", c_uint8),
        ("client_certificate", c_char * 64), ("server_certificate", c_char * 64), ("server_organization",  c_char * 64),
        ("ja3_client", c_char * 33), ("ja3_server", c_char * 33),
        ("server_cipher", c_uint16),
        ("server_unsafe_cipher", c_int)
    ]

class stun(Structure):
    _fields_ = [
        ("num_udp_pkts", c_uint8),
        ("num_processed_pkts", c_uint8),
        ("num_binding_requests", c_uint8),
        ("is_skype", c_uint8)
    ]

class stun_ssl(Union): # We can have STUN over SSL thus they need to live together
    _fields_ = [("ssl", ssl),("stun",stun)]

class ssh(Structure):
    _fields_ = [("client_signature", c_char * 48), ("server_signature", c_char * 48)]

class mdns(Structure):
    _fields_ = [("answer", c_char * 96)]

class ubntac2(Structure):
    _fields_ = [("version", c_char * 96)]

class http2(Structure):
    _fields_ = [
        ("detected_os", c_ubyte * 32), #Via HTTP User-Agent
        ("nat_ip", c_ubyte * 24)
    ]

class bittorrent(Structure): # Bittorrent hash
    _fields_ = [ ("hash", c_ubyte * 20) ]

class dhcp(Structure):
    _fields_ = [
        ("fingerprint", c_char * 48),
        ("nat_ip", c_char * 48)
    ]

class protos(Union):
    _fields_ = [
        ("dns", dns),
        ("ntp", ntp),
        ("stun_ssl", stun_ssl),
        ("ssh", ssh),
        ("mdns", mdns),
        ("ubntac2", ubntac2),
        ("http", http2),
        ("bittorrent", bittorrent),
        ("dhcp", dhcp)
    ]

class tinc_cache_entry(Structure):
    _fields_ = [
        ('src_address', c_uint32),
        ('dst_address', c_uint32),
        ('dst_port', c_uint16),
    ]

class struct_ndpi_int_one_line_struct(Structure):
    _fields_ = [
        ('ptr', POINTER(c_uint8)),
        ('len', c_uint16),
    ]

class struct_ndpi_iphdr_little_end(Structure):
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

class struct_ndpi_ip6_hdrctl(Structure):
    _fields_ = [
        ('ip6_un1_flow', c_uint32),
        ('ip6_un1_plen', c_uint16),
        ('ip6_un1_nxt', c_uint8),
        ('ip6_un1_hlim', c_uint8),
    ]

class struct_ndpi_ipv6hdr(Structure):
    _fields_ = [
        ('ip6_hdr', struct_ndpi_ip6_hdrctl),
        ('ip6_src', ndpi_in6_addr),
        ('ip6_dst', ndpi_in6_addr),
    ]

class struct_ndpi_tcphdr(Structure):
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

class struct_ndpi_udphdr(Structure):
    _fields_ = [
        ('source', c_uint16),
        ('dest', c_uint16),
        ('len', c_uint16),
        ('check', c_uint16),
    ]

class ndpi_packet_struct(Structure):
    _fields_ = [
        ('iph', POINTER(struct_ndpi_iphdr_little_end)),
        ('iphv6', POINTER(struct_ndpi_ipv6hdr)),
        ('tcp', POINTER(struct_ndpi_tcphdr)),
        ('udp', POINTER(struct_ndpi_udphdr)),
        ('generic_l4_ptr', POINTER(c_uint8)),
        ('payload', POINTER(c_uint8)),
        ('tick_timestamp', c_uint32),
        ('tick_timestamp_l', c_uint64),
        ('detected_protocol_stack', c_uint16 * 2),
        ('detected_subprotocol_stack', c_uint8 * 2),
        ('protocol_stack_info', c_uint16),
        ('line', struct_ndpi_int_one_line_struct * 64),
        ('host_line', struct_ndpi_int_one_line_struct),
        ('forwarded_line', struct_ndpi_int_one_line_struct),
        ('referer_line', struct_ndpi_int_one_line_struct),
        ('content_line', struct_ndpi_int_one_line_struct),
        ('accept_line', struct_ndpi_int_one_line_struct),
        ('user_agent_line', struct_ndpi_int_one_line_struct),
        ('http_url_name', struct_ndpi_int_one_line_struct),
        ('http_encoding', struct_ndpi_int_one_line_struct),
        ('http_transfer_encoding', struct_ndpi_int_one_line_struct),
        ('http_contentlen', struct_ndpi_int_one_line_struct),
        ('http_cookie', struct_ndpi_int_one_line_struct),
        ('http_origin', struct_ndpi_int_one_line_struct),
        ('http_x_session_type', struct_ndpi_int_one_line_struct),
        ('server_line', struct_ndpi_int_one_line_struct),
        ('http_method', struct_ndpi_int_one_line_struct),
        ('http_response', struct_ndpi_int_one_line_struct),
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
    ]

ndpi_flow_struct._fields_ = [
    ("detected_protocol_stack", c_uint16 * ndpi.ndpi_wrap_ndpi_procol_size()),
    ("protocol_stack_info", c_uint16),

   # init parameter, internal used to set up timestamp,...
    ("guessed_protocol_id", c_uint16),
    ("guessed_host_protocol_id", c_uint16),
    ("guessed_category", c_uint16),
    ("guessed_header_category", c_uint16),
    ("protocol_id_already_guessed", c_uint8, 1),
    ("host_already_guessed", c_uint8, 1),
    ("init_finished", c_uint8, 1),
    ("setup_packet_direction", c_uint8, 1),
    ("packet_direction", c_uint8, 1),
    ("check_extra_packets", c_uint8, 1),

  # if ndpi_struct->direction_detect_disable == 1 tcp sequence number connection tracking
    ("next_tcp_seq_nr", c_uint32 * 2),

    ("max_extra_packets_to_check", c_uint8),
    ("num_extra_packets_checked", c_uint8),
    ("num_processed_pkts", c_uint8),  # <= WARNING it can wrap but we do expect people to giveup earlier

    ("extra_packets_func", CFUNCTYPE(c_int,POINTER(ndpi_detection_module_struct),POINTER(ndpi_flow_struct))),

    ("l4", l4),

  # Pointer to src or dst that identifies the server of this connection
    ("server_id", ndpi_id_struct),
    # HTTP host or DNS query
    ("host_server_name", c_ubyte * 256),


  #  This structure below will not not stay inside the protos
    #  structure below as HTTP is used by many subprotocols
    #  such as FaceBook, Google... so it is hard to know
    #  when to use it or not. Thus we leave it outside for the
    #  time being.


    ("http", http),
    ("protos", protos),

  # ALL protocol specific 64 bit variables here

  # protocols which have marked a connection as this connection cannot be protocol XXX, multiple u_int64_t
    ("excluded_protocol_bitmask", NDPI_PROTOCOL_BITMASK),

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
    ('tinc_cache_entry', tinc_cache_entry),
    ('csgo_strid', c_uint8 * 18),
    ('csgo_state', c_uint8),
    ('csgo_s2', c_uint8),
    ('csgo_id2', c_uint32),
    ('kxun_counter', c_uint16),
    ('iqiyi_counter', c_uint16),
    ('packet', ndpi_packet_struct),
    ('flow', POINTER(ndpi_flow_struct)),
    ('src', POINTER(ndpi_id_struct)),
    ('dst', POINTER(ndpi_id_struct))
]


ndpi.ndpi_tfind.restype = c_void_p
ndpi.ndpi_tsearch.restype = c_void_p
ndpi.ndpi_revision.restype = c_void_p
ndpi.ndpi_get_proto_name.restype = c_void_p
ndpi.ndpi_get_num_supported_protocols.restype = c_uint
ndpi.ndpi_detection_process_packet.restype = ndpi_protocol
ndpi.ndpi_init_detection_module.restype = POINTER(ndpi_detection_module_struct)
ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL.argtypes = [POINTER(NDPI_PROTOCOL_BITMASK)]
ndpi.ndpi_set_protocol_detection_bitmask2.argtypes = [POINTER(ndpi_detection_module_struct), POINTER(NDPI_PROTOCOL_BITMASK)]
ndpi.ndpi_tsearch.argtypes = [c_void_p, POINTER(c_void_p), CFUNCTYPE(c_int, c_void_p, c_void_p)]
ndpi.ndpi_twalk.argtypes = [c_void_p, CFUNCTYPE(None, c_void_p, c_int32, c_int, c_void_p), c_void_p]
ndpi.ndpi_tdestroy.argtypes = [c_void_p, CFUNCTYPE(None, c_void_p)]
ndpi.ndpi_detection_giveup.restype = ndpi_protocol
ndpi.ndpi_detection_giveup.argtypes = [POINTER(ndpi_detection_module_struct), POINTER(ndpi_flow_struct), c_uint8]
ndpi.ndpi_detection_process_packet.argtypes = [POINTER(ndpi_detection_module_struct), POINTER(ndpi_flow_struct), POINTER(c_ubyte), c_ushort, c_uint64, POINTER(ndpi_id_struct), POINTER(ndpi_id_struct)]
