--
-- (C) 2017-24 - ntop.org
--
-- This plugin is part of nDPI (https://github.com/ntop/nDPI)
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software Foundation,
-- Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
--
-- STUN code courtesy of Lorenzo Iannarella <l.iannarela@studenti.unpi.it>
--

-- ##############################################

function bit(p) -- 0-based indexing; returning a UInt64 object!
   if p < 32 then
      return UInt64(2 ^ p, 0)
   else
      return UInt64(0, 2 ^ (p - 32))
   end
end

-- ##############################################

local ndpi_proto = Proto("ndpi", "nDPI Protocol Interpreter")
local tcp_fprint = Proto("ndpi.tcp_fingerprint", "TCP Fingerprint")
local dhcp_fprint = Proto("ndpi.dhcp_fingerprint", "DHCP Fingerprint")

ndpi_proto.fields = {}

local ndpi_fds                = ndpi_proto.fields
local tcp_fprint_fds          = tcp_fprint.fields
ndpi_fds.magic                = ProtoField.new("nDPI Magic", "ndpi.magic", ftypes.UINT32, nil, base.HEX)
ndpi_fds.network_protocol     = ProtoField.new("nDPI Network Protocol", "ndpi.protocol.network", ftypes.UINT8, nil, base.DEC)
ndpi_fds.application_protocol = ProtoField.new("nDPI Application Protocol", "ndpi.protocol.application", ftypes.UINT16, nil, base.DEC)
ndpi_fds.name                 = ProtoField.new("nDPI Protocol Name", "ndpi.protocol.name", ftypes.STRING)
ndpi_fds.flags                = ProtoField.new("nDPI Flags", "ndpi.flags", ftypes.UINT8, nil, base.HEX)

local dir_types = {
   [0] = "Unknown Direction",
   [1] = "Client to Server Direction",
   [2] = "Server to Client Direction",
}
ndpi_fds.flags_direction      = ProtoField.new("nDPI Direction", "ndpi.flags.direction", ftypes.UINT8, dir_types, base.DEC, 0x03)
local dpi_state_types = {
   [0] = "Inspecting",
   [1] = "From Inspecting to Done",
   [2] = "Done",
}
ndpi_fds.flags_dpi_state      = ProtoField.new("nDPI DPI state", "ndpi.flags.dpi_state", ftypes.UINT8, dpi_state_types, base.DEC, 0xC)
ndpi_fds.flow_risk            = ProtoField.new("nDPI Flow Risk", "ndpi.flow_risk", ftypes.UINT64, nil, base.HEX)
ndpi_fds.flow_score           = ProtoField.new("nDPI Flow Score", "ndpi.flow_score", ftypes.UINT32)
ndpi_fds.flow_risk_info_len   = ProtoField.new("nDPI Flow Risk Info Length", "ndpi.flow_risk_info_len", ftypes.UINT16, nil, base.DEC)
ndpi_fds.flow_risk_info       = ProtoField.new("nDPI Flow Risk Info", "ndpi.flow_risk_info", ftypes.STRING)

ndpi_fds.metadata_list_len    = ProtoField.new("nDPI Metadata List Length", "ndpi.metadata_list_len", ftypes.UINT16, nil, base.DEC)
ndpi_fds.metadata_list        = ProtoField.new("nDPI Metadata List", "ndpi.metadata_list", ftypes.NONE)
ndpi_fds.metadata             = ProtoField.new("nDPI Metadata", "ndpi.metadata", ftypes.NONE)
local mtd_types = {
   [0] = "Padding",
   [1] = "Server Name",
   [2] = "JA4C",
   [3] = "TLS Heuristic Fingerprint",
}
ndpi_fds.metadata_type        = ProtoField.new("nDPI Metadata Type", "ndpi.metadata.type", ftypes.UINT16, mtd_types)
ndpi_fds.metadata_length      = ProtoField.new("nDPI Metadata Length", "ndpi.metadata.length", ftypes.UINT16)
-- Generic field
ndpi_fds.metadata_value       = ProtoField.new("nDPI Metadata Value", "ndpi.metadata.value", ftypes.BYTES)
-- Specific fields
ndpi_fds.metadata_server_name = ProtoField.new("nDPI Server Name", "ndpi.metadata.server_name", ftypes.STRING)
ndpi_fds.metadata_ja4c        = ProtoField.new("nDPI JA4C", "ndpi.metadata.ja4c", ftypes.STRING)
ndpi_fds.metadata             = ProtoField.new("nDPI Metadata", "ndpi.metadata", ftypes.NONE)
ndpi_fds.metadata_tls_heuristic_fingerprint = ProtoField.new("nDPI TLS Heuristic Fingerprint", "ndpi.metadata.tls_heuristic_fingerprint", ftypes.NONE)
ndpi_fds.metadata_tls_heuristic_fingerprint_bytes0 = ProtoField.new("Bytes[0]", "ndpi.metadata.tls_heuristic_fingerprint.bytes0", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_bytes1 = ProtoField.new("Bytes[1]", "ndpi.metadata.tls_heuristic_fingerprint.bytes1", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_bytes2 = ProtoField.new("Bytes[2]", "ndpi.metadata.tls_heuristic_fingerprint.bytes2", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_bytes3 = ProtoField.new("Bytes[3]", "ndpi.metadata.tls_heuristic_fingerprint.bytes3", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_pkts0 = ProtoField.new("Pkts[0]", "ndpi.metadata.tls_heuristic_fingerprint.pkts0", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_pkts1 = ProtoField.new("Pkts[1]", "ndpi.metadata.tls_heuristic_fingerprint.pkts1", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_pkts2 = ProtoField.new("Pkts[2]", "ndpi.metadata.tls_heuristic_fingerprint.pkts2", ftypes.UINT32)
ndpi_fds.metadata_tls_heuristic_fingerprint_pkts3 = ProtoField.new("Pkts[3]", "ndpi.metadata.tls_heuristic_fingerprint.pkts3", ftypes.UINT32)


local flow_risks = {}
--- You can't use a 64 bit integer "as-is" as mask: we choose to use UInt64 object instead
local num_bits_flow_risks = 64
flow_risks[0]  = ProtoField.bool("ndpi.flow_risk.unused0", "Reserved", num_bits_flow_risks, nil, bit(0), "nDPI Flow Risk: Reserved bit")
flow_risks[1]  = ProtoField.bool("ndpi.flow_risk.xss_attack", "XSS attack", num_bits_flow_risks, nil, bit(1), "nDPI Flow Risk: XSS attack")
flow_risks[2]  = ProtoField.bool("ndpi.flow_risk.sql_injection", "SQL injection", num_bits_flow_risks, nil, bit(2), "nDPI Flow Risk: SQL injection")
flow_risks[3]  = ProtoField.bool("ndpi.flow_risk.rce_injection", "RCE injection", num_bits_flow_risks, nil, bit(3), "nDPI Flow Risk: RCE injection")
flow_risks[4]  = ProtoField.bool("ndpi.flow_risk.binary_application_transfer", "Binary application transfer", num_bits_flow_risks, nil, bit(4), "nDPI Flow Risk: Binary application transfer")
flow_risks[5]  = ProtoField.bool("ndpi.flow_risk.known_protocol_on_non_standard_port", "Known protocol on non standard port", num_bits_flow_risks, nil, bit(5), "nDPI Flow Risk: Known protocol on non standard port")
flow_risks[6]  = ProtoField.bool("ndpi.flow_risk.self_signed_certificate", "Self-signed Certificate", num_bits_flow_risks, nil, bit(6), "nDPI Flow Risk: Self-signed Certificate")
flow_risks[7]  = ProtoField.bool("ndpi.flow_risk.obsolete_tls_version", "Obsolete TLS version (< 1.1)", num_bits_flow_risks, nil, bit(7), "nDPI Flow Risk: Obsolete TLS version (< 1.1)")
flow_risks[8]  = ProtoField.bool("ndpi.flow_risk.weak_tls_cipher", "Weak TLS cipher", num_bits_flow_risks, nil, bit(8), "nDPI Flow Risk: Weak TLS cipher")
flow_risks[9]  = ProtoField.bool("ndpi.flow_risk.tls_expired_certificate", "TLS Expired Certificate", num_bits_flow_risks, nil, bit(9), "nDPI Flow Risk: TLS Expired Certificate")
flow_risks[10] = ProtoField.bool("ndpi.flow_risk.tls_certificate_mismatch", "TLS Certificate Mismatch", num_bits_flow_risks, nil, bit(10), "nDPI Flow Risk: TLS Certificate Mismatch")
flow_risks[11] = ProtoField.bool("ndpi.flow_risk.http_suspicious_user_agent", "HTTP Suspicious User-Agent", num_bits_flow_risks, nil, bit(11), "nDPI Flow Risk: HTTP Suspicious User-Agent")
flow_risks[12] = ProtoField.bool("ndpi.flow_risk.numeric_ip_host", "HTTP/TLS/QUIC Numeric IP Hostname/SNI", num_bits_flow_risks, nil, bit(12), "nDPI Flow Risk: HTTP/TLS/QUIC Numeric IP Hostname/SNI")
flow_risks[13] = ProtoField.bool("ndpi.flow_risk.http_suspicious_url", "HTTP Suspicious URL", num_bits_flow_risks, nil, bit(13), "nDPI Flow Risk: HTTP Suspicious URL")
flow_risks[14] = ProtoField.bool("ndpi.flow_risk.http_suspicious_header", "HTTP Suspicious Header", num_bits_flow_risks, nil, bit(14), "nDPI Flow Risk: HTTP Suspicious Header")
flow_risks[15] = ProtoField.bool("ndpi.flow_risk.tls_probably_not_https", "TLS (probably) not carrying HTTPS", num_bits_flow_risks, nil, bit(15), "nDPI Flow Risk: TLS (probably) not carrying HTTPS")
flow_risks[16] = ProtoField.bool("ndpi.flow_risk.suspicious_dga", "Suspicious DGA domain name", num_bits_flow_risks, nil, bit(16), "nDPI Flow Risk: Suspicious DGA domain name")
flow_risks[17] = ProtoField.bool("ndpi.flow_risk.malformed_packet", "Malformed packet", num_bits_flow_risks, nil, bit(17), "nDPI Flow Risk: Malformed packet")
flow_risks[18] = ProtoField.bool("ndpi.flow_risk.ssh_obsolete_client", "SSH Obsolete Client Version/Cipher", num_bits_flow_risks, nil, bit(18), "nDPI Flow Risk: SSH Obsolete Client Version/Cipher")
flow_risks[19] = ProtoField.bool("ndpi.flow_risk.ssh_obsolete_server", "SSH Obsolete Server Version/Cipher", num_bits_flow_risks, nil, bit(19), "nDPI Flow Risk: SSH Obsolete Server Version/Cipher")
flow_risks[20] = ProtoField.bool("ndpi.flow_risk.smb_insecure_version", "SMB Insecure Version", num_bits_flow_risks, nil, bit(20), "nDPI Flow Risk: SMB Insecure Version")
flow_risks[21] = ProtoField.bool("ndpi.flow_risk.tls_suspicious_esni", "TLS Suspicious ESNI Usage", num_bits_flow_risks, nil, bit(21), "nDPI Flow Risk: TLS Suspicious ESNI Usage")
flow_risks[22] = ProtoField.bool("ndpi.flow_risk.unsafe_protocol", "Unsafe Protocol", num_bits_flow_risks, nil, bit(22), "nDPI Flow Risk: Unsafe Protocol")
flow_risks[23] = ProtoField.bool("ndpi.flow_risk.suspicious_dns_traffic", "Suspicious DNS traffic", num_bits_flow_risks, nil, bit(23), "nDPI Flow Risk: Suspicious DNS traffic")
flow_risks[24] = ProtoField.bool("ndpi.flow_risk.sni_tls_extension_missing", "SNI TLS extension was missing", num_bits_flow_risks, nil, bit(24), "nDPI Flow Risk: SNI TLS extension was missing")
flow_risks[25] = ProtoField.bool("ndpi.flow_risk.http_suspicious_content", "HTTP suspicious content", num_bits_flow_risks, nil, bit(25), "nDPI Flow Risk: HTTP suspicious content")
flow_risks[26] = ProtoField.bool("ndpi.flow_risk.risky_asn", "Risky ASN", num_bits_flow_risks, nil, bit(26), "nDPI Flow Risk: Risky ASN")
flow_risks[27] = ProtoField.bool("ndpi.flow_risk.risky_domain_name", "Risky domain name", num_bits_flow_risks, nil, bit(27), "nDPI Flow Risk: Risky domain name")
flow_risks[28] = ProtoField.bool("ndpi.flow_risk.possibly_malicious_ja3", "Possibly Malicious JA3 Fingerprint", num_bits_flow_risks, nil, bit(28), "nDPI Flow Risk: Possibly Malicious JA3 Fingerprint")
flow_risks[29] = ProtoField.bool("ndpi.flow_risk.possibly_malicious_ssl_certificate_sha1", "Possibly Malicious SSL Certificate SHA1 Fingerprint", num_bits_flow_risks, nil, bit(29), "nDPI Flow Risk: Possibly Malicious SSL Certificate SHA1 Fingerprint")
flow_risks[30] = ProtoField.bool("ndpi.flow_risk.desktop_file_sharing_session", "Desktop/File Sharing Session", num_bits_flow_risks, nil, bit(30), "nDPI Flow Risk: Desktop/File Sharing Session")
flow_risks[31] = ProtoField.bool("ndpi.flow_risk.uncommon_tls_alpn", "Uncommon TLS ALPN", num_bits_flow_risks, nil, bit(31), "nDPI Flow Risk: Uncommon TLS ALPN")
flow_risks[32] = ProtoField.bool("ndpi.flow_risk.cert_validity_too_long", "TLS certificate validity longer than 13 months", num_bits_flow_risks, nil, bit(32), "nDPI Flow Risk: TLS certificate validity longer than 13 months")
flow_risks[33] = ProtoField.bool("ndpi.flow_risk.suspicious_extension", "TLS suspicious extension", num_bits_flow_risks, nil, bit(33), "nDPI Flow Risk: TLS suspicious extension")
flow_risks[34] = ProtoField.bool("ndpi.flow_risk.fatal_alert", "TLS fatal alert detected", num_bits_flow_risks, nil, bit(34), "nDPI Flow Risk: TLS fatal alert")
flow_risks[35] = ProtoField.bool("ndpi.flow_risk.suspicious_entropy", "Suspicious entropy", num_bits_flow_risks, nil, bit(35), "nDPI Flow Risk: suspicious entropy")
flow_risks[36] = ProtoField.bool("ndpi.flow_risk.clear_text_credentials", "Cleat-Text credentials", num_bits_flow_risks, nil, bit(36), "nDPI Flow Risk: cleat-text credentials")
flow_risks[37] = ProtoField.bool("ndpi.flow_risk.dns_large_packet", "DNS large packet", num_bits_flow_risks, nil, bit(37), "nDPI Flow Risk: DNS packet is larger than 512 bytes")
flow_risks[38] = ProtoField.bool("ndpi.flow_risk.dns_fragmented", "DNS fragmented", num_bits_flow_risks, nil, bit(38), "nDPI Flow Risk: DNS message is fragmented")
flow_risks[39] = ProtoField.bool("ndpi.flow_risk.invalid_characters", "Invalid characters", num_bits_flow_risks, nil, bit(39), "nDPI Flow Risk: Text contains non-printable characters")
flow_risks[40] = ProtoField.bool("ndpi.flow_risk.possible_exploit", "Possible Exploit", num_bits_flow_risks, nil, bit(40), "nDPI Flow Risk: Possible exploit attempt detected")
flow_risks[41] = ProtoField.bool("ndpi.flow_risk.cert_about_to_expire", "TLS cert about to expire", num_bits_flow_risks, nil, bit(41), "nDPI Flow Risk: TLS certificate about to expire")
flow_risks[42] = ProtoField.bool("ndpi.flow_risk.punycode_idn", "IDN Domain Name", num_bits_flow_risks, nil, bit(42), "nDPI Flow Risk: IDN Domain Name")
flow_risks[43] = ProtoField.bool("ndpi.flow_risk.error_code_detected", "Error Code Detected", num_bits_flow_risks, nil, bit(43), "nDPI Flow Risk: Error Code Detected")
flow_risks[44] = ProtoField.bool("ndpi.flow_risk.crawler_bot", "Crawler/Bot Detected", num_bits_flow_risks, nil, bit(44), "nDPI Flow Risk: Crawler/Bot Detected")
flow_risks[45] = ProtoField.bool("ndpi.flow_risk.anonymous_subscriber", "Anonymous Subscriber", num_bits_flow_risks, nil, bit(45), "nDPI Flow Risk: Anonymous Subscriber")
flow_risks[46] = ProtoField.bool("ndpi.flow_risk.unidirectional_traffic", "Unidirectional Traffic", num_bits_flow_risks, nil, bit(46), "nDPI Flow Risk: Unidirectional Traffi")
flow_risks[47] = ProtoField.bool("ndpi.flow_risk.http_obsolete_server", "Obsolete HTTP Server", num_bits_flow_risks, nil, bit(47), "nDPI Flow Risk: Obsolete HTTP Server")
flow_risks[48] = ProtoField.bool("ndpi.flow_risk.periodic_flow", "Periodic Flow", num_bits_flow_risks, nil, bit(48), "nDPI Flow Risk: Periodic Flow")
flow_risks[49] = ProtoField.bool("ndpi.flow_risk.minor_issues", "Minor flow issues", num_bits_flow_risks, nil, bit(49), "nDPI Flow Risk: Minor flow issues")
flow_risks[50] = ProtoField.bool("ndpi.flow_risk.tcp_issues", "TCP connection issues", num_bits_flow_risks, nil, bit(50), "nDPI Flow Risk: TCP connection issues")
flow_risks[51] = ProtoField.bool("ndpi.flow_risk.fully_encrypted", "Fully encrypted connection", num_bits_flow_risks, nil, bit(51), "nDPI Flow Risk: Fully encrypted connection")
flow_risks[52] = ProtoField.bool("ndpi.flow_risk.tls_alpn_sni_mismatch", "ALPN/SNI Mismatch", num_bits_flow_risks, nil, bit(52), "nDPI Flow Risk: ALPN/SNI Mismatch")
flow_risks[53] = ProtoField.bool("ndpi.flow_risk.malware_contact", "Contact with a malware host", num_bits_flow_risks, nil, bit(53), "nDPI Flow Risk: Malware host contacted")
flow_risks[54] = ProtoField.bool("ndpi.flow_risk.binary_data_transfer", "Attempt to transfer a binary file", num_bits_flow_risks, nil, bit(54), "nDPI Flow Risk: binary data file transfer")
flow_risks[55] = ProtoField.bool("ndpi.flow_risk.probing_attempt", "Probing attempt", num_bits_flow_risks, nil, bit(55), "nDPI Flow Risk: probing attempt")
flow_risks[56] = ProtoField.bool("ndpi.flow_risk.obfuscated_traffic", "Obfuscated Traffic", num_bits_flow_risks, nil, bit(56), "nDPI Flow Risk: obfuscated traffic")

-- Last one: keep in sync the bitmask when adding new risks!!
flow_risks[64] = ProtoField.new("Unused", "ndpi.flow_risk.unused", ftypes.UINT64, nil, base.HEX, bit(64) - bit(57))

for _,v in pairs(flow_risks) do
   ndpi_fds[#ndpi_fds + 1] = v
end

local stun_request_table = {}
local stun_flows_table = {}
local stun_processed_packets = {}
local stun_old_id_packet = 0


local ntop_proto = Proto("ntop", "ntop Extensions")
ntop_proto.fields = {}

local ntop_fds = ntop_proto.fields
ntop_fds.client_nw_rtt    = ProtoField.new("TCP client network RTT (msec)",  "ntop.latency.client_rtt", ftypes.FLOAT,  nil, base.NONE)
ntop_fds.server_nw_rtt    = ProtoField.new("TCP server network RTT (msec)",  "ntop.latency.server_rtt", ftypes.FLOAT,  nil, base.NONE)
ntop_fds.appl_latency_rtt = ProtoField.new("Application Latency RTT (msec)", "ntop.latency.appl_rtt",   ftypes.FLOAT,  nil, base.NONE)
ntop_fds.tcp_fingerprint  = ProtoField.new("TCP Fingerprint",                "ntop.tcp_fingerprint",    ftypes.STRING, nil, base.NONE)
ntop_fds.dhcp_fingerprint = ProtoField.new("DHCP Fingerprint",               "ntop.dhcp_fingerprint",   ftypes.STRING, nil, base.NONE)

local f_eth_source        = Field.new("eth.src")
local f_eth_trailer       = Field.new("eth.trailer")
local f_vlan_trailer      = Field.new("vlan.trailer")
local f_sll_trailer       = Field.new("sll.trailer")
local f_vlan_id           = Field.new("vlan.id")
local f_arp_opcode        = Field.new("arp.opcode")
local f_arp_sender_mac    = Field.new("arp.src.hw_mac")
local f_arp_target_mac    = Field.new("arp.dst.hw_mac")
local f_dns_query_name    = Field.new("dns.qry.name")
local f_dns_ret_code      = Field.new("dns.flags.rcode")
local f_dns_response      = Field.new("dns.flags.response")
local f_udp_len           = Field.new("udp.length")
local f_tcp_header_len    = Field.new("tcp.hdr_len")
local f_tcp_win           = Field.new("tcp.window_size_value")
local f_tcp_stream        = Field.new("tcp.stream")
local f_tcp_options       = Field.new("tcp.options")
local f_ip_len            = Field.new("ip.len")
local f_ip_proto          = Field.new("ip.proto")
local f_ipv6_next_hdr     = Field.new("ipv6.nxt")
local f_ip_ttl            = Field.new("ip.ttl")
local f_ipv6_hlim         = Field.new("ipv6.hlim")
local f_ip_hdr_len        = Field.new("ip.hdr_len")
local f_tls_server_name   = Field.new("tls.handshake.extensions_server_name")
local f_tls_ja4           = Field.new("tls.handshake.ja4")
--local f_tls_ja4           = Field.new("tls.handshake.ja4_r")
local f_tcp_flags         = Field.new('tcp.flags')
local f_tcp_retrans       = Field.new('tcp.analysis.retransmission')
local f_tcp_ooo           = Field.new('tcp.analysis.out_of_order')
local f_tcp_lost_segment  = Field.new('tcp.analysis.lost_segment') -- packet drop ?
local f_rpc_xid           = Field.new('rpc.xid')
local f_rpc_msgtyp        = Field.new('rpc.msgtyp')
local f_user_agent        = Field.new('http.user_agent')
local f_dhcp_request_item = Field.new('dhcp.option.request_list_item')

local f_stun_type           = Field.new("stun.type")
local f_stun_classic_type   = Field.new("classicstun.type")
local f_stun_length         = Field.new("stun.length")
local f_stun_username       = Field.new("stun.att.username")
local f_stun_tie_breaker    = Field.new("stun.att.tie-breaker")
local f_stun_unknown_att    = Field.new("stun.unknown_attribute")
local f_stun_realm          = Field.new("stun.att.realm")
local f_stun_nonce          = Field.new("stun.att.nonce")
local f_stun_software       = Field.new("stun.att.software")
local f_stun_ip_xor         = Field.new("stun.att.ipv4-xord")
local f_stun_ms_version     = Field.new("stun.att.ms.version")
local f_stun_ms_version_ice = Field.new("stun.att.ms.version.ice")
local f_stun_response_to    = Field.new("stun.response-to")
local f_udp_traffic         = Field.new("udp")
local f_src_ip              = Field.new("ip.src")
local f_src_ipv6            = Field.new("ipv6.src")
local f_dst_ip              = Field.new("ip.dst")
local f_src_port            = Field.new("udp.srcport")
local f_dst_port            = Field.new("udp.dstport")

local ndpi_protos            = {}
local ndpi_flows             = {}
local num_ndpi_flows         = 0

local arp_stats              = {}
local mac_stats              = {}
local vlan_stats             = {}
local vlan_found             = false

local dns_responses_ok       = {}
local dns_responses_error    = {}
local dns_client_queries     = {}
local dns_server_responses   = {}
local dns_queries            = {}

local syn                    = {}
local synack                 = {}
local lower_ndpi_flow_id     = 0
local lower_ndpi_flow_volume = 0

local compute_flows_stats    = true
local max_num_entries        = 10
local max_num_flows          = 50

local num_top_dns_queries    = 0
local max_num_dns_queries    = 50

local tls_server_names       = {}
local tot_tls_flows          = 0
local tot_tls_ja4_flows      = 0 -- # of JA4 flows per signature

local tcp_host_fingerprints  = {}
local tcp_fingerprint_hosts  = {}
local http_ua                = {}
local tot_http_ua_flows      = 0

local possible_obfuscated_servers = {}
local tot_obfuscated_flows        = 0

local flows                  = {}
local tot_flows              = 0

local flows_with_risks       = {}

local dhcp_fingerprints      = {}

local stream_app             = {}

local min_nw_client_RRT      = {}
local min_nw_server_RRT      = {}
local max_nw_client_RRT      = {}
local max_nw_server_RRT      = {}
local min_appl_RRT           = {}
local max_appl_RRT           = {}

local first_payload_ts       = {}
local first_payload_id       = {}

local rpc_ts                 = {}

local num_pkts               = 0
local last_processed_packet_number = 0
local max_latency_discard    = 5000  -- 5 sec
local max_appl_lat_discard   = 15000 -- 15 sec
local debug                  = false

local dump_timeseries = false

local track_obfuscated_servers = true

local dissect_ndpi_trailer = true

local dump_file = "/tmp/wireshark-influx.txt"
local file

local ndpi_proto_unknown  = ""           -- NDPI_PROTOCOL_UNKNOWN
local ndpi_proto_whatsapp = "WhatApp"    -- NDPI_PROTOCOL_WHATSAPP_CALL
local ndpi_proto_telegram = "Telegram"   -- NDPI_PROTOCOL_TELEGRAM
local ndpi_proto_teams    = "Teams"      -- NDPI_PROTOCOL_SKYPE_TEAMS_CALL
local ndpi_proto_meet     = "GoogleMeet" -- NDPI_PROTOCOL_GOOGLE_MEET

-- ##############################################

local tcp_fingeprint_db = {
   ['2_64_65535_8bf9e292397e']   = "FreeBSD",

   ['2_64_64800_83b2f9a5576c']   = "Linux",
   ['2_64_64240_2e3cee914fc1']   = "Linux",
   ['2_64_29200_2e3cee914fc1']   = "Linux",
   ['2_64_29200_d853e95bd80f']   = "Linux",
   ['2_64_14600_8c07a80cc645']   = "Linux",
   ['2_64_64240_2e3cee914fc1']   = "Linux",
   ['2_64_29200_90541420d839']   = "Linux",
   
   ['2_64_65535_d876f498b09e']   = "Android",
   ['2_64_65535_685ad951a756']   = "Android",
   ['2_64_65535_41a9d5af7dd3']   = "Android",
   ['2_64_65535_148107a0d970']   = "Android",
   ['2_64_65535_f518bfb025b0']   = "Android",

   ['2_128_64240_6bb88f5575fd']    = "Windows",
   ['194_128_64240_0c6c715fcb8e']  = "Windows",
   ['194_128_64240_29659b8d8574']  = "Windows",
   ['194_128_32768_e75eea53a4fd']  = "Windows",
   ['194_128_32768_84fee6d35dde']  = "Windows",
   
   ['194_64_65535_15db81ff8b0d'] = "iOS",
   ['2_64_65535_41a9d5af7dd3']   = "iOS",
   ['194_64_65535_dd5737e4fedb'] = "iOS",
   ['194_64_65535_d3a424420f2a'] = "iPad OS",
   ['194_64_0_d29295416479'    ] = "iPad OS",

   ['194_64_65535_d29295416479'] = "macOS/iPad OS",
   ['2_64_65535_d29295416479']   = "macOS/iPad OS",
   ['194_64_65535_78dd6871cb6d'] = "macOS",
   ['2_64_65535_dd5737e4fedb']   = "macOS",
}

-- ##############################################

local ja4_db = {
   ['02e81d9f7c9f_736b2a1ed4d3'] = 'Chrome',
   ['07be0c029dc8_ad97e2351c08'] = 'Firefox',
   ['07be0c029dc8_d267a5f792d4'] = 'Firefox',
   ['0a330963ad8f_c905abbc9856'] = 'Chrome',
   ['0a330963ad8f_c9eaec7dbab4'] = 'Chrome',
   ['168bb377f8c8_a1e935682795'] = 'Anydesk',
   ['24fc43eb1c96_14788d8d241b'] = 'Chrome',
   ['24fc43eb1c96_14788d8d241b'] = 'Safari',
   ['24fc43eb1c96_845d286b0d67'] = 'Chrome',
   ['24fc43eb1c96_845d286b0d67'] = 'Safari',
   ['24fc43eb1c96_c5b8c5b1cdcb'] = 'Safari',
   ['2a284e3b0c56_12b7a1cb7c36'] = 'Safari',
   ['2a284e3b0c56_f05fdf8c38a9'] = 'Safari',
   ['2b729b4bf6f3_9e7b989ebec8'] = 'IcedID',
   ['39b11509324c_ab57fa081356'] = 'Chrome',
   ['39b11509324c_c905abbc9856'] = 'Chrome',
   ['39b11509324c_c9eaec7dbab4'] = 'Chrome',
   ['41f4ea5be9c2_06a4338d0495'] = 'Chrome',
   ['41f4ea5be9c2_736b2a1ed4d3'] = 'Chrome',
   ['41f4ea5be9c2_ed5eb0a3fdc3'] = 'Chrome',
   ['49e15d6cf97a_6bdcaa414218'] = 'Chrome',
   ['49e15d6cf97a_736b2a1ed4d3'] = 'Chrome',
   ['4b22cbed5bed_27793441e138'] = 'Edge',
   ['4b22cbed5bed_2cdefc264be7'] = 'Safari',
   ['55b375c5d22e_06cda9e17597'] = 'Chrome',
   ['5b57614c22b0_14788d8d241b'] = 'Chrome',
   ['5b57614c22b0_14788d8d241b'] = 'Safari',
   ['5b57614c22b0_3d5424432f57'] = 'Firefox',
   ['5b57614c22b0_5c2c66f702b0'] = 'Firefox',
   ['5b57614c22b0_d267a5f792d4'] = 'Firefox',
   ['8daaf6152771_02713d6af862'] = 'Chrome',
   ['8daaf6152771_02713d6af862'] = 'Chrome',
   ['8daaf6152771_45f260be83e2'] = 'Chrome',
   ['8daaf6152771_45f260be83e2'] = 'Edge',
   ['8daaf6152771_6a09c78d0dc2'] = 'Firefox',
   ['8daaf6152771_b0da82dd1658'] = 'Chrome',
   ['8daaf6152771_b1ff8ab2d16f'] = 'Chrome',
   ['8daaf6152771_b1ff8ab2d16f'] = 'Chrome',
   ['8daaf6152771_de4a06bb82e3'] = 'Chrome',
   ['8daaf6152771_de4a06bb82e3'] = 'Edge',
   ['8daaf6152771_e5627efa2ab1'] = 'Chrome',
   ['8daaf6152771_e5627efa2ab1'] = 'Edge',
   ['8daaf6152771_e5627efa2ab1'] = 'Samsung Internet',
   ['95e1cefdbe28_d267a5f792d4'] = 'Firefox',
   ['9dc949149365_97f8aa674fd9'] = 'Sliver Agent',
   ['9dc949149365_e7c285222651'] = 'ngrok',
   ['a571d07754c8_06a4338d0495'] = 'Chrome',
   ['a571d07754c8_6bdcaa414218'] = 'Chrome',
   ['a571d07754c8_736b2a1ed4d3'] = 'Chrome',
   ['a571d07754c8_ed5eb0a3fdc3'] = 'Chrome',
   ['c45550529adf_c9eaec7dbab4'] = 'Chrome',
   ['c45550529adf_ce3753e6c77f'] = 'Chrome',
   ['c866b44c5a26_de5ccbe16bdd'] = 'Chrome',
   ['c877c20a043a_e70312a1ce2c'] = 'Firefox',
   ['ccb88ad3c00d_c9eaec7dbab4'] = 'Chrome',
   ['d34a8e72043a_77989cba1f4a'] = 'Chrome',
   ['d34a8e72043a_b00751acaffa'] = 'Chrome',
   ['d34a8e72043a_eb7c9aabf852'] = 'Chrome',
   ['e72c3b3287f1_e5627efa2ab1'] = 'Edge',
   ['fcb5b95cb75a_b0d3b4ac2a14'] = 'SoftEther VPN',
   ['8daaf6152771_02713d6af862'] = 'Chrome/Brave/Opera/Edge',
   ['5b57614c22b0_5c2c66f702b0'] = 'Firefox',
   ['5b57614c22b0_7121afd63204'] = 'Firefox',
   ['8daaf6152771_e5627efa2ab1'] = 'Chrome',
   ['a09f3c656075_14788d8d241b'] = 'Safari',
   ['0d8feac7bc37_7395dae3b2f3'] = 'curl',
}

-- ##############################################
-- ##############################################

-- From http://pastebin.com/gsFrNjbt linked from http://www.computercraft.info/forums2/index.php?/topic/8169-sha-256-in-pure-lua/

--
--  Adaptation of the Secure Hashing Algorithm (SHA-244/256)
--  Found Here: http://lua-users.org/wiki/SecureHashAlgorithm
--
--  Using an adapted version of the bit library
--  Found Here: https://bitbucket.org/Boolsheet/bslf/src/1ee664885805/bit.lua
--

local MOD = 2^32
local MODM = MOD-1

local function memoize(f)
   local mt = {}
   local t = setmetatable({}, mt)
   function mt:__index(k)
      local v = f(k)
      t[k] = v
      return v
   end
   return t
end

local function make_bitop_uncached(t, m)
   local function bitop(a, b)
      local res,p = 0,1
      while a ~= 0 and b ~= 0 do
	 local am, bm = a % m, b % m
	 res = res + t[am][bm] * p
	 a = (a - am) / m
	 b = (b - bm) / m
	 p = p*m
      end
      res = res + (a + b) * p
      return res
   end
   return bitop
end

local function make_bitop(t)
   local op1 = make_bitop_uncached(t,2^1)
   local op2 = memoize(function(a) return memoize(function(b) return op1(a, b) end) end)
   return make_bitop_uncached(op2, 2 ^ (t.n or 1))
end

local bxor1 = make_bitop({[0] = {[0] = 0,[1] = 1}, [1] = {[0] = 1, [1] = 0}, n = 4})

local function bxor(a, b, c, ...)
   local z = nil
   if b then
      a = a % MOD
      b = b % MOD
      z = bxor1(a, b)
      if c then z = bxor(z, c, ...) end
      return z
   elseif a then return a % MOD
   else return 0 end
end

local function band(a, b, c, ...)
   local z
   if b then
      a = a % MOD
      b = b % MOD
      z = ((a + b) - bxor1(a,b)) / 2
      if c then z = bit32_band(z, c, ...) end
      return z
   elseif a then return a % MOD
   else return MODM end
end

local function bnot(x) return (-1 - x) % MOD end

local function rshift1(a, disp)
   if disp < 0 then return lshift(a,-disp) end
   return math.floor(a % 2 ^ 32 / 2 ^ disp)
end

local function rshift(x, disp)
   if disp > 31 or disp < -31 then return 0 end
   return rshift1(x % MOD, disp)
end

local function lshift(a, disp)
   if disp < 0 then return rshift(a,-disp) end
   return (a * 2 ^ disp) % 2 ^ 32
end

local function rrotate(x, disp)
   x = x % MOD
   disp = disp % 32
   local low = band(x, 2 ^ disp - 1)
   return rshift(x, disp) + lshift(low, 32 - disp)
end

local k = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
   0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
   0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
   0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
   0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
   0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
   0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function str2hexa(s)
   return (string.gsub(s, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function num2s(l, n)
   local s = ""
   for i = 1, n do
      local rem = l % 256
      s = string.char(rem) .. s
      l = (l - rem) / 256
   end
   return s
end

local function s232num(s, i)
   local n = 0
   for i = i, i + 3 do n = n*256 + string.byte(s, i) end
   return n
end

local function preproc(msg, len)
   local extra = 64 - ((len + 9) % 64)
   len = num2s(8 * len, 8)
   msg = msg .. "\128" .. string.rep("\0", extra) .. len
   assert(#msg % 64 == 0)
   return msg
end

local function initH256(H)
   H[1] = 0x6a09e667
   H[2] = 0xbb67ae85
   H[3] = 0x3c6ef372
   H[4] = 0xa54ff53a
   H[5] = 0x510e527f
   H[6] = 0x9b05688c
   H[7] = 0x1f83d9ab
   H[8] = 0x5be0cd19
   return H
end

local function digestblock(msg, i, H)
   local w = {}
   for j = 1, 16 do w[j] = s232num(msg, i + (j - 1)*4) end
   for j = 17, 64 do
      local v = w[j - 15]
      local s0 = bxor(rrotate(v, 7), rrotate(v, 18), rshift(v, 3))
      v = w[j - 2]
      w[j] = w[j - 16] + s0 + w[j - 7] + bxor(rrotate(v, 17), rrotate(v, 19), rshift(v, 10))
   end

   local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
   for i = 1, 64 do
      local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = s0 + maj
      local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
      local ch = bxor (band(e, f), band(bnot(e), g))
      local t1 = h + s1 + ch + k[i] + w[i]
      h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + t2
   end

   H[1] = band(H[1] + a)
   H[2] = band(H[2] + b)
   H[3] = band(H[3] + c)
   H[4] = band(H[4] + d)
   H[5] = band(H[5] + e)
   H[6] = band(H[6] + f)
   H[7] = band(H[7] + g)
   H[8] = band(H[8] + h)
end

-- Made this global
function sha256(msg)
   msg = preproc(msg, #msg)
   local H = initH256({})
   for i = 1, #msg, 64 do digestblock(msg, i, H) end
   return str2hexa(num2s(H[1], 4) .. num2s(H[2], 4) .. num2s(H[3], 4) .. num2s(H[4], 4) ..
		   num2s(H[5], 4) .. num2s(H[6], 4) .. num2s(H[7], 4) .. num2s(H[8], 4))
end

-- ##############################################
-- ##############################################

function string.contains(String,Start)
   if type(String) ~= 'string' or type(Start) ~= 'string' then
      return false
   end
   
   return(string.find(String,Start,1) ~= nil)
end

-- ##############################################

function string.starts(String,Start)
   if type(String) ~= 'string' or type(Start) ~= 'string' then
      return false
   end
   return string.sub(String,1,string.len(Start))==Start
end

-- ##############################################

function string.ends(String,End)
   if type(String) ~= 'string' or type(End) ~= 'string' then
      return false
   end
   return End=='' or string.sub(String,-string.len(End))==End
end

-- ###############################################

local function stun_develop_table(tab, key1, key2, protocol)
   if tab[key1] == nil then
      if tab[key2] ==  nil then
	 tab[key1] = protocol
      end
   end

   return tab
end

function round(num, idp)
   return tonumber(string.format("%." .. (idp or 0) .. "f", num))
end

function formatPctg(p)
   if(p == nil) then p = 0 end
   
   local p = round(p, 1)

   if(p < 1) then return("< 1 %") end

   return p.." %"
end

-- ###############################################

string.split = function(s, p)
   local temp = {}
   local index = 0
   local last_index = string.len(s)

   while true do
      local i, e = string.find(s, p, index)

      if i and e then
	 local next_index = e + 1
	 local word_bound = i - 1
	 table.insert(temp, string.sub(s, index, word_bound))
	 index = next_index
      else
	 if index > 0 and index <= last_index then
	    table.insert(temp, string.sub(s, index, last_index))
	 elseif index == 0 then
	    temp = nil
	 end
	 break
      end
   end

   return temp
end

-- ##############################################

function shortenString(name, max_len)
   max_len = max_len or 24
   if(string.len(name) < max_len) then
      return(name)
   else
      return(string.sub(name, 1, max_len).."...")
   end
end

-- ###############################################

-- Convert bytes to human readable format
function bytesToSize(bytes)
   if(bytes == nil) then
      return("0")
   else
      precision = 2
      kilobyte = 1024;
      megabyte = kilobyte * 1024;
      gigabyte = megabyte * 1024;
      terabyte = gigabyte * 1024;

      bytes = tonumber(bytes)
      if((bytes >= 0) and (bytes < kilobyte)) then
	 return round(bytes, precision) .. " Bytes";
      elseif((bytes >= kilobyte) and (bytes < megabyte)) then
	 return round(bytes / kilobyte, precision) .. ' KB';
      elseif((bytes >= megabyte) and (bytes < gigabyte)) then
	 return round(bytes / megabyte, precision) .. ' MB';
      elseif((bytes >= gigabyte) and (bytes < terabyte)) then
	 return round(bytes / gigabyte, precision) .. ' GB';
      elseif(bytes >= terabyte) then
	 return round(bytes / terabyte, precision) .. ' TB';
      else
	 return round(bytes, precision) .. ' Bytes';
      end
   end
end

-- ###############################################

function pairsByKeys(t, f)
   local a = {}

   -- io.write(debug.traceback().."\n")
   for n in pairs(t) do table.insert(a, n) end
   table.sort(a, f)
   local i = 0      -- iterator variable
   local iter = function ()   -- iterator function
      i = i + 1
      if a[i] == nil then return nil
      else return a[i], t[a[i]]
      end
   end
   return iter
end

-- ###############################################

function pairsByValues(t, f)
   local a = {}
   for n in pairs(t) do table.insert(a, n) end
   table.sort(a, function(x, y) return f(t[x], t[y]) end)
   local i = 0      -- iterator variable
   local iter = function ()   -- iterator function
      i = i + 1
      if a[i] == nil then return nil
      else return a[i], t[a[i]]
      end
   end
   return iter
end

-- ###############################################

function asc(a,b) return (a < b) end
function rev(a,b) return (a > b) end

-- ###############################################

local function BitOR(a,b)--Bitwise or
   local p,c=1,0
   while a+b>0 do
      local ra,rb=a%2,b%2
      if ra+rb>0 then c=c+p end
      a,b,p=(a-ra)/2,(b-rb)/2,p*2
   end
   return c
end

local function BitNOT(n)
   local p,c=1,0
   while n>0 do
      local r=n%2
      if r<1 then c=c+p end
      n,p=(n-r)/2,p*2
   end
   return c
end

local function BitAND(a,b)--Bitwise and (portable edition)
   local p,c=1,0
   while a>0 and b>0 do
      local ra,rb=a%2,b%2
      if ra+rb>1 then c=c+p end
      a,b,p=(a-ra)/2,(b-rb)/2,p*2
   end
   return c
end

-- ###############################################

function ndpi_proto.init()
   ndpi_protos            = { }
   ndpi_flows             = { }

   num_ndpi_flows         = 0
   lower_ndpi_flow_id     = 0
   lower_ndpi_flow_volume = 0
   num_pkts               = 0
   last_processed_packet_number = 0

   -- ARP
   arp_stats              = { }

   -- MAC
   mac_stats              = { }

   -- VLAN
   vlan_stats             = { }
   vlan_found             = false

   -- TCP
   syn                    = {}
   synack                 = {}
   tcp_host_fingerprints  = {}
   tcp_fingerprint_hosts  = {}

   -- TLS
   tls_server_names       = {}
   tot_tls_flows          = 0
   tls_ja4_flows          = {}
   tls_ja4_clients        = {} -- JA4 signature per client

   -- HTTP
   http_ua                = {}
   tot_http_ua_flows      = 0

   -- Obfuscated servers
   possible_obfuscated_servers = {}
   tot_obfuscated_flows        = 0

   -- Flows
   flows                  = {}
   tot_flows              = 0

   -- Risks
   flows_with_risks      = {}

   -- DHCP
   dhcp_fingerprints      = {}

   -- DNS
   dns_responses_ok       = {}
   dns_responses_error    = {}
   dns_client_queries     = {}
   dns_server_responses   = {}
   top_dns_queries        = {}
   num_top_dns_queries    = 0

   -- TCP analysis
   num_tcp_retrans        = 0
   num_tcp_ooo            = 0
   num_tcp_lost_segment   = 0
   tcp_retrans            = {}
   tcp_ooo                = {}
   tcp_lost_segment       = {}

   -- Network RRT
   min_nw_client_RRT  = {}
   min_nw_server_RRT  = {}
   max_nw_client_RRT  = {}
   max_nw_server_RRT  = {}

   -- Application Latency
   min_nw_client_RRT     = {}
   min_nw_server_RRT     = {}
   max_nw_client_RRT     = {}
   max_nw_server_RRT     = {}
   min_appl_RRT          = {}
   max_appl_RRT          = {}
   first_payload_ts      = {}
   first_payload_id      = {}

   -- RPC
   rpc_ts                = {}

   -- STUN
   stun_request_table = {}
   stun_flows_table = {}

   if(dump_timeseries) then
      file = assert(io.open(dump_file, "a"))
      print("Writing to "..dump_file.."\n")
      print('Load data with:\ncurl -i -XPOST "http://localhost:8086/write?db=wireshark" --data-binary @/tmp/wireshark-influx.txt\n')
   end
end

function slen(str)
   local i = 1
   local len = 0
   local zero = string.char(0)

   for i = 1, 16 do
      local c = str:sub(i,i)

      if(c ~= zero) then
	 len = len + 1
      else
	 break
      end
   end

   return(str:sub(1, len))
end

-- Print contents of `tbl`, with indentation.
-- You can call it as tprint(mytable)
-- The other two parameters should not be set
function tprint(s, l, i)
   l = (l) or 1000; i = i or "";-- default item limit, indent string
   if (l<1) then io.write("ERROR: Item limit reached.\n"); return l-1 end;
   local ts = type(s);
   if (ts ~= "table") then io.write(i..' '..ts..' '..tostring(s)..'\n'); return l-1 end
   io.write(i..' '..ts..'\n');
   for k,v in pairs(s) do
      local indent = ""

      if(i ~= "") then
	 indent = i .. "."
      end
      indent = indent .. tostring(k)

      l = tprint(v, l, indent);
      if (l < 0) then break end
   end

   return l
end

-- ###############################################

local function getstring(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = "(unknown)" end
   return val
end

local function getval(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = nil end
   return val
end

function dump_pinfo(pinfo)
   local fields = { all_field_infos() }
   for ix, finfo in ipairs(fields) do
      --  output = output .. "\t[" .. ix .. "] " .. finfo.name .. " = " .. getstring(finfo) .. "\n"
      --print(finfo.name .. "\n")
      print("\t[" .. ix .. "] " .. finfo.name .. " = " .. getstring(finfo) .. "\n")
   end
end

-- ###############################################


function initARPEntry(mac)
   if(arp_stats[mac] == nil) then
      arp_stats[mac] = { request_sent=0, request_rcvd=0, response_sent=0, response_rcvd=0 }
   end
end

function dissectARP(isRequest, src_mac, dst_mac)
   if(isRequest == 1) then
      -- ARP Request
      initARPEntry(src_mac)
      arp_stats[src_mac].request_sent = arp_stats[src_mac].request_sent + 1

      initARPEntry(dst_mac)
      arp_stats[dst_mac].request_rcvd = arp_stats[dst_mac].request_rcvd + 1
   else
      -- ARP Response
      initARPEntry(src_mac)
      arp_stats[src_mac].response_sent = arp_stats[src_mac].response_sent + 1

      initARPEntry(dst_mac)
      arp_stats[dst_mac].response_rcvd = arp_stats[dst_mac].response_rcvd + 1
   end
end

-- ###############################################

function abstime_diff(a, b)
   return(tonumber(a)-tonumber(b))
end

-- ###############################################

function arp_dissector(tvb, pinfo, tree)
   local arp_opcode = f_arp_opcode()

   if(arp_opcode ~= nil) then
      -- ARP
      local isRequest = getval(arp_opcode)
      local src_mac = getval(f_arp_sender_mac())
      local dst_mac = getval(f_arp_target_mac())
      dissectARP(isRequest, src_mac, dst_mac)
   end
end

-- ###############################################

function vlan_dissector(tvb, pinfo, tree)
   local vlan_id = f_vlan_id()
   if(vlan_id ~= nil) then
      vlan_id = tonumber(getval(vlan_id))

      if(vlan_stats[vlan_id] == nil) then vlan_stats[vlan_id] = 0 end
      vlan_stats[vlan_id] = vlan_stats[vlan_id] + 1
      vlan_found = true
   end
end

-- ###############################################

function mac_dissector(tvb, pinfo, tree)
   local src_mac = tostring(pinfo.dl_src)
   local src_ip  = tostring(pinfo.src)
   if(mac_stats[src_mac] == nil) then mac_stats[src_mac] = {} end
   mac_stats[src_mac][src_ip] = 1
end

-- ###############################################

function tls_dissector(tvb, pinfo, tree)
   local tls_server_name = f_tls_server_name()
   local tls_ja4         = f_tls_ja4()
   local src_ip          = f_src_ip()
   local stream_id       = f_tcp_stream()
   local app

   stream_id = getval(stream_id)

   app = stream_app[stream_id]
   if(app ~= nil) then
      local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb)

      ndpi_subtree:add(ndpi_fds.name, app)
      return
   end

   if(tls_server_name ~= nil) then
      tls_server_name = getval(tls_server_name)

      if(tls_server_names[tls_server_name] == nil) then
	 tls_server_names[tls_server_name] = 0
      end

      tls_server_names[tls_server_name] = tls_server_names[tls_server_name] + 1
      tot_tls_flows = tot_tls_flows + 1
   end

   if(tls_ja4 ~= nil) then
      tls_ja4 = getval(tls_ja4)
      if(src_ip == nil) then
	 src_ip = f_src_ipv6()
      end

      src_ip  = getval(src_ip)

      if(src_ip ~= nil) then
	 if(tls_ja4_clients[tls_ja4] == nil) then
	    tls_ja4_clients[tls_ja4] = {}
	 end

	 tls_ja4_clients[tls_ja4][src_ip] = true
      end

      if(tls_ja4_flows[tls_ja4] == nil) then
	 tls_ja4_flows[tls_ja4] = 0
      end

      tls_ja4_flows[tls_ja4] = tls_ja4_flows[tls_ja4] + 1
      tot_tls_ja4_flows = tot_tls_ja4_flows + 1

      -- Check if this is a known JA4
      m = string.split(tls_ja4, "_")
      key = m[2] .. "_" .. m[3]

      if(ja4_db[key] ~= nil) then
	 local value = ja4_db[key]
	 local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb)

	 ndpi_subtree:add(ndpi_fds.name, value)
	 stream_app[stream_id] = value
      end
   end
end

-- ###############################################

function http_dissector(tvb, pinfo, tree)
   local user_agent = f_user_agent()
   if(user_agent ~= nil) then
      local srckey = tostring(pinfo.src)

      user_agent = getval(user_agent)

      if(http_ua[user_agent] == nil) then
	 http_ua[user_agent] = { }
	 tot_http_ua_flows = tot_http_ua_flows + 1
      end

      if(http_ua[user_agent][srckey] == nil) then
	 http_ua[user_agent][srckey] = 1
	 -- io.write("Adding ["..user_agent.."] @ "..srckey.."\n")
      end
   end
end

-- ###############################################

function timeseries_dissector(tvb, pinfo, tree)
   if(pinfo.dst_port ~= 0) then
      local rev_key = getstring(pinfo.dst)..":"..getstring(pinfo.dst_port).."-"..getstring(pinfo.src)..":"..getstring(pinfo.src_port)
      local k

      if(flows[rev_key] ~= nil) then
	 flows[rev_key][2] = flows[rev_key][2] + pinfo.len
	 k = rev_key
      else
	 local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).."-"..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)

	 k = key
	 if(flows[key] == nil) then
	    flows[key] = { pinfo.len, 0 } -- src -> dst  / dst -> src
	    tot_flows = tot_flows + 1
	 else
	    flows[key][1] = flows[key][1] + pinfo.len
	 end
      end

      --k = pinfo.curr_proto..","..k

      local bytes = flows[k][1]+flows[k][2]
      local row

      -- Prometheus
      -- row = "wireshark {metric=\"bytes\", flow=\""..k.."\"} ".. bytes .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"

      -- Influx
      row = "wireshark,flow="..k.." bytes=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,ndpi="..ndpi.protocol_name.." bytes=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,host="..getstring(pinfo.src).." sent=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,host="..getstring(pinfo.dst).." rcvd=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      -- print(row)

      file:flush()
   end
end

-- ###############################################

function risk_dissector(tvb, pinfo, tree)
   if(pinfo.dst_port ~= 0) then
      local rev_key = getstring(pinfo.dst)..":"..getstring(pinfo.dst_port).."-"..getstring(pinfo.src)..":"..getstring(pinfo.src_port)
      local k

      if(flows[rev_key] ~= nil) then
	 flows[rev_key][2] = flows[rev_key][2] + pinfo.len
	 k = rev_key
      else
	 local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).."-"..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)

	 k = key
	 if(flows[key] == nil) then
	    flows[key] = { pinfo.len, 0 } -- src -> dst  / dst -> src
	    tot_flows = tot_flows + 1
	 else
	    flows[key][1] = flows[key][1] + pinfo.len
	 end
      end

      --k = pinfo.curr_proto..","..k

      local bytes = flows[k][1]+flows[k][2]
      local row

      -- Prometheus
      -- row = "wireshark {metric=\"bytes\", flow=\""..k.."\"} ".. bytes .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"

      -- Influx
      row = "wireshark,flow="..k.." bytes=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,ndpi="..ndpi.protocol_name.." bytes=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,host="..getstring(pinfo.src).." sent=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      row = "wireshark,host="..getstring(pinfo.dst).." rcvd=".. pinfo.len .. " ".. (tonumber(pinfo.abs_ts)*10000).."00000"
      file:write(row.."\n")

      -- print(row)

      file:flush()
   end
end

-- ###############################################

function dhcp_dissector(tvb, pinfo, tree)
   local req_item = f_dhcp_request_item()

   if(req_item ~= nil) then
      local srckey = tostring(f_eth_source())
      local req_table = { f_dhcp_request_item() }
      local fingerprint = ""

      for k,v in pairs(req_table) do
	 fingerprint = fingerprint .. string.format("%02X", v.value)
      end

      dhcp_fingerprints[srckey] = fingerprint

      if(pinfo.visited == true) then
	 local dhcp_f_entry = tree:add(ntop_proto, tvb())
	 dhcp_f_entry:add(ntop_fds.dhcp_fingerprint, fingerprint)
      end
   end
end

-- ###############################################

function dns_dissector(tvb, pinfo, tree)
   local dns_response = f_dns_response()
   if(dns_response ~= nil) then
      local dns_ret_code = f_dns_ret_code()
      local dns_response = dns_response() -- conversion to true/false. We can't use tonumber() on Bool
      local srckey = tostring(pinfo.src)
      local dstkey = tostring(pinfo.dst)
      local dns_query_name = f_dns_query_name()
      dns_query_name = getval(dns_query_name)

      if(dns_response == false) then
	 -- DNS Query
	 if(dns_client_queries[srckey] == nil) then dns_client_queries[srckey] = 0 end
	 dns_client_queries[srckey] = dns_client_queries[srckey] + 1

	 if(dns_query_name ~= nil) then
	    if(top_dns_queries[dns_query_name] == nil) then
	       top_dns_queries[dns_query_name] = 0
	       num_top_dns_queries = num_top_dns_queries + 1

	       if(num_top_dns_queries > max_num_dns_queries) then
		  -- We need to harvest the flow with least packets beside this new one
		  for k,v in pairsByValues(dns_client_queries, asc) do
		     if(k ~= dns_query_name) then
			table.remove(ndpi_flows, k)
			num_top_dns_queries = num_top_dns_queries - 1

			if(num_top_dns_queries == (2*max_num_entries)) then
			   break
			end
		     end
		  end
	       end
	    end

	    top_dns_queries[dns_query_name] = top_dns_queries[dns_query_name] + 1
	 end
      else
	 -- DNS Response
	 if(dns_server_responses[srckey] == nil) then dns_server_responses[srckey] = 0 end
	 dns_server_responses[srckey] = dns_server_responses[srckey] + 1

	 if(dns_ret_code ~= nil) then
	    dns_ret_code = getval(dns_ret_code)

	    if((dns_query_name ~= nil) and (dns_ret_code ~= nil)) then
	       dns_ret_code = tonumber(dns_ret_code)

	       if(debug) then print("[".. srckey .." -> ".. dstkey .."] "..dns_query_name.."\t"..dns_ret_code) end

	       if(dns_ret_code == 0) then
		  if(dns_responses_ok[srckey] == nil) then dns_responses_ok[srckey] = 0 end
		  dns_responses_ok[srckey] = dns_responses_ok[srckey] + 1
	       else
		  if(dns_responses_error[srckey] == nil) then dns_responses_error[srckey] = 0 end
		  dns_responses_error[srckey] = dns_responses_error[srckey] + 1
	       end
	    end
	 end
      end
   end
end

-- ###############################################

function rpc_dissector(tvb, pinfo, tree)
   local _rpc_xid      = f_rpc_xid()
   local _rpc_msgtyp   = f_rpc_msgtyp()

   if((_rpc_xid ~= nil) and (_rpc_msgtyp ~= nil)) then
      local xid    = getval(_rpc_xid)
      local msgtyp = getval(_rpc_msgtyp)

      if(msgtyp == "0") then
	 rpc_ts[xid] = pinfo.abs_ts
      else
	 if(rpc_ts[xid] ~= nil) then
	    local appl_latency = abstime_diff(pinfo.abs_ts, rpc_ts[xid]) * 1000

	    if((appl_latency > 0) and (appl_latency < max_appl_lat_discard)) then
	       local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")

	       ntop_subtree:add(ntop_fds.appl_latency_rtt, appl_latency)
	    end
	 end
      end
   end
end

-- ###############################################

function tcp_fingerprint(tvb, pinfo, tree, ip_version)
   local tcp_flags = getval(f_tcp_flags())

   if((tcp_flags == "0x0002")-- SYN
      or (tcp_flags == "0x00c2") -- SYN / ECE / CWR
   ) then
      local tcp_options = f_tcp_options()
      
      if(tcp_options ~= nil) then
	 local tcp_win = getval(f_tcp_win())
	 local fingerprint = ""	 
	 local d_tcp_options = tcp_options.display
	 local d_tcp_options_len = d_tcp_options:len()
	 local tcp_opt_debug = false

	 if(tcp_win == "nil") then tcp_win = 0 end
	 
	 i = 1
	 while(i < d_tcp_options_len) do
	    if(tcp_opt_debug) then tprint("[offset "..i .. "/".. d_tcp_options:len().."]") end
	    
	    local kind = d_tcp_options:sub(i,i+1)

	    if(tcp_opt_debug) then tprint("[Kind: " .. kind .."] *** ") end
	    
	    i = i + 2 -- Skip kind

	    fingerprint = fingerprint .. kind
	    
	    if(kind == "00") then
	       -- EOL
	       if(tcp_opt_debug) then tprint("[" .. kind .."][EOL]") end
	    elseif(kind == "01") then
	       -- NOP
	       if(tcp_opt_debug) then tprint("[" .. kind .."][NOP]") end
	    else
	       local len = d_tcp_options:sub(i, i+1)

	       if(tcp_opt_debug) then tprint("[Len: " .. len .."] *** ") end

	       len = tonumber(len, 16)
	       i = i + 2 -- Skip len

	       if((len ~= nil) and (len > 0)) then
		  local value_len = 2 * (len-2)
		  local value	   
		  
		  if(tcp_opt_debug) then tprint("[ValueLen: " .. value_len .."] *** ") end

		  -- Skip timestamps
		  if((kind ~= "08") and (value_len > 0)) then		     		  
		     value = d_tcp_options:sub(i, i+value_len)
		     value = value:sub(1, value_len) -- make sure the lenght is correct
		     if(tcp_opt_debug) then tprint("[" .. kind .."][len: ".. len .."][value: ".. value.."]") end

		     fingerprint = fingerprint .. value
		  end
		  
		  i = i + value_len
	       end
	    end
	 end -- while
	 
	 local ip_ttl
	 local src_ip
	 
	 if(ip_version == 6) then
	    ip_ttl = getval(f_ipv6_hlim())
	    src_ip = f_src_ipv6()
	 else
	    ip_ttl = getval(f_ip_ttl())
	    src_ip = f_src_ip()
	 end
	 
	 src_ip  = getval(src_ip)

	 -- Normalize TTL
	 ip_ttl = tonumber(ip_ttl)
	 if(ip_ttl <= 32) then      ip_ttl = 32
	 elseif(ip_ttl <= 64)  then ip_ttl = 64
	 elseif(ip_ttl <= 128) then ip_ttl = 128
	 elseif(ip_ttl <= 192) then ip_ttl = 192
	 else ip_ttl = 255     end

	 fingerprint = string.lower(fingerprint)

	 local f_print
	 local num_tcp_flags = tostring(tonumber(string.sub(tcp_flags, 3), 16))

	 if(true) then
	    -- Use SHA256
	    f_print = string.lower(num_tcp_flags.."_"..ip_ttl .."_".. tcp_win .."_".. string.sub(sha256(fingerprint), 1, 12))
	 else
	    f_print = string.upper(num_tcp_flags.."_"..ip_ttl .."_".. tcp_win .."_".. fingerprint)
	 end

	 if(tcp_opt_debug) then tprint("Fingerprint: " .. f_print) end
	 
	 local tcp_f_entry = tree:add(ntop_proto, tvb())
	 tcp_f_entry:add(ntop_fds.tcp_fingerprint, f_print)
	 
	 tcp_host_fingerprints[src_ip] = f_print	 

	 if(tcp_fingerprint_hosts[f_print] == nil) then
	    tcp_fingerprint_hosts[f_print] = {}
	 end
	 
	 tcp_fingerprint_hosts[f_print][src_ip] = 1
      end
   end
end

-- ###############################################

function tcp_dissector(tvb, pinfo, tree, ip_version)
   local _tcp_retrans      = f_tcp_retrans()
   local _tcp_ooo          = f_tcp_ooo()
   local _tcp_lost_segment = f_tcp_lost_segment()

   tcp_fingerprint(tvb, pinfo, tree, ip_version)
   
   if(_tcp_retrans ~= nil) then
      local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).." -> "..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)
      num_tcp_retrans = num_tcp_retrans + 1
      if(tcp_retrans[key] == nil) then tcp_retrans[key] = 0 end
      tcp_retrans[key] = tcp_retrans[key] + 1
   end

   if(_tcp_ooo ~= nil) then
      local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).." -> "..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)
      num_tcp_ooo = num_tcp_ooo + 1
      if(tcp_ooo[key] == nil) then tcp_ooo[key] = 0 end
      tcp_ooo[key] = tcp_ooo[key] + 1
   end

   if(_tcp_lost_segment ~= nil) then
      local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).." -> "..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)
      num_tcp_lost_segment = num_tcp_lost_segment + 1
      if(tcp_lost_segment[key] == nil) then tcp_lost_segment[key] = 0 end
      tcp_lost_segment[key] = tcp_lost_segment[key] + 1
   end
end

-- ###############################################

function latency_dissector(tvb, pinfo, tree)
   local _tcp_flags = f_tcp_flags()
   local udp_len    = f_udp_len()

   if((_tcp_flags ~= nil) or (udp_len ~= nil)) then
      local key
      local rtt_debug = false
      local tcp_flags
      local tcp_header_len
      local ip_len
      local ip_hdr_len

      if(udp_len == nil) then
	 tcp_flags      = f_tcp_flags().value
	 tcp_header_len = f_tcp_header_len()
	 ip_len         = f_ip_len()
	 ip_hdr_len     = f_ip_hdr_len()
      end

      if(((ip_len ~= nil) and (tcp_header_len ~= nil) and (ip_hdr_len ~= nil))
	 or (udp_len ~= nil)
      ) then
	 local payloadLen

	 if(udp_len == nil) then
	    ip_len         = tonumber(getval(ip_len))
	    tcp_header_len = tonumber(getval(tcp_header_len))
	    ip_hdr_len     = tonumber(getval(ip_hdr_len))

	    payloadLen = ip_len - tcp_header_len - ip_hdr_len
	 else
	    payloadLen = tonumber(getval(udp_len))
	 end

	 if(payloadLen > 0) then
	    local key = getstring(pinfo.src).."_"..getstring(pinfo.src_port).."_"..getstring(pinfo.dst).."_"..getstring(pinfo.dst_port)
	    local revkey = getstring(pinfo.dst).."_"..getstring(pinfo.dst_port).."_"..getstring(pinfo.src).."_"..getstring(pinfo.src_port)

	    if(first_payload_ts[revkey] ~= nil) then
	       local appl_latency = abstime_diff(pinfo.abs_ts, first_payload_ts[revkey]) * 1000

	       if((appl_latency > 0) and (appl_latency < max_appl_lat_discard)
		  -- The trick below is used to set only the first latency packet
		  and ((first_payload_id[revkey] == nil) or (first_payload_id[revkey] == pinfo.number))
	       ) then
		  local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")
		  local server = getstring(pinfo.src)

		  if(rtt_debug) then print("==> Appl Latency @ "..pinfo.number..": "..appl_latency) end

		  ntop_subtree:add(ntop_fds.appl_latency_rtt, appl_latency)
		  first_payload_id[revkey] = pinfo.number

		  if(min_appl_RRT[server] == nil) then
		     min_appl_RRT[server] = appl_latency
		  else
		     min_appl_RRT[server] = math.min(min_appl_RRT[server], appl_latency)
		  end

		  if(max_appl_RRT[server] == nil) then
		     max_appl_RRT[server] = appl_latency
		  else
		     max_appl_RRT[server] = math.max(max_appl_RRT[server], appl_latency)
		  end

		  -- first_payload_ts[revkey] = nil
	       end
	    else
	       if(first_payload_ts[key] == nil) then first_payload_ts[key] = pinfo.abs_ts end
	    end
	 end
      end

      tcp_flags = tonumber(tcp_flags)

      if(tcp_flags == 2) then
	 -- SYN
	 key = getstring(pinfo.src).."_"..getstring(pinfo.src_port).."_"..getstring(pinfo.dst).."_"..getstring(pinfo.dst_port)
	 if(rtt_debug) then print("SYN @ ".. pinfo.abs_ts.." "..key) end
	 syn[key] = pinfo.abs_ts
      elseif(tcp_flags == 18) then
	 -- SYN|ACK
	 key = getstring(pinfo.dst).."_"..getstring(pinfo.dst_port).."_"..getstring(pinfo.src).."_"..getstring(pinfo.src_port)
	 if(rtt_debug) then print("SYN|ACK @ ".. pinfo.abs_ts.." "..key) end
	 synack[key] = pinfo.abs_ts
	 if(syn[key] ~= nil) then
	    local diff = abstime_diff(synack[key], syn[key]) * 1000 -- msec

	    if(rtt_debug) then print("Server RTT --> ".. diff .. " msec") end

	    if(diff <= max_latency_discard) then
	       local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")
	       ntop_subtree:add(ntop_fds.server_nw_rtt, diff)
	       -- Do not delete the key below as it's used when a user clicks on a packet
	       -- syn[key] = nil

	       local server = getstring(pinfo.src)
	       if(min_nw_server_RRT[server] == nil) then
		  min_nw_server_RRT[server] = diff
	       else
		  min_nw_server_RRT[server] = math.min(min_nw_server_RRT[server], diff)
	       end

	       if(max_nw_server_RRT[server] == nil) then
		  max_nw_server_RRT[server] = diff
	       else
		  max_nw_server_RRT[server] = math.max(max_nw_server_RRT[server], diff)
	       end
	    end
	 end
      elseif(tcp_flags == 16) then
	 -- ACK
	 key = getstring(pinfo.src).."_"..getstring(pinfo.src_port).."_"..getstring(pinfo.dst).."_"..getstring(pinfo.dst_port)
	 if(rtt_debug) then print("ACK @ ".. pinfo.abs_ts.." "..key) end

	 if(synack[key] ~= nil) then
	    local diff = abstime_diff(pinfo.abs_ts, synack[key]) * 1000 -- msec
	    if(rtt_debug) then print("Client RTT --> ".. diff .. " msec") end

	    if(diff <= max_latency_discard) then
	       local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")
	       ntop_subtree:add(ntop_fds.client_nw_rtt, diff)

	       -- Do not delete the key below as it's used when a user clicks on a packet
	       synack[key] = nil

	       local client = getstring(pinfo.src)
	       if(min_nw_client_RRT[client] == nil) then
		  min_nw_client_RRT[client] = diff
	       else
		  min_nw_client_RRT[client] = math.min(min_nw_client_RRT[client], diff)
	       end

	       if(max_nw_client_RRT[client] == nil) then
		  max_nw_client_RRT[client] = diff
	       else
		  max_nw_client_RRT[client] = math.max(max_nw_client_RRT[client], diff)
	       end
	    end
	 end
      end
   end
end

-- ###############################################

function stun_dissector(tvb, pinfo, tree)
   if(pinfo.visited == true) then
      local id_packet = pinfo.number
      local udp_traffic = f_udp_traffic()

      if udp_traffic then
	 if stun_old_id_packet > id_packet then
	    stun_processed_packets = stun_flows_table
	    stun_flows_table = {}
	    stun_old_id_packet = id_packet
	 end

	 local src = getstring(f_src_ip())
	 local dst = getstring(f_dst_ip())
	 local src_port = getstring(f_src_port())
	 local dst_port = getstring(f_dst_port())
	 local stun_type = getstring(f_stun_type())
	 local stun_length = getstring(f_stun_length())
	 local classic_type = getstring(f_stun_classic_type())
	 local stun_username = f_stun_username()
	 local stun_tie_breaker = f_stun_tie_breaker()
	 local stun_unknown_att = f_stun_unknown_att()
	 local stun_realm = f_stun_realm()
	 local stun_nonce = f_stun_nonce()
	 local stun_software = f_stun_software()
	 local stun_ip_xor = f_stun_ip_xor()
	 local stun_ms_version = f_stun_ms_version()
	 local stun_ms_version_ice = f_stun_ms_version_ice()
	 local stun_request = f_stun_response_to()
	 local protocol = ndpi_proto_unknown

	 local key = src..":"..src_port.." <--> "..dst..":"..dst_port
	 local key2 = dst..":"..dst_port.." <--> "..src..":"..src_port

	 --     Send Data
	 if stun_type == "0x0016"  then
	    -- da sistemare, guarda meet_test1.pcap
	    protocol = (stun_flows_table[key] ~= nil) and stun_flows_table[key] or (stun_flows_table[key2] ~= nil) and stun_flows_table[key2] or ndpi_proto_unknown

	    --  Data Indication
	 elseif stun_type == "0x0017" then
	    protocol = (stun_software ~= nil) and ndpi_proto_telegram or ndpi_proto_teams
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    --	Create Permission Request
	 elseif stun_type == "0x0008" then
	    protocol = (getstring(stun_realm) == "telegram.org") and ndpi_proto_telegram or ndpi_proto_teams
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Refresh Request
	 elseif stun_type == "0x0004" then
	    protocol = (stun_ms_version ~= nil and stun_username ~= nil) and ndpi_proto_teams or (getstring(stun_realm) == "telegram.org") and ndpi_proto_telegram or ndpi_proto_teams
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Create Permission Response
	 elseif stun_type =="0x0108" then
	    protocol = (stun_software ~= nil) and ndpi_proto_telegram or ndpi_proto_teams
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Refresh Success Response
	 elseif stun_type == "0x0104" then
	    protocol = (stun_software ~= nil) and ndpi_proto_telegram or ndpi_proto_teams
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- unknown request whatsapp
	 elseif stun_type == "0x0800" then
	    protocol = ndpi_proto_whatsapp
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- binding request
	 elseif stun_type == "0x0001" then
	    local telegram_tie_breaker = "00:00:00:00:00:00:00:00"

	    if (stun_username and stun_unknown_att) or stun_ms_version_ice ~= nil or stun_ms_version  ~= nil then
	       protocol = ndpi_proto_teams
	    elseif stun_tie_breaker ~= nil and stun_username ~= nil then
	       if getstring(stun_tie_breaker) == telegram_tie_breaker   and getstring(stun_username):len()== 9 then
		  protocol = ndpi_proto_telegram
	       elseif getstring(stun_tie_breaker) ~= telegram_tie_breaker and getstring(stun_username):len()== 9  then
		  protocol = ndpi_proto_teams
	       elseif getstring(stun_username):len() == 73 then
		  protocol = "Zoom"
	       elseif getstring(stun_tie_breaker) ~= telegram_tie_breaker and getstring(stun_username):len()~= 9  then
		  protocol = ndpi_proto_meet
	       end
	    elseif tonumber(stun_length) == 0 then
	       protocol = (stun_flows_table[key] ~= nil) and stun_flows_table[key] or (stun_flows_table[key2] ~= nil) and stun_flows_table[key2] or ndpi_proto_unknown

	    elseif tonumber(stun_length) == 24 then
	       protocol = ndpi_proto_whatsapp
	    end

	    stun_request_table[getstring(pinfo.number)]= protocol
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- binding request
	 elseif classic_type == "0x0001" then
	    protocol = "Zoom"
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- binding success response
	 elseif classic_type == "0x0101"then
	    protocol = "Zoom"
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- shared Secret Request
	 elseif classic_type == "0x0002" then
	    protocol = "Zoom"
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- allocate request
	 elseif stun_type == "0x0003" then
	    if stun_ms_version then
	       protocol = ndpi_proto_teams
	    elseif stun_unknown_att then
	       protocol = ndpi_proto_whatsapp
	    elseif stun_realm and stun_nonce and stun_username then
	       protocol = ndpi_proto_telegram
	    else
	       protocol = ndpi_proto_telegram
	    end
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- binding success response
	 elseif stun_type == "0x0101" then

	    if tonumber(stun_length) == 44 or tonumber(stun_length) == 12 then
	       protocol = stun_request_table[getstring(stun_request)]
	    else
	       if stun_ms_version_ice then
		  protocol = ndpi_proto_teams
	       elseif stun_software then
		  protocol = ndpi_proto_telegram
	       elseif (stun_software == nil) and stun_ip_xor then
		  protocol = ndpi_proto_meet
	       elseif tonumber(stun_length) == 24 then
		  protocol = ndpi_proto_whatsapp
	       end
	    end
	    if stun_request_table[getstring(stun_request)] ~= nil and protocol ~= stun_request_table[getstring(stun_request)] then
	       protocol = stun_request_table[getstring(stun_request)]

	    end
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Allocate Success Response
	 elseif stun_type == "0x0103" then
	    protocol = (stun_ms_version ~= nil) and ndpi_proto_teams or (stun_software ~= nil) and ndpi_proto_telegram or ndpi_proto_whatsapp
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Allocate Error Response
	 elseif stun_type == "0x0113"  then
	    protocol = (stun_ms_version ~= nil) and ndpi_proto_teams or (stun_realm ~= nil) and ndpi_proto_telegram or ndpi_proto_unknown
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)

	    -- Create permission error response
	 elseif stun_type == "0x0118"  then
	    protocol = ndpi_proto_telegram
	    stun_flows_table = stun_develop_table(stun_flows_table,key,key2,protocol)
	 end

	 if(protocol ~= ndpi_proto_unknown) then
	    local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb, "nDPI Protocol")
	    ndpi_subtree:add(ndpi_fds.name, protocol)
	    stun_old_id_packet = id_packet
	 elseif(protocol == ndpi_proto_unknown) then
	    if stun_flows_table[key] ~= nil then
	       local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb, "nDPI Protocol")
	       ndpi_subtree:add(ndpi_fds.name,stun_flows_table[key])
	    elseif stun_flows_table[key2] ~= nil then
	       local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb, "nDPI Protocol")
	       ndpi_subtree:add(ndpi_fds.name,stun_flows_table[key2])
	    elseif stun_old_id_packet > id_packet then
	       protocol = stun_processed_packets[key] ~= nil and stun_processed_packets[key] or stun_processed_packets[key2] ~= nil and stun_processed_packets[key2] or ndpi_proto_unknown
	       local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb, "nDPI Protocol")
	       ndpi_subtree:add(ndpi_fds.name,protocol)
	    end

	    stun_old_id_packet = id_packet
	 end
      end
   end
end

-- end########################################

function hasbit(x, p)
   return x % (p + p) >= p
end

-- the dissector function callback
function ndpi_proto.dissector(tvb, pinfo, tree)
   local ip_proto     = getval(f_ip_proto())
   local ip6_next_hdr = getval(f_ipv6_next_hdr())

   -- Wireshark dissects the packet twice. General rule:
   --  * proto fields must be add in both cases (to be compatible with tshark)
   --  * statistics should be gather onl on first pass

   if(dissect_ndpi_trailer) then
      local eth_trailer = {f_eth_trailer()}
      local vlan_trailer = {f_vlan_trailer()}
      local sll_trailer = {f_sll_trailer()}

      -- nDPI trailer is usually the (only one) ethernet trailer.
      -- But, depending on Wireshark configuration, on L2 protocols and on data link type, the
      -- situation may be more complex. Let's try to handle the most common cases:
      --  1) with (multiple) ethernet trailers, nDPI trailer is usually the last one
      --  2) with VLAN encapsulation, nDPI trailer is usually recognized as vlan trailer
      --  3) with Linux "cooked" capture encapsulation, nDPI trailer is usually recognized as sll trailer
      -- Note that it might not work with PPP-like encapsulations
      if(eth_trailer[#eth_trailer] ~= nil or
         vlan_trailer[#vlan_trailer] ~= nil or
         sll_trailer[#sll_trailer] ~= nil) then

	 local ndpi_trailer
	 local trailer_tvb
	 if (eth_trailer[#eth_trailer] ~= nil) then
	    ndpi_trailer = getval(eth_trailer[#eth_trailer])
	    trailer_tvb = eth_trailer[#eth_trailer].range()
	 elseif(vlan_trailer[#vlan_trailer] ~= nil) then
	    ndpi_trailer = getval(vlan_trailer[#vlan_trailer])
	    trailer_tvb = vlan_trailer[#vlan_trailer].range()
	 else
	    ndpi_trailer = getval(sll_trailer[#sll_trailer])
	    trailer_tvb = sll_trailer[#sll_trailer].range()
	 end
	 local magic = string.sub(ndpi_trailer, 1, 11)

	 if(magic == "19:68:09:24") then
	    local ndpikey, srckey, dstkey, flowkey, flow_risk
	    local flow_risk_tree, flow_risk_info_len, metadata_list_tree, metadata_tree, metadata_list_len
	    local name
	    local ndpi_subtree = tree:add(ndpi_proto, trailer_tvb, "nDPI Protocol")
	    local application_protocol, mlen
	    local offset = 0

	    ndpi_subtree:add(ndpi_fds.magic, trailer_tvb(offset, 4))
	    offset = offset + 4
	    ndpi_subtree:add(ndpi_fds.network_protocol, trailer_tvb(offset, 2))
	    offset = offset + 2
	    ndpi_subtree:add(ndpi_fds.name, trailer_tvb(offset, 2))
	    application_protocol = trailer_tvb(offset, 2):int()
	    offset = offset + 2

	    ndpi_subtree:add(ndpi_fds.name, trailer_tvb(offset, 16))
	    name = trailer_tvb(offset, 16):string()
	    offset = offset + 16

	    if(application_protocol ~= 0) then
	       -- Set protocol name in the wireshark protocol column (if not Unknown)
	       pinfo.cols.protocol = name
	       --print(network_protocol .. "/" .. application_protocol .. "/".. name)
	    end

	    ndpi_subtree:add(ndpi_fds.flags, trailer_tvb(offset, 1))
	    ndpi_subtree:add(ndpi_fds.flags_direction, trailer_tvb(offset, 1))
	    local direction = trailer_tvb(offset, 1):bitfield(6,2) -- From left to right!! -> inverted values
	    ndpi_subtree:add(ndpi_fds.flags_dpi_state, trailer_tvb(offset, 1))
	    local dpi_state = trailer_tvb(offset, 1):bitfield(4,2) -- From left to right!! -> inverted values
	    offset = offset + 1

	    flow_risk_tree = ndpi_subtree:add(ndpi_fds.flow_risk, trailer_tvb(offset, 8))
	    flow_risk = trailer_tvb(offset, 8):uint64() -- UInt64 object!
	    offset = offset + 8
	    ndpi_subtree:add(ndpi_fds.flow_score, trailer_tvb(offset, 2))
	    flow_score = trailer_tvb(offset, 2):int()
	    offset = offset + 2

	    if (flow_risk ~= UInt64(0, 0)) then
               if(pinfo.visited == false) then
	          local rev_key = getstring(pinfo.dst)..":"..getstring(pinfo.dst_port).." - "..getstring(pinfo.src)..":"..getstring(pinfo.src_port)

	          if(flows_with_risks[rev_key] == nil) then
		     local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).." - "..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)

		     if(flows_with_risks[key] == nil) then
		        flows_with_risks[key] = flow_score
		     end
                  end
               end

	       for i=0,63 do
		  if flow_risks[i] ~= nil then
		     flow_risk_tree:add(flow_risks[i], trailer_tvb(25, 8))
		  end

	       end
	       flow_risk_tree:add(flow_risks[64], trailer_tvb(25, 8)) -- Unused bits in flow risk bitmask

	       flow_risk_obfuscated_traffic = trailer_tvb(25, 8):bitfield(7,1) -- From left to right
	    else
	       flow_risk_obfuscated_traffic = 0
	    end

	    if(flow_score > 0) then
	       local level
	       if(flow_score <= 10) then     -- NDPI_SCORE_RISK_LOW
		  level = PI_CHAT
	       elseif(flow_score <= 50) then -- NDPI_SCORE_RISK_MEDIUM
		  level = PI_NOTE
	       else
		  level = PI_WARN
	       end

	       ndpi_subtree:add_expert_info(PI_PROTOCOL, level, "Non zero score")
	    end

	    ndpi_subtree:add(ndpi_fds.flow_risk_info_len, trailer_tvb(offset, 2))
	    flow_risk_info_len = trailer_tvb(offset, 2):int()
	    offset = offset + 2
	    ndpi_subtree:add(ndpi_fds.flow_risk_info, trailer_tvb(offset, flow_risk_info_len))
	    offset = offset + flow_risk_info_len

	    -- Metadata
	    ndpi_subtree:add(ndpi_fds.metadata_list_len, trailer_tvb(offset, 2))
	    metadata_list_len = trailer_tvb(offset, 2):int()
	    offset = offset + 2
	    metadata_list_tree = ndpi_subtree:add(ndpi_fds.metadata_list, trailer_tvb(offset, metadata_list_len))
	    m_len = 0

	    while m_len + 4 < metadata_list_len do
	       local mtd_type = trailer_tvb(offset, 2):int();
	       local mtd_length = trailer_tvb(offset + 2, 2):int();

	       metadata_tree = metadata_list_tree:add(ndpi_fds.metadata, trailer_tvb(offset, 4 + mtd_length))
	       metadata_tree:add(ndpi_fds.metadata_type, trailer_tvb(offset, 2))
	       metadata_tree:add(ndpi_fds.metadata_length, trailer_tvb(offset + 2, 2))

	       -- Specific fields: there is definitely a better way...
	       if mtd_type == 0 then
		  metadata_tree:append_text(" Padding")
		  -- Generic field
		  metadata_tree:add(ndpi_fds.metadata_value, trailer_tvb(offset + 4, mtd_length))
	       elseif mtd_type == 1 then
		  metadata_tree:append_text(" ServerName: " .. trailer_tvb(offset + 4, mtd_length):string())
		  metadata_tree:add(ndpi_fds.metadata_server_name, trailer_tvb(offset + 4, mtd_length))
	       elseif mtd_type == 2 then
	          metadata_tree:append_text(" JA4C: " .. trailer_tvb(offset + 4, mtd_length):string())
	          metadata_tree:add(ndpi_fds.metadata_ja4c, trailer_tvb(offset + 4, mtd_length))
	       elseif mtd_type == 3 then
	          metadata_tree:append_text(" TLS Heuristic Fingerprint")
	          tls_tree = metadata_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint, trailer_tvb(offset + 4, mtd_length))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_bytes0, trailer_tvb(offset + 4, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_bytes1, trailer_tvb(offset + 8, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_bytes2, trailer_tvb(offset + 12, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_bytes3, trailer_tvb(offset + 16, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_pkts0, trailer_tvb(offset + 20, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_pkts1, trailer_tvb(offset + 24, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_pkts2, trailer_tvb(offset + 28, 4))
	          tls_tree:add(ndpi_fds.metadata_tls_heuristic_fingerprint_pkts3, trailer_tvb(offset + 32, 4))
	       else
		  -- Generic field
		  metadata_tree:add(ndpi_fds.metadata_value, trailer_tvb(offset + 4, mtd_length))
	       end

	       offset = offset + 4 + mtd_length
	       m_len = m_len + 4 + mtd_length
	    end

	    if(compute_flows_stats and pinfo.visited == false) then
	       ndpikey = tostring(slen(name))

	       if(ndpi_protos[ndpikey] == nil) then ndpi_protos[ndpikey] = 0 end
	       ndpi_protos[ndpikey] = ndpi_protos[ndpikey] + pinfo.len

	       srckey = tostring(pinfo.src)
	       dstkey = tostring(pinfo.dst)

	       flowkey = srckey.." / "..dstkey.."\t["..ndpikey.."]"
	       if(ndpi_flows[flowkey] == nil) then
		  ndpi_flows[flowkey] = 0
		  num_ndpi_flows = num_ndpi_flows + 1

		  if(num_ndpi_flows > max_num_flows) then
		     -- We need to harvest the flow with least packets beside this new one
		     local tot_removed = 0

		     for k,v in pairsByValues(ndpi_flows, asc) do
			if(k ~= flowkey) then
			   ndpi_flows[k] = nil -- Remove entry
			   num_ndpi_flows = num_ndpi_flows + 1
			   if(num_ndpi_flows == (2*max_num_entries)) then
			      break
			   end
			end
		     end
		  end
	       end

	       ndpi_flows[flowkey] = ndpi_flows[flowkey] + pinfo.len
	    end

	    if(track_obfuscated_servers and pinfo.visited == false) then
	       -- Only once per flow, when DPI ends
	       if(dpi_state == 1) then
		  if(direction == 2) then -- current packet from server to client
		     key = tostring(pinfo.src) .. ":" .. getstring(pinfo.src_port) .. " " .. name
		  else
		     key = tostring(pinfo.dst) .. ":" .. getstring(pinfo.dst_port) .. " " .. name
		  end
		  if(possible_obfuscated_servers[key] == nil) then
		     possible_obfuscated_servers[key] = {1, flow_risk_obfuscated_traffic}
		  else
		     possible_obfuscated_servers[key][1] = possible_obfuscated_servers[key][1] + 1
		     if(flow_risk_obfuscated_traffic == 1) then
			possible_obfuscated_servers[key][2] = possible_obfuscated_servers[key][2] + 1
		     end
		  end

		  if(flow_risk_obfuscated_traffic == 1) then
		     tot_obfuscated_flows = tot_obfuscated_flows + 1
		  end
	       end
	    end
	 end
      end -- nDPI

      -- These dissector add some proto fields
      latency_dissector(tvb, pinfo, tree)
      rpc_dissector(tvb, pinfo, tree)
   end

   -- ###########################################

   -- As we do not need to add fields to the dissection
   -- there is no need to process the packet multiple times
   num_pkts = num_pkts + 1
   if((num_pkts > 1) and (pinfo.number == 1)) then return end

   if(last_processed_packet_number < pinfo.number) then
      last_processed_packet_number = pinfo.number
   end

   -- print(num_pkts .. " / " .. pinfo.number .. " / " .. last_processed_packet_number)

   if(false) then
      local srckey = tostring(pinfo.src)
      local dstkey = tostring(pinfo.dst)
      --print("Processing packet "..pinfo.number .. "["..srckey.." / "..dstkey.."]")
   end

   if(dump_timeseries) then
      timeseries_dissector(tvb, pinfo, tree)
   end

   
   if(ip_proto == "6") then
      tcp_dissector(tvb, pinfo, tree, 4)      
   elseif(ip6_next_hdr == "6") then
      tcp_dissector(tvb, pinfo, tree, 6)
   end

   mac_dissector(tvb, pinfo, tree)
   arp_dissector(tvb, pinfo, tree)
   vlan_dissector(tvb, pinfo, tree)
   tls_dissector(tvb, pinfo, tree)
   http_dissector(tvb, pinfo, tree)
   dhcp_dissector(tvb, pinfo, tree)
   dns_dissector(tvb, pinfo, tree)
   stun_dissector(tvb, pinfo, tree)
end

register_postdissector(ndpi_proto)

-- ###############################################

local function flow_score_dialog_menu()
   local win = TextWindow.new("nDPI Flow Risks");
   local label = ""
   local i

   for k,v in pairsByValues(flows_with_risks, asc) do
      if(label == "") then
	 label = "Flows with positive score value:\n"
      end

      label = label .. "- " .. k .." [score: ".. v .."]\n"
   end

   if(label == "") then
      label = "No flows with score > 0 found"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function ndpi_dialog_menu()
   local win = TextWindow.new("nDPI Protocol Statistics");
   local label = ""
   local i

   if(ndpi_protos ~= {}) then
      local tot = 0
      label =          "nDPI Protocol Breakdown\n"
      label = label .. "-----------------------\n"

      for _,v in pairs(ndpi_protos) do
	 tot = tot + v
      end

      i = 0
      if(tot == 0) then return end
      
      for k,v in pairsByValues(ndpi_protos, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 label = label .. string.format("%-32s\t\t%s\t", k, bytesToSize(v)).. "\t["..pctg.."]\n"
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      -- #######

      label = label .. "\nTop nDPI Flows\n"
      label = label .. "-----------\n"
      i = 0
      for k,v in pairsByValues(ndpi_flows, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 label = label .. string.format("%-48s\t%s", k, bytesToSize(v)).. "\t["..pctg.."]\n"
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      win:set(label)
      win:add_button("Clear", function() win:clear() end)
   end
end

-- ###############################################

local function arp_dialog_menu()
   local win = TextWindow.new("ARP Statistics");
   local label = ""
   local _stats
   local found = false
   local tot_arp_pkts = 0

   _stats = {}
   for k,v in pairs(arp_stats) do
      if(k ~= "Broadcast") then
	 _stats[k] = v.request_sent + v.request_rcvd + v.response_sent + v.response_rcvd
	 tot_arp_pkts = tot_arp_pkts + _stats[k]
	 found = true
      end
   end

   if(not found) then
      label = "No ARP Traffic detected"
   else
      label = "Top ARP Senders/Receivers\n\nMAC Address\tTot Pkts\tPctg\tARP Breakdown\n"
      i = 0
      for k,v in pairsByValues(_stats, rev) do
	 local s = arp_stats[k]
	 local pctg = formatPctg((v * 100) / tot_arp_pkts)
	 local str = k .. "\t" .. v .. "\t" .. pctg .. "\t" .. "[sent: ".. (s.request_sent + s.response_sent) .. "][rcvd: ".. (s.request_rcvd + s.response_rcvd) .. "]\n"
	 label = label .. str
	 if(i == max_num_entries) then break else i = i + 1 end
      end
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function vlan_dialog_menu()
   local win = TextWindow.new("VLAN Statistics");
   local label = ""
   local _macs
   local num_hosts = 0

   if(vlan_found) then
      i = 0
      label = "VLAN\tPackets\n"
      for k,v in pairsByValues(vlan_stats, rev) do
	 local pctg = formatPctg((v * 100) / last_processed_packet_number)
	 label = label .. k .. "\t" .. v .. " pkts [".. pctg .."]\n"
	 if(i == max_num_entries) then break else i = i + 1 end
      end
   else
      label = "No VLAN traffic found"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function ip_mac_dialog_menu()
   local win = TextWindow.new("IP-MAC Statistics");
   local label = ""
   local _macs, _manufacturers
   local num_hosts = 0

   _macs = {}
   _manufacturers = {}
   for mac,v in pairs(mac_stats) do
      local num = 0
      local m =  string.split(mac, "_")
      local manuf

      if(m == nil) then
	 m =  string.split(mac, ":")

	 manuf = m[1]..":"..m[2]..":"..m[3]
      else
	 manuf = m[1]
      end

      for a,b in pairs(v) do
	 num = num +1
      end

      _macs[mac] = num
      if(_manufacturers[manuf] == nil) then _manufacturers[manuf] = 0 end
      _manufacturers[manuf] = _manufacturers[manuf] + 1
      num_hosts = num_hosts + num
   end

   if(num_hosts > 0) then
      i = 0
      label = label .. "MAC\t\t# Hosts\tPercentage\n"
      for k,v in pairsByValues(_macs, rev) do
	 local pctg = formatPctg((v * 100) / num_hosts)
	 label = label .. k .. "\t" .. v .. "\t".. pctg .."\n"
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      i = 0
      label = label .. "\n\nManufacturer\t# Hosts\tPercentage\n"
      for k,v in pairsByValues(_manufacturers, rev) do
	 local pctg = formatPctg((v * 100) / num_hosts)
	 label = label .. k .. "\t\t" .. v .. "\t".. pctg .."\n"
	 if(i == max_num_entries) then break else i = i + 1 end
      end
   else
      label = label .. "\nIP-MAC traffic found"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function dns_dialog_menu()
   local win = TextWindow.new("DNS Statistics");
   local label = ""
   local tot = 0
   local _dns = {}

   for k,v in pairs(dns_responses_ok) do
      _dns[k] = v
      tot = tot + v
   end

   for k,v in pairs(dns_responses_error) do
      if(_dns[k] == nil) then _dns[k] = 0 end
      _dns[k] = _dns[k] + v
      tot = tot + v
   end

   if(tot > 0) then
      i = 0
      label = label .. "DNS Server\t\t# Responses\n"
      for k,v in pairsByValues(_dns, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 local ok   = dns_responses_ok[k]
	 local err  = dns_responses_error[k]

	 if(ok == nil)  then ok = 0 end
	 if(err == nil) then err = 0 end
	 label = label .. string.format("%-20s\t%s\n", shortenString(k), v .. "\t[ok: "..ok.."][error: "..err.."][".. pctg .."]")

	 if(i == max_num_entries) then break else i = i + 1 end
      end

      i = 0
      label = label .. "\n\nTop DNS Clients\t# Queries\n"
      for k,v in pairsByValues(dns_client_queries, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 label = label .. string.format("%-20s\t%s\n", shortenString(k), v .. "\t["..pctg.."]")
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      i = 0
      label = label .. "\n\nTop DNS Resolvers\t# Responses\n"
      for k,v in pairsByValues(dns_server_responses, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 label = label .. string.format("%-20s\t%s\n", shortenString(k), v .. "\t["..pctg.."]")
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      i = 0
      label = label .. "\n\nTop DNS Queries\t\t\t# Queries\n"
      for k,v in pairsByValues(top_dns_queries, rev) do
	 local pctg = formatPctg((v * 100) / tot)
	 label = label .. string.format("%-32s\t%s\n", shortenString(k,32), v .. "\t["..pctg.."]")
	 if(i == max_num_entries) then break else i = i + 1 end
      end
   else
      label = label .. "\nNo DNS traffic found"
   end

   win:set(label)


   -- add buttons to clear text window and to enable editing
   win:add_button("Clear", function() win:clear() end)
   --win:add_button("Enable edit", function() win:set_editable(true) end)

   -- print "closing" to stdout when the user closes the text windw
   --win:set_atclose(function() print("closing") end)
end

-- ###############################################

local function rtt_dialog_menu()
   local win = TextWindow.new("Network Latency");
   local label = ""
   local tot = 0
   local i

   i = 0
   label = label .. "Client\t\tMin/Max RTT\n"
   for k,v in pairsByValues(min_nw_client_RRT, rev) do
      label = label .. string.format("%-20s\t%.3f / %.3f msec\n", shortenString(k), v, max_nw_client_RRT[k])
      if(i == max_num_entries) then break else i = i + 1 end
   end

   i = 0
   label = label .. "\nServer\t\tMin RTT\n"
   for k,v in pairsByValues(min_nw_server_RRT, rev) do
      label = label .. string.format("%-20s\t%.3f / %.3f msec\n", shortenString(k), v, max_nw_server_RRT[k])
      if(i == max_num_entries) then break else i = i + 1 end
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function appl_rtt_dialog_menu()
   local win = TextWindow.new("Application Latency");
   local label = ""
   local tot = 0
   local i

   i = 0
   label = label .. "Server\t\tMin Application RTT\n"
   for k,v in pairsByValues(min_appl_RRT, rev) do
      label = label .. string.format("%-20s\t%.3f / %.3f msec\n", shortenString(k), v, max_appl_RRT[k])
      if(i == max_num_entries) then break else i = i + 1 end
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function obfuscated_servers_dialog_menu()
   local win = TextWindow.new("Obfuscated Servers Analysis");
   local label = ""
   local tot = 0
   local i

   if(tot_obfuscated_flows > 0) then
      i = 0
      label = label .. "Server\t\tProtocol\tTotal Flows\tObfuscated flows\n"
      for k,v in pairsByKeys(possible_obfuscated_servers, rev) do
         for token in string.gmatch(k, "[^%s]+") do -- split key in two token (for beter formatting): ip:port and protocol
	    label = label .. token .. "\t"
         end
	 label = label .. v[1] .. "\t\t" .. v[2] .. "\n"
      end
      label = label .. "\n\nTotal obfuscated flows: " .. tot_obfuscated_flows .. "\n"
   else
      label = "No possible Obfuscated Servers detected"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function http_ua_dialog_menu()
   local win = TextWindow.new("HTTP User Agent");
   local label = ""
   local tot = 0
   local i

   if(tot_http_ua_flows > 0) then
      i = 0
      label = label .. "Client\t\tUser Agent\n"
      for k,v in pairsByKeys(http_ua, rev) do
	 local ips = ""
	 for k1,v1 in pairs(v) do
	    if(ips ~= "") then ips = ips .. "," end
	    ips = ips .. k1
	 end

	 --	 label = label .. string.format("%-32s", shortenString(k,32)).."\t"..ips.."\n"
	 label = label .. ips.."\t"..k.."\n"
	 if(i == 50) then break else i = i + 1 end
      end
   else
      label = "No HTTP User agents detected"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function flows_ua_dialog_menu()
   local win = TextWindow.new("Flows");
   local label = ""
   local tot = 0
   local i

   if(tot_flows > 0) then
      i = 0
      label = label .. "Flow\t\t\t\t\tA->B\tB->A\n"
      for k,v in pairsByKeys(flows, rev) do
	 label = label .. k.."\t"..v[1].."\t"..v[2].."\n"
	 --label = label .. k.."\n"
	 if(i == 50) then break else i = i + 1 end
      end
   else
      label = "No flows detected"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function dhcp_dialog_menu()
   local win = TextWindow.new("DHCP Fingerprinting");
   local label = ""
   local tot = 0
   local i
   local fingeprints = {
      ['017903060F77FC'] = 'iOS',
      ['017903060F77FC5F2C2E'] = 'macOS',
      ['0103060F775FFC2C2E2F'] = 'macOS',
      ['017903060F6C7277FC5F2C2E'] = 'macOS',
      ['0103060F775FFC2C2E'] = 'MacOS',
      ['0603010F0C2C51452B1242439607'] = 'HP LaserJet',
      ['0603010F42430D2C0C'] = 'HP LaserJet',
      ['01032C06070C0F16363A3B45122B7751999A'] = 'HP LaserJet',
      ['060FFC'] = 'Xerox Printer',
      ['0103063633'] = 'Windows',
      ['0103060F1F212B2C2E2F79F9FC'] = 'Windows',
      ['0103060F1F212B2C2E2F7779F9FC'] = 'Windows',
      ['0102060C0F1A1C79032128292A77F9FC11'] = 'Windows',
      ['010F03062C2E2F1F2179F92B'] = 'Windows',
      ['0103060C0F1C2A'] = 'Linux',
      ['011C02030F06770C2C2F1A792A79F921FC2A'] = 'Linux',
      ['0102030F060C2C'] = 'Apple AirPort',
      ['01792103060F1C333A3B77'] = 'Android',
   }

   if(dhcp_fingerprints ~= {}) then
      i = 0

      for k,v in pairsByValues(dhcp_fingerprints, rev) do
	 local os = fingeprints[v]

	 if(os ~= nil) then
	    local os = " ["..os.."]"

	    if(i == 0) then
	       label = label .. "Client\t\tKnown Fingerprint\n"
	    end

	    label = label .. k.."\t"..v..os.."\n"
	    if(i == 50) then break else i = i + 1 end
	 end
      end

      i = 0
      for k,v in pairsByValues(dhcp_fingerprints, rev) do
	 local os = fingeprints[v]

	 if(os == nil) then
	    if(i == 0) then
	       label = label .. "\n\nClient\t\tUnknown Fingerprint\n"
	    end

	    label = label .. k.."\t"..v.."\n"
	    if(i == 50) then break else i = i + 1 end
	 end
      end



   else
      label = "No DHCP fingerprints detected"
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function tls_dialog_menu()
   local win = TextWindow.new("TLS Server Contacts");
   local label = ""
   local tot = 0
   local i

   if(tot_tls_flows > 0) then
      i = 0
      label = label .. "TLS Server\t\t\t\t# Flows\n"
      for k,v in pairsByValues(tls_server_names, rev) do
	 local pctg

	 v = tonumber(v)
	 pctg = formatPctg((v * 100) / tot_tls_flows)
	 label = label .. string.format("%-32s", shortenString(k,32)).."\t"..v.." [".. pctg.." %]\n"
	 if(i == 50) then break else i = i + 1 end
      end
   else
      label = "No TLS server certificates detected"
   end

   if(tot_tls_ja4_flows > 0) then
      i = 0
      label = label .. "\n\nJA4\t\t\t\t# Flows\n"
      for k,v in pairsByValues(tls_ja4_flows, rev) do
	 local pctg

	 v = tonumber(v)
	 pctg = formatPctg((v * 100) / tot_tls_ja4_flows)
	 label = label .. k .."\t"..v.." [".. pctg.."]\n"

	 if(i == 50) then break else i = i + 1 end
      end

      i = 0
      label = label .. "\n\nJA4\t\t\t\t# Client Hosts\n"
      for k,v in pairs(tls_ja4_clients) do
	 clients = ""

	 for k1,v1 in pairs(v) do
	    if(k1 ~= nil) then
	       clients = clients .. " " .. k1
	    end
	 end

	 label = label .. k.."\t["..clients.." ]\n"
      end
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function tcp_dialog_menu()
   local win = TextWindow.new("TCP Packets Analysis");
   local label = ""
   local i

   i = 0
   label = label .. "TCP Host Fingerprints\n"
   for k,v in pairsByValues(tcp_host_fingerprints, rev) do
      if(tcp_fingeprint_db[v] ~= nil) then
	 v = v .. " [" .. tcp_fingeprint_db[v] .."]"
      end
      
      label = label .. string.format("%-32s", shortenString(k,32)).."\t"..v.."\n"
      if(i == 50) then break else i = i + 1 end
   end

   i = 0
   label = label .. "\nTCP Fingerprint Hosts\n"
   for k,v in pairs(tcp_fingerprint_hosts) do
      label = label .. string.format("%-32s", shortenString(k,32)).."\t["

      for h,_ in  pairsByValues(v, rev) do
	 label = label .. " " .. h
      end

      label = label .. " ]\n"

      if(i == 50) then break else i = i + 1 end
   end
   
   label = label .. "\nTotal Retransmissions : "..num_tcp_retrans.."\n"
   if(num_tcp_retrans > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_retrans, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 50) then break else i = i + 1 end
      end
   end

   label = label .. "\nTotal Out-of-Order : "..num_tcp_ooo.."\n"
   if(num_tcp_ooo > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_ooo, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 50) then break else i = i + 1 end
      end
   end

   label = label .. "\nTotal Lost Segment : "..num_tcp_lost_segment.."\n"
   if(num_tcp_lost_segment > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_lost_segment, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 50) then break else i = i + 1 end
      end
   end

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

register_menu("ntop/ARP",          arp_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/DHCP",         dhcp_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/DNS",          dns_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/HTTP UA",      http_ua_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/Flows",        flows_ua_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/IP-MAC",       ip_mac_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/TLS",          tls_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/TCP Analysis", tcp_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/VLAN",         vlan_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/Latency/Network",      rtt_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/Latency/Application",  appl_rtt_dialog_menu, MENU_TOOLS_UNSORTED)
register_menu("ntop/Obfuscated Servers Analysis", obfuscated_servers_dialog_menu, MENU_TOOLS_UNSORTED)

-- ###############################################

if(compute_flows_stats) then
   register_menu("ntop/nDPI", ndpi_dialog_menu, MENU_TOOLS_UNSORTED)
   register_menu("ntop/nDPI Flow Score", flow_score_dialog_menu, MENU_TOOLS_UNSORTED)
end
