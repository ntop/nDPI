--
-- (C) 2017-21 - ntop.org
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

function bit(p)
   return 2 ^ p  -- 0-based indexing
end


local ndpi_proto = Proto("ndpi", "nDPI Protocol Interpreter")
ndpi_proto.fields = {}

local ndpi_fds    = ndpi_proto.fields
ndpi_fds.network_protocol     = ProtoField.new("nDPI Network Protocol", "ndpi.protocol.network", ftypes.UINT8, nil, base.DEC)
ndpi_fds.application_protocol = ProtoField.new("nDPI Application Protocol", "ndpi.protocol.application", ftypes.UINT8, nil, base.DEC)
ndpi_fds.name                 = ProtoField.new("nDPI Protocol Name", "ndpi.protocol.name", ftypes.STRING)
ndpi_fds.flow_risk            = ProtoField.new("nDPI Flow Risk", "ndpi.flow_risk", ftypes.UINT64, nil, base.HEX)
ndpi_fds.flow_score           = ProtoField.new("nDPI Flow Score", "ndpi.flow_score", ftypes.UINT32)


local flow_risks = {}
-- Wireshark/Lua doesn't handle 64 bit integer very well, so we split the risk mask into two 32 bit integer values
local num_bits_flow_risks = 32
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
flow_risks[12] = ProtoField.bool("ndpi.flow_risk.http_numeric_ip_address", "HTTP Numeric IP Address", num_bits_flow_risks, nil, bit(12), "nDPI Flow Risk: HTTP Numeric IP Address")
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
-- Restart bitmask from 0!
flow_risks[32] = ProtoField.bool("ndpi.flow_risk.cert_validity_too_long", "TLS certificate validity longer than 13 months", num_bits_flow_risks, nil, bit(0), "nDPI Flow Risk: TLS certificate validity longer than 13 months")
flow_risks[33] = ProtoField.bool("ndpi.flow_risk.suspicious_extension", "TLS suspicious extension", num_bits_flow_risks, nil, bit(1), "nDPI Flow Risk: TLS suspicious extension")
flow_risks[34] = ProtoField.bool("ndpi.flow_risk.fatal_alert", "TLS fatal alert detected", num_bits_flow_risks, nil, bit(2), "nDPI Flow Risk: TLS fatal alert")
flow_risks[35] = ProtoField.bool("ndpi.flow_risk.suspicious_entropy", "Suspicious entropy", num_bits_flow_risks, nil, bit(3), "nDPI Flow Risk: suspicious entropy")
flow_risks[36] = ProtoField.bool("ndpi.flow_risk.clear_text_credentials", "Cleat-Text credentials", num_bits_flow_risks, nil, bit(4), "nDPI Flow Risk: cleat-text credentials")
flow_risks[37] = ProtoField.bool("ndpi.flow_risk.dns_large_packet", "DNS large packet", num_bits_flow_risks, nil, bit(5), "nDPI Flow Risk: DNS packet is larger than 512 bytes")
flow_risks[38] = ProtoField.bool("ndpi.flow_risk.dns_fragmented", "DNS fragmented", num_bits_flow_risks, nil, bit(6), "nDPI Flow Risk: DNS message is fragmented")
flow_risks[39] = ProtoField.bool("ndpi.flow_risk.invalid_characters", "Invalid characters", num_bits_flow_risks, nil, bit(7), "nDPI Flow Risk: Text contains non-printable characters")
flow_risks[40] = ProtoField.bool("ndpi.flow_risk.possible_exploit", "Possible Exploit", num_bits_flow_risks, nil, bit(8), "nDPI Flow Risk: Possible exploit detected")
flow_risks[41] = ProtoField.bool("ndpi.flow_risk.cert_about_to_expire", "TLS cert about to expire", num_bits_flow_risks, nil, bit(9), "nDPI Flow Risk: TLS certificate about to expire")

-- Last one: keep in sync the bitmask when adding new risks!!
flow_risks[64] = ProtoField.new("Unused", "ndpi.flow_risk.unused", ftypes.UINT32, nil, base.HEX, bit(32) - bit(10))

for _,v in pairs(flow_risks) do
  ndpi_fds[#ndpi_fds + 1] = v
end

local ntop_proto = Proto("ntop", "ntop Extensions")
ntop_proto.fields = {}

local ntop_fds = ntop_proto.fields
ntop_fds.client_nw_rtt    = ProtoField.new("TCP client network RTT (msec)",  "ntop.latency.client_rtt", ftypes.FLOAT, nil, base.NONE)
ntop_fds.server_nw_rtt    = ProtoField.new("TCP server network RTT (msec)",  "ntop.latency.server_rtt", ftypes.FLOAT, nil, base.NONE)
ntop_fds.appl_latency_rtt = ProtoField.new("Application Latency RTT (msec)", "ntop.latency.appl_rtt",   ftypes.FLOAT, nil, base.NONE)

local f_eth_source        = Field.new("eth.src")
local f_eth_trailer       = Field.new("eth.trailer")
local f_vlan_trailer      = Field.new("vlan.trailer")
local f_vlan_id           = Field.new("vlan.id")
local f_arp_opcode        = Field.new("arp.opcode")
local f_arp_sender_mac    = Field.new("arp.src.hw_mac")
local f_arp_target_mac    = Field.new("arp.dst.hw_mac")
local f_dns_query_name    = Field.new("dns.qry.name")
local f_dns_ret_code      = Field.new("dns.flags.rcode")
local f_dns_response      = Field.new("dns.flags.response")
local f_udp_len           = Field.new("udp.length")
local f_tcp_header_len    = Field.new("tcp.hdr_len")
local f_ip_len            = Field.new("ip.len")
local f_ip_hdr_len        = Field.new("ip.hdr_len")
local f_tls_server_name   = Field.new("tls.handshake.extensions_server_name")
local f_tcp_flags         = Field.new('tcp.flags')
local f_tcp_retrans       = Field.new('tcp.analysis.retransmission')
local f_tcp_ooo           = Field.new('tcp.analysis.out_of_order')
local f_tcp_lost_segment  = Field.new('tcp.analysis.lost_segment') -- packet drop ?
local f_rpc_xid           = Field.new('rpc.xid')
local f_rpc_msgtyp        = Field.new('rpc.msgtyp')
local f_user_agent        = Field.new('http.user_agent')
local f_dhcp_request_item = Field.new('dhcp.option.request_list_item')

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

local http_ua                = {}
local tot_http_ua_flows      = 0

local flows                  = {}
local tot_flows              = 0

local flows_with_risks       = {}

local dhcp_fingerprints      = {}

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

local dump_file = "/tmp/wireshark-influx.txt"
local file

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

function round(num, idp)
   return tonumber(string.format("%." .. (idp or 0) .. "f", num))
end

function formatPctg(p)
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

   -- TLS
   tls_server_names       = {}
   tot_tls_flows          = 0
   
   -- HTTP
   http_ua                = {}
   tot_http_ua_flows      = 0

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
   if(tls_server_name ~= nil) then
      tls_server_name = getval(tls_server_name)

      if(tls_server_names[tls_server_name] == nil) then
	 tls_server_names[tls_server_name] = 0
      end

      tls_server_names[tls_server_name] = tls_server_names[tls_server_name] + 1
      tot_tls_flows = tot_tls_flows + 1
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
   end
end

-- ###############################################

function dns_dissector(tvb, pinfo, tree)
   local dns_response = f_dns_response()
   if(dns_response ~= nil) then
      local dns_ret_code = f_dns_ret_code()
      local dns_response = tonumber(getval(dns_response))
      local srckey = tostring(pinfo.src)
      local dstkey = tostring(pinfo.dst)
      local dns_query_name = f_dns_query_name()
      dns_query_name = getval(dns_query_name)

      if(dns_response == 0) then
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

function tcp_dissector(tvb, pinfo, tree)
   local _tcp_retrans      = f_tcp_retrans()
   local _tcp_ooo          = f_tcp_ooo()
   local _tcp_lost_segment = f_tcp_lost_segment()

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



function hasbit(x, p)
   return x % (p + p) >= p
end

-- the dissector function callback
function ndpi_proto.dissector(tvb, pinfo, tree)
   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice

   if(pinfo.visited == true) then
      local eth_trailer = {f_eth_trailer()}
      local vlan_trailer = {f_vlan_trailer()}

      -- nDPI trailer is usually the (only one) ethernet trailer.
      -- But, depending on Wireshark configuration and on L2 protocols, the
      -- situation may be more complex. Let's try to handle the most common cases:
      --  1) with (multiple) ethernet trailers, nDPI trailer is usually the last one
      --  2) with VLAN encapsulation, nDPI trailer is usually recognized as vlan trailer
      if(eth_trailer[#eth_trailer] ~= nil or
         vlan_trailer[#vlan_trailer] ~= nil) then

	 local ndpi_trailer
	 if (eth_trailer[#eth_trailer] ~= nil) then
	     ndpi_trailer = getval(eth_trailer[#eth_trailer])
	 else
	     ndpi_trailer = getval(vlan_trailer[#vlan_trailer])
	 end
	 local magic = string.sub(ndpi_trailer, 1, 11)

	 if(magic == "19:68:09:24") then
	    local ndpikey, srckey, dstkey, flowkey
	    local elems                = string.split(string.sub(ndpi_trailer, 12), ":")
	    local ndpi_subtree         = tree:add(ndpi_proto, tvb(), "nDPI Protocol")
	    local str_score            = elems[14]..elems[15]
	    local flow_score           = tonumber(str_score, 16) -- 16 = HEX
	    local len                  = tvb:len()
	    local flow_risk            = tvb(len-30, 8):uint64() -- UInt64 object!
	    local name                 = ""
	    local flow_risk_tree
	    
	    for i=16,31 do
	       name = name .. string.char(tonumber(elems[i], 16))
	    end

	    ndpi_subtree:add(ndpi_fds.network_protocol, tvb(len-34, 2))
	    ndpi_subtree:add(ndpi_fds.application_protocol, tvb(len-32, 2))

	    flow_risk_tree = ndpi_subtree:add(ndpi_fds.flow_risk, tvb(len-30, 8))
	    if (flow_risk ~= UInt64(0, 0)) then
	       local rev_key = getstring(pinfo.dst)..":"..getstring(pinfo.dst_port).." - "..getstring(pinfo.src)..":"..getstring(pinfo.src_port)

	       if(flows_with_risks[rev_key] == nil) then
		  local key = getstring(pinfo.src)..":"..getstring(pinfo.src_port).." - "..getstring(pinfo.dst)..":"..getstring(pinfo.dst_port)
		  
		  if(flows_with_risks[key] == nil) then
		     flows_with_risks[key] = flow_score
		  end
	       end
	       
	       for i=0,63 do
		 if flow_risks[i] ~= nil then
	            -- Wireshark/Lua doesn't handle 64 bit integer very well, so we split the risk mask into two 32 bit integer values
	            flow_risk_tree:add(flow_risks[i], tvb(len - (i < 32 and 26 or 30), 4))
		 end

	       end
	       flow_risk_tree:add(flow_risks[64], tvb(len - 30, 4))
	    end
	    
	    ndpi_subtree:add(ndpi_fds.flow_score, tvb(len-22, 2))	    
	    ndpi_subtree:add(ndpi_fds.name, tvb(len-20, 16))

	    if(flow_score > 0) then
	       local level
	       if(flow_score <= 10) then     -- NDPI_SCORE_RISK_LOW
		  level = PI_NOTE
	       elseif(flow_score <= 50) then -- NDPI_SCORE_RISK_MEDIUM
		  level = PI_WARN
	       else
		  level = PI_ERROR
	       end
	       
	       ndpi_subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Non zero score")
	    end

	    if(application_protocol ~= 0) then	       
	       -- Set protocol name in the wireshark protocol column (if not Unknown)
	       pinfo.cols.protocol = name
	       --print(network_protocol .. "/" .. application_protocol .. "/".. name)
	    end

	    if(compute_flows_stats) then
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
	 end
      end -- nDPI

      latency_dissector(tvb, pinfo, tree)
      tcp_dissector(tvb, pinfo, tree)
   end
   
   -- ###########################################

   -- As we do not need to add fields to the dissection
   -- there is no need to process the packet multiple times
   if(pinfo.visited == true) then return end

   num_pkts = num_pkts + 1
   if((num_pkts > 1) and (pinfo.number == 1)) then return end

   if(last_processed_packet_number < pinfo.number) then
      last_processed_packet_number = pinfo.number
   end

   -- print(num_pkts .. " / " .. pinfo.number .. " / " .. last_processed_packet_number)

   if(true) then
      local srckey = tostring(pinfo.src)
      local dstkey = tostring(pinfo.dst)
      --print("Processing packet "..pinfo.number .. "["..srckey.." / "..dstkey.."]")
   end

   if(dump_timeseries) then
      timeseries_dissector(tvb, pinfo, tree)
   end
   
   mac_dissector(tvb, pinfo, tree)
   arp_dissector(tvb, pinfo, tree)
   vlan_dissector(tvb, pinfo, tree)
   tls_dissector(tvb, pinfo, tree)
   http_dissector(tvb, pinfo, tree)
   dhcp_dissector(tvb, pinfo, tree)   
   dns_dissector(tvb, pinfo, tree)
   rpc_dissector(tvb, pinfo, tree)
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
      ['017903060F77FC5F2C2E'] = 'MacOS',
      ['0103060F775FFC2C2E2F'] = 'MacOS',
      ['0103060F775FFC2C2E'] = 'MacOS',
      ['0603010F0C2C51452B1242439607'] = 'HP LaserJet',
      ['01032C06070C0F16363A3B45122B7751999A'] = 'HP LaserJet',
      ['0103063633'] = 'Windows',
      ['0103060F1F212B2C2E2F79F9FC'] = 'Windows',
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

   win:set(label)
   win:add_button("Clear", function() win:clear() end)
end

-- ###############################################

local function tcp_dialog_menu()
   local win = TextWindow.new("TCP Packets Analysis");
   local label = ""

   label = label .. "Total Retransmissions : "..num_tcp_retrans.."\n"
   if(num_tcp_retrans > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_retrans, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 10) then break else i = i + 1 end
      end
   end
   
   label = label .. "\nTotal Out-of-Order : "..num_tcp_ooo.."\n"
   if(num_tcp_ooo > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_ooo, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 10) then break else i = i + 1 end
      end
   end

   label = label .. "\nTotal Lost Segment : "..num_tcp_lost_segment.."\n"
   if(num_tcp_lost_segment > 0) then
      i = 0
      label = label .. "-----------------------------\n"
      for k,v in pairsByValues(tcp_lost_segment, rev) do
	 label = label .. string.format("%-48s", shortenString(k,48)).."\t"..v.."\n"
	 if(i == 10) then break else i = i + 1 end
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

-- ###############################################

if(compute_flows_stats) then
   register_menu("ntop/nDPI", ndpi_dialog_menu, MENU_TOOLS_UNSORTED)
   register_menu("ntop/nDPI Flow Score", flow_score_dialog_menu, MENU_TOOLS_UNSORTED)
end
