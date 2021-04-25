#!/usr/bin/env lua

--
-- (C) 2021 - ntop.org
--

package.path = "lib/?.lua;" .. package.path

local tshark = require "tshark"

-- ======================================

function make_key(proto, src, sport, dst, dport)
   if(sport == "") then
      return(proto .. " " .. src .. "-" .. dst)
   else
      return(proto .. " " .. src .. ":" .. sport .. "-" .. dst .. ":" .. dport)
   end
end

-- ======================================


local pcap_file = "../../tests/pcap/tor.pcap"

local t = tshark:open(pcap_file, "ip or ipv6")

if(t == nil) then
   io.write("Unable to read pcap file "..pcap_file.."\n")
   exit()
end

local flows = {}

while(true) do
   local pkt = t:read()
   local flow_key
   local src = ""
   local dst = ""
   local sport = ""
   local dport = ""
   local proto = ""
   
   if(pkt == nil) then break end

   if(pkt.ip ~= nil) then
      -- IPv4

      src = pkt.ip.ip_ip_src
      dst = pkt.ip.ip_ip_dst
      
      if(pkt.ip.ip_ip_proto == "6") then
	 sport = pkt.tcp.tcp_tcp_srcport
	 dport = pkt.tcp.tcp_tcp_dstport
	 proto = "TCP"
      elseif(pkt.ip.ip_ip_proto == "17") then
	 sport = pkt.udp.udp_udp_srcport
	 dport = pkt.udp.udp_udp_dstport
	 proto = "UDP"
      else
	 proto = pkt.ip.ip_ip_proto
      end

      pkt_len = pkt.ip.ip_ip_len
   else
      -- IPv6

      src = "["..pkt.ipv6.ipv6_ipv6_src.."]"
      dst = "["..pkt.ipv6.ipv6_ipv6_dst.."]"
      
      if(pkt.ipv6.ipv6_ipv6_nxt == "6") then
	 sport = pkt.tcp.tcp_tcp_srcport
	 dport = pkt.tcp.tcp_tcp_dstport
	 proto = "TCP"
      elseif(pkt.ipv6.ipv6_ipv6_nxt == "17") then
	 sport = pkt.udp.udp_udp_srcport
	 dport = pkt.udp.udp_udp_dstport
	 proto = "UDP"
      else
	 proto = pkt.ipv6.ipv6_ipv6_nxt
      end

      pkt_len = pkt.ipv6.ipv6_ipv6_plen
   end
   
   io.write(".")
   io.flush()

   flow_key = make_key(proto, src, sport, dst, dport)
      
   if(flows[flow_key] == nil) then
      local rev_key = make_key(proto, dst, dport, src, sport, dst)
      
      if(flows[rev_key] ~= nil) then
	 flows[rev_key].rcvd = flows[rev_key].rcvd + pkt_len
      else
	 flows[flow_key] = { sent = pkt_len, rcvd = 0 }
      end
   else
      flows[flow_key].sent = flows[flow_key].sent + pkt_len
   end  
end

t:close()

io.write("\nFlows:\n")

for k, v in pairs(flows) do
   io.write(k.."\t[sent: " .. v.sent .. "][rcvd: " .. v.rcvd .. "]\n")
end
