#!/usr/bin/env lua
--
-- (C) 2021 - ntop.org
--

package.path = "lib/?.lua;" .. package.path
local tshark = require "tshark"

local pcap_file = "../../tests/pcap/tor.pcap"

local t = tshark:open(pcap_file, "tcp")

if(t == nil) then
   io.write("Unable to read pcap file "..pcap_file.."\n")
   exit()
end

local num_tcp = 0

while(true) do
   local l = t:read()
   
   if(l == nil) then break end
   
   io.write(".")
   io.flush()

   num_tcp = num_tcp + 1
end

t:close()

io.write("\nFound "..num_tcp.." TCP packets on pcap "..pcap_file.."\n") 
