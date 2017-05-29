--
-- (C) 2017 - ntop.org
--
-- This plugin is part of nDPI (https://github.com/ntop/nDPI)
--
--


local ndpi_proto = Proto("ndpi", "nDPI", "nDPI Protocol Interpreter")
ndpi_proto.fields = {}
local ndpi_fds = ndpi_proto.fields
ndpi_fds.network_protocol     = ProtoField.new("nDPI Network Protocol", "ndpi.protocol.network", ftypes.UINT8, nil, base.DEC)
ndpi_fds.application_protocol = ProtoField.new("nDPI Application Protocol", "ndpi.protocol.application", ftypes.UINT8, nil, base.DEC)
ndpi_fds.name                 = ProtoField.new("nDPI Protocol Name", "ndpi.protocol.name", ftypes.STRING)


local ntop_proto = Proto("ntop", "ntop", "ntop Extensions")
ntop_proto.fields = {}
local ntop_fds = ntop_proto.fields
ntop_fds.client_nw_rtt = ProtoField.new("TCP client network RTT (msec)", "ntop.latency.client_rtt", ftypes.FLOAT, nil, base.NONE)
ntop_fds.server_nw_rtt = ProtoField.new("TCP server network RTT (msec)", "ntop.latency.server_rtt", ftypes.FLOAT, nil, base.NONE)

local f_eth_trailer = Field.new("eth.trailer")

local ndpi_protos            = {}
local ndpi_flows             = {}
local num_ndpi_flows         = 0

local arp_stats              = {}
local mac_stats              = {}
local vlan_stats             = {}
local vlan_found             = false

local syn                    = {}
local synack                 = {}
local lower_ndpi_flow_id     = 0
local lower_ndpi_flow_volume = 0

local compute_flows_stats    = true
local max_num_entries        = 10
local max_num_flows          = 50

local num_pkts               = 0
local last_processed_packet_number = 0

local debug = false

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
   local mac

   -- print(num_pkts)
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
   local secs1, frac1 = math.modf(a)
   local secs2, frac2 = math.modf(b)
   local diff   
   local diff_sec = secs1 - secs2
   local diff_res = frac1 - frac2

   if(diff_res < 0) then diff_sec = diff_sec + 1 end
   
   return(diff_sec + diff_res)   
end

-- ###############################################

local field_tcp_flags = Field.new('tcp.flags')

-- the dissector function callback
function ndpi_proto.dissector(tvb, pinfo, tree)
   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice

   if(pinfo.visited == false) then return end

   num_pkts = num_pkts + 1
   if((num_pkts > 1) and (pinfo.number == 1)) then return end

   if(last_processed_packet_number < pinfo.number) then
      last_processed_packet_number = pinfo.number
   end

   -- print(num_pkts .. " / " .. pinfo.number .. " / " .. last_processed_packet_number)

   -- ############# ARP / VLAN #############
   local offset = 12
   local eth_proto = tostring(tvb(offset,2))

   if(eth_proto == "8100") then
      local vlan_id = BitAND(tonumber(tostring(tvb(offset+2,2))), 0xFFF)

      if(vlan_stats[vlan_id] == nil) then vlan_stats[vlan_id] = 0 end
      vlan_stats[vlan_id] = vlan_stats[vlan_id] + 1
      vlan_found = true
   end

   while(eth_proto == "8100") do
      offset = offset + 4
      eth_proto = tostring(tvb(offset,2))
   end

   if(eth_proto == "0806") then
      -- ARP
      local isRequest = tonumber(tvb(21,1))
      --print(eth_proto.." ["..tostring(pinfo.dl_src).." / ".. tostring(pinfo.dl_dst) .."] [" .. tostring(pinfo.src).." -> "..tostring(pinfo.dst).."]")
      dissectARP(isRequest, tostring(pinfo.dl_src), tostring(pinfo.dl_dst))
   else
      -- ############# 2 nDPI Dissection #############

      if(false) then
	 local srckey = tostring(pinfo.src)
	 local dstkey = tostring(pinfo.dst)
	 print("Processing packet "..pinfo.number .. "["..srckey.." / "..dstkey.."]")
      end

      local src_mac = tostring(pinfo.dl_src)
      local src_ip  = tostring(pinfo.src)
      if(mac_stats[src_mac] == nil) then mac_stats[src_mac] = {} end
      mac_stats[src_mac][src_ip] = 1
      
      local pktlen = tvb:len()
      local eth_trailer = f_eth_trailer()
      local magic = tostring(tvb(pktlen-28,4))

      if(magic == "19680924") then
	 local ndpi_subtree = tree:add(ndpi_proto, tvb(), "nDPI Protocol")
	 local network_protocol     = tvb(pktlen-24,2)
	 local application_protocol = tvb(pktlen-22,2)
	 local name = tvb(pktlen-20,16)
	 local name_str = name:string(ENC_ASCII)
	 local ndpikey, srckey, dstkey, flowkey

	 ndpi_subtree:add(ndpi_fds.network_protocol, network_protocol)
	 ndpi_subtree:add(ndpi_fds.application_protocol, application_protocol)
	 ndpi_subtree:add(ndpi_fds.name, name)

	 local pname = ""..application_protocol
	 if(pname ~= "0000") then
	    -- Set protocol name in the wireshark protocol column (if not Unknown)
	    pinfo.cols.protocol = name_str
	 end

	 if(compute_flows_stats) then
	    ndpikey = tostring(slen(name_str))

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
			table.remove(ndpi_flows, k)
			tot_removed = tot_removed + 1
			if(tot_removed == max_num_entries) then
			   break
			end
		     end
		  end

	       end
	    end

	    ndpi_flows[flowkey] = ndpi_flows[flowkey] + pinfo.len
	 end
      end -- nDPI


      local _tcp_flags = field_tcp_flags()

      if(_tcp_flags ~= nil) then
	 local key
	 local tcp_flags = field_tcp_flags().value
	 
	 tcp_flags = tonumber(tcp_flags)
	 
	 if(tcp_flags == 2) then
	    -- SYN
	    if(debug) then print("SYN @ ".. pinfo.abs_ts.." "..key) end
	    
	    key = getstring(pinfo.src).."_"..getstring(pinfo.src_port).."_"..getstring(pinfo.dst).."_"..getstring(pinfo.dst_port)
	    syn[key] = pinfo.abs_ts
	 elseif(tcp_flags == 18) then
	    -- SYN|ACK
	    if(debug) then print("SYN|ACK @ ".. pinfo.abs_ts.." "..key) end

	    key = getstring(pinfo.dst).."_"..getstring(pinfo.dst_port).."_"..getstring(pinfo.src).."_"..getstring(pinfo.src_port)
	    synack[key] = pinfo.abs_ts
	    if(syn[key] ~= nil) then
	       local diff = abstime_diff(synack[key], syn[key]) * 1000 -- msec
	       
	       if(debug) then print("Client RTT --> ".. diff .. " sec") end
	       local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")
	       ntop_subtree:add(ntop_fds.client_nw_rtt, diff)
	       -- syn[key] = nil
	    end
	 elseif(tcp_flags == 16) then
	    -- ACK
	    if(debug) then print("ACK @ ".. pinfo.abs_ts.." "..key) end
	    
	    key = getstring(pinfo.src).."_"..getstring(pinfo.src_port).."_"..getstring(pinfo.dst).."_"..getstring(pinfo.dst_port)
    	    
	    if(synack[key] ~= nil) then
	       local diff = abstime_diff(pinfo.abs_ts, synack[key]) * 1000 -- msec
	       if(debug) then print("Server RTT --> ".. diff .. " sec") end
	       local ntop_subtree = tree:add(ntop_proto, tvb(), "ntop")
	       ntop_subtree:add(ntop_fds.server_nw_rtt, diff)
	       -- synack[key] = nil
	    end

	 end
      end
      
      if(debug) then
	 local fields  = { }
	 local _fields = { all_field_infos() }
	 
	 -- fields['pinfo.number'] = pinfo.number
	 
	 for k,v in pairs(_fields) do
	    local value = getstring(v)
	    
	    if(value ~= nil) then
	       fields[v.name] = value
	    end
	 end

	 for k,v in pairs(fields) do
	    print(k.." = "..v)
	 end
      end
   end
end

register_postdissector(ndpi_proto)

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
   end
end

-- ###############################################

if(compute_flows_stats) then
   register_menu("nDPI", ndpi_dialog_menu, MENU_STAT_UNSORTED)
end

-- ###############################################

local function arp_dialog_menu()
   local win = TextWindow.new("ARP Statistics");
   local label = ""
   local _stats
   local found = false

   _stats = {}
   for k,v in pairs(arp_stats) do
      if(k ~= "Broadcast") then
	 _stats[k] = v.request_sent + v.request_rcvd + v.response_sent + v.response_rcvd
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
	 local pctg = formatPctg((v * 100) / last_processed_packet_number)
	 local str = k .. "\t" .. v .. "\t" .. pctg .. "\t" .. "[sent: ".. (s.request_sent + s.response_sent) .. "][rcvd: ".. (s.request_rcvd + s.response_rcvd) .. "]\n"
	 label = label .. str
	 if(i == max_num_entries) then break else i = i + 1 end	 
      end
   end

   win:set(label)
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
end

-- ###############################################

register_menu("ARP",  arp_dialog_menu, MENU_STAT_UNSORTED)
register_menu("VLAN", vlan_dialog_menu, MENU_STAT_UNSORTED)
register_menu("IP-MAC", ip_mac_dialog_menu, MENU_STAT_UNSORTED)
