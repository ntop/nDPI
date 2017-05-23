--
-- (C) 2017 - ntop.org
--
-- This plugin is part of nDPI (https://github.com/ntop/nDPI)
--
--
local ndpi_proto = Proto("ndpi", "nDPI", "nDPI Protocol Interpreter")

ndpi_proto.fields = {}
local fds = ndpi_proto.fields

fds.network_protocol     = ProtoField.new("nDPI Network Protocol", "ndpi.protocol.network", ftypes.UINT8, nil, base.DEC)
fds.application_protocol = ProtoField.new("nDPI Application Protocol", "ndpi.protocol.application", ftypes.UINT8, nil, base.DEC)
fds.name = ProtoField.new("nDPI Protocol Name", "ndpi.protocol.name", ftypes.STRING)

local f_eth_trailer = Field.new("eth.trailer")

local ndpi_protos            = {}
local ndpi_flows             = {}
local num_ndpi_flows         = 0

local lower_ndpi_flow_id     = 0
local lower_ndpi_flow_volume = 0

local compute_flows_stats    = true
local max_num_entries        = 10
local max_num_flows          = 50

-- ###############################################

function round(num, idp)         return tonumber(string.format("%." .. (idp or 0) .. "f", num)) end

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

function asc(a,b) return (a < b) end
function rev(a,b) return (a > b) end

-- ###############################################

function ndpi_proto.init()
   ndpi_protos       = {}
   ndpi_flows        = {}
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

-- the dissector function callback
local num_pkts = 0

function ndpi_proto.dissector(tvb, pinfo, tree)
   num_pkts = num_pkts + 1

   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice
   if(num_pkts < pinfo.number) then return end

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

      ndpi_subtree:add(fds.network_protocol, network_protocol)
      ndpi_subtree:add(fds.application_protocol, application_protocol)
      ndpi_subtree:add(fds.name, name)

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

	 flowkey = srckey.." / "..dstkey.." ["..ndpikey.."]"
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
   end
end

register_postdissector(ndpi_proto)

-- ###############################################


local function ndpi_dialog_menu()
   local win = TextWindow.new("nDPI Protocol Statistics");
   local label = ""
   local i

   if(ndpi_protos ~= {}) then
      label =          "nDPI Protocol Breakdown\n"
      label = label .. "-----------------------\n"

      i = 0
      for k,v in pairsByValues(ndpi_protos, rev) do
	 -- label = label .. k .. "\t".. bytesToSize(v) .. "\n"
	 label = label .. string.format("%-32s\t%s\n", k, bytesToSize(v))
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      -- #######

      label = label .. "\nTop nDPI Flows\n"
      label = label .. "-----------\n"
      i = 0
      for k,v in pairsByValues(ndpi_flows, rev) do
	 label = label .. string.format("%-32s\t%s\n", k, bytesToSize(v))
	 if(i == max_num_entries) then break else i = i + 1 end
      end

      win:set(label)
   end
end

if(compute_flows_stats) then
   register_menu("nDPI", ndpi_dialog_menu, MENU_STAT_UNSORTED)
end
