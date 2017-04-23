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

-- ###############################################

-- the dissector function callback
function ndpi_proto.dissector(tvb, pinfo, tree)
   local pktlen = tvb:len()
   local eth_trailer = f_eth_trailer()
   local magic = tostring(tvb(pktlen-28,4))

   if(magic == "19680924") then
      local ndpi_subtree = tree:add(ndpi_proto, tvb(), "nDPI Protocol")
      local network_protocol     = tvb(pktlen-24,2)
      local application_protocol = tvb(pktlen-22,2)
      local name = tvb(pktlen-20,16)
      local name_str = name:string(ENC_UTF_8)
      
      ndpi_subtree:add(fds.network_protocol, network_protocol)
      ndpi_subtree:add(fds.application_protocol, application_protocol)
      ndpi_subtree:add(fds.name, name)

      local pname = ""..application_protocol
      if(pname ~= "0000") then
	 -- Set protocol name in the wireshark protocol column (if not Unknown)
	 pinfo.cols.protocol = name_str
      end
   end
end

register_postdissector(ndpi_proto)

-- ###############################################
