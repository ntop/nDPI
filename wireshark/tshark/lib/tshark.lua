#!/usr/bin/env lua

--
-- (C) 2021 - ntop.org
--

local json = require "dkjson"

tshark = {}
tshark.__index = tshark

-- ###############################################################

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

-- ###############################################################

local function file_exists(name)
   local f = io.open(name, "r")

   if(f ~= nil) then
      io.close(f)
      return true
   else
      return false
   end
end

-- ###############################################################

--
-- Creates a tshark class instance
--

function tshark:open(pcap_file_or_dev, filter)
   local ret = {}

   setmetatable(ret, tshark)  -- Open the class
   
   cmd = "tshark -n -T ek -l "

   if(file_exists(pcap_file_or_dev)) then
      cmd = cmd .. "-r "..pcap_file_or_dev

      if(filter ~= nil) then
	 cmd = cmd .. " -2 -R \"" .. filter .."\""
      end

   else
      cmd = cmd .. "-i "..pcap_file_or_dev

      if(filter ~= nil) then
	 cmd = cmd .. " -f \"" .. filter .."\""
      end	 
   end
   
   ret.pipe = io.popen(cmd)

   return ret
end

-- ###############################################################

--
-- Terminates the tshark class
--

function tshark:close()
   if(self.pipe ~= nil) then
      self.pipe:close()
   end
end

-- ###############################################################

--
-- Read a single packet
--

function tshark:read()
   local l = self.pipe:read()
   local j

   if(l == nil) then return(nil) end

   j = json.decode(l)

   if(j.layers ~= nil) then
      return(j.layers)
   else
      return(self:read())
   end
end

return tshark
