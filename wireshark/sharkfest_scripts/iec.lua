--
-- (C) 2021 - switch.ch
-- IEC 60870-5-14 expert anlysis PoC for sharkfest Europe 2021
-- Version 1.0
--


local iec_analysis = Proto("iec_analysis", "IEC Packet Analysis")

iec_analysis.fields = {}
iec_analysis.fields.invalid_cp56time = ProtoField.new("Invalid CP56Time", "iec_analysis.fields.invalid_cp56time", ftypes.STRING)

local f_time_epoch         = Field.new("frame.time_epoch")
local f_cp56time_min       = Field.new("iec60870_asdu.cp56time.min")
local f_cp56time_hour      = Field.new("iec60870_asdu.cp56time.hour")
local f_cp56time_day       = Field.new("iec60870_asdu.cp56time.day")
local f_cp56time_month     = Field.new("iec60870_asdu.cp56time.month")
local f_cp56time_year      = Field.new("iec60870_asdu.cp56time.year")

local f_tcplen             = Field.new("tcp.len")
local f_payload            = Field.new("tcp.payload")
local f_src_port           = Field.new("tcp.srcport")
local f_dst_port           = Field.new("tcp.dstport")

local f_asdu_start         = Field.new("iec60870_asdu.start")


-- ###############################################

function iec_analysis.init()

end

-- ###############################################


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

-- the dissector function callback
function iec_analysis.dissector(tvb, pinfo, tree)
   -- Wireshark dissects the packet twice. We ignore the first
   -- run as on that step the packet is still undecoded
   -- The trick below avoids to process the packet twice

   if (pinfo.visited == true) then

      -- get raw data
      local tcplenRaw          = { f_tcplen() }
      local payloadRaw         = { f_payload() }
      local dstportRaw         = { f_dst_port() }
      local srcportRaw         = { f_src_port() }
      local asdu_start       = { f_asdu_start() }
   
   
      if ((tcplenRaw ~= nil) and (payloadRaw ~= nil )) and (dstportRaw ~= nil) and (srcportRaw ~= nil) and (asdu_start ~= nil) then


         local cp56time_min       = { f_cp56time_min() } 
         local cp56time_hour      = { f_cp56time_hour()  }
         local cp56time_day       = { f_cp56time_day()   }
         local cp56time_month     = { f_cp56time_month() }
         local cp56time_year      = { f_cp56time_year()  }

         local msgTime = ""


         if((cp56time_day ~= nil)
            and (cp56time_month ~= nil)
            and (cp56time_year ~= nil)
            and (cp56time_hour ~= nil)
            and (cp56time_min ~= nil)) then
               -- The field is present: we now validate CP56time
               local hour  = tonumber(getval(cp56time_hour[#cp56time_hour]))
               local day   = tonumber(getval(cp56time_day[#cp56time_day]))
               local month = tonumber(getval(cp56time_month[#cp56time_month]))
               local year  = tonumber(getval(cp56time_year[#cp56time_year]))
               local min   = tonumber(getval(cp56time_min[#cp56time_min]))

               if((day ~= nil)
                and (month ~= nil)
                and (year ~= nil)
                and (hour ~= nil)
                and (min ~= nil)) then
                   local t = {year=2000+year, month=month, day=day, hour=hour, min=min}
                   local cp56time = os.time(t)
                   local epoch = { f_time_epoch() }
                   local packet_epoch  = tonumber(getval(epoch[#epoch]))

                   local deviation3h = 10800

                  if ((cp56time + deviation3h) < packet_epoch) then
                     msgTime = "CP54time differs more then 3h from epoch time. Difference = " .. os.date("%X", packet_epoch - cp56time)
                  elseif ((cp56time + 10) < packet_epoch) then
                     local msgTime = "CP54time differs more than 10s from epoch time. Difference = " .. os.date("%X", packet_epoch - cp56time)
                  end
               end
         end





 
         local tcplen    = tonumber(getval(tcplenRaw[#tcplenRaw]))
         local srcport    = tonumber(getval(srcportRaw[#srcportRaw]))
         local dstport    = tonumber(getval(dstportRaw[#dstportRaw]))
         local payload    = tostring(getval(payloadRaw[#payloadRaw]))
         
         local APDU_type = {"Length", "Type", "Rx", "Tx", "TypeID", "TestFr", "StartPos", "CauseTx", "IOA", "NumIx"}
         local APDU = APDU_type

         local StartPos = 1
         local i = 1
         local msg = ""
         local msg2 = ""
         local msg3 = ""

         local APDU_length = {}
         local APDU_StartPos = {}

         --read first APDU length and check wheater payload contains multiple APDUs or not
         --additional checks
         if ((payload ~= nil) and (tcplen ~= nil ) and (asdu_start ~= nil ) and ((srcport == 2404) or (dstport == 2404)) ) then
         
            if ((tcplen > 3)  and (tonumber(string.sub(payload,StartPos,StartPos  + 1),16)==104)) then
               --define APDUs start positions, containing 0x68
               if ((tonumber(string.sub(payload,4,5),16) + 2) < tcplen) then
                  --multiple APDUs
                  --loop through all APDU's
                  while StartPos < (tcplen*3-1) do
                     APDU_StartPos[i] = StartPos
                     APDU_length[i] = tonumber(string.sub(payload,StartPos + 3,StartPos + 3 + 1),16)
                     
                     StartPos = StartPos + 5 + APDU_length[i]*3 + 1
                     i = i + 1
                  end

               else
                  --single APDU
                  APDU_length[i] = tonumber(string.sub(payload,StartPos + 3,StartPos + 3 + 1),16)
                  APDU_StartPos[i] = StartPos
               end  
          
               --process all APDUs
               for j=1,#APDU_StartPos do


                  if (APDU_length[j] > 7) then
                     APDU['NumIx'] = tonumber(string.sub(payload,APDU_StartPos[j]+21, APDU_StartPos[j] + 21 + 1),16)
                     if ((APDU['NumIx'] * 6) > (APDU_length[j] - 10) and (APDU['NumIx'] >= 3)) then
                        msg = " APDU object #" .. j  .. msg
                     end
                     APDU["TypeID"] = tonumber(string.sub(payload,APDU_StartPos[j]+ 18, APDU_StartPos[j] + 18 + 1),16)
                     if ( not (APDU["TypeID"] == 9 
                        or APDU["TypeID"] == 13 
                        or APDU["TypeID"] == 36 
                        or APDU["TypeID"] == 45 
                        or APDU["TypeID"] == 46 
                        or APDU["TypeID"] == 48
                        or APDU["TypeID"] == 30 
                        or APDU["TypeID"] == 103 
                        or APDU["TypeID"] == 100 
                        or APDU["TypeID"] == 37 )) then
                        msg3 = "in ASDU #" .. j .. " (TypeID: " .. APDU["TypeID"] .. ")" .. msg3
                     end
                  else
                     APDU['NumIx'] = 0 
                     APDU["TypeID"] = 0
                  end

               -- end for loop   
               end

               if (msg ~= "") then
                  msg = "Possible missing data, check for [] in IOAs in" .. msg
               end

               if #APDU_StartPos > 8 then
                  msg2 = "Payload contains more then 8 APDU objects. Number of APDU objects found: " .. #APDU_StartPos
               end

               if (msg3 ~= "") then
                  msg3 = "Not permitted TypeID(s) " .. msg3
               end

               -- Add analysis information to packet
               if (msg ~= "") or (msg2 ~= "") or (msg3 ~= "") or (msgTime  ~= "") then
                  local iec_subtree = tree:add(iec_analysis, tvb(), "IEC 60870-5-104 Analysis")
                  if (msg ~= "") then
                     iec_subtree:add_expert_info(PI_PROTOCOL, PI_WARN, msg)
                  end
                  if (msg2 ~= "") then
                     iec_subtree:add_expert_info(PI_PROTOCOL, PI_NOTE, msg2)
                  end
                  if (msg3 ~= "") then
                     iec_subtree:add_expert_info(PI_PROTOCOL, PI_NOTE, msg3)
                  end
                  if (msgTime ~= "") then
                     iec_subtree:add_expert_info(PI_PROTOCOL, PI_WARN, msgTime)
                  end
               end

            -- end of: if ((payload ~= nil) and (tcplen > 3 )) then
            end
            
         end
      -- end of: if ((tcplenRaw ~= nil) and (payloadRaw ~= nil )) then
      end

   -- end of: if (pinfo.visited == true) then
   end




         

        

   
   
       

   
   -- ###########################################

   -- As we do not need to add fields to the dissection
   -- there is no need to process the packet multiple times
   if(pinfo.visited == true) then return end

end

register_postdissector(iec_analysis)

