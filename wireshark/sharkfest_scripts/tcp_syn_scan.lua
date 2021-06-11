--
-- (C) 2021 - ntop.org
--
-- This is going to be an example of a lua script that can be written for cybersecurity reasons.
-- TCP No Data Exchanged:
-- The TCP No Data Exchanged is a really important script to check if flows are suspicious
-- Because usually, a typic TCP traffic, have some payload and it is not 0. Instead, in some attacks,
-- for example the TCP SYN Scan or SYN Flood, there is a lot of TCP traffic with no data.

local f_tcp_traffic = Field.new("tcp")
local f_tcp_payload = Field.new("tcp.len")
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_port_src = Field.new("tcp.srcport")
local f_port_dst = Field.new("tcp.dstport")
local f_conn_fin = Field.new("tcp.flags.fin")

--############################################

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

--############################################

local function processResponse(tcp_table, src, src_port, dst, dst_port, payload)
    local key = src .. " -> " .. dst

    -- Create the table entry if needed
    if not tcp_table[key] then
        local key2 = dst .. "->" ..  src
        if not tcp_table[key2] then
            tcp_table[key] = {
                payload = 0,
                fin = false,
                contacted_ports = 0,
                dst_ports = {}
            }
        else
            -- Switching src and dst ports and ip
            local tmp = dst
            key = key2
            dst = src
            src = tmp
            tmp = src_port
            src_port = dst_port
            dst_port = tmp
        end
    end

    -- Increase the stats
    tcp_table[key]["payload"] = tcp_table[key]["payload"] + getstring(payload.value)

    if not tcp_table[key]["dst_ports"][dst_port] then
        tcp_table[key]["dst_ports"][dst_port] = 1
        tcp_table[key]["contacted_ports"] = tcp_table[key]["contacted_ports"] + 1        
    end

    if getstring(f_conn_fin().value) == true then
        tcp_table[key]["fin"] = true
    end

    return tcp_table
end

--############################################

local function processPackets(pinfo,tvb, tcp_table) 
    -- Call the function that extracts the field
    local tcp_traffic = f_tcp_traffic()
    local tcp_payload = f_tcp_payload()

    --Check if there is an HTTP request or reply
    if tcp_traffic then
        local src = getstring(f_ip_src().value)
        local dst = getstring(f_ip_dst().value)
        local src_port = getstring(f_port_src().value)
        local dst_port = getstring(f_port_dst().value)

        tcp_table = processResponse(tcp_table, src, src_port, dst, dst_port, tcp_payload)
    end

    return tcp_table
end

--############################################

local function tcpSynScan()
	-- Declare the window we will use
	local tw = TextWindow.new("TCP No Data Exchanged")

	local tcp_table = {}

	local tap = Listener.new();

	local function removeListener()
		-- This way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- We tell the window to call the remove() function when closed
	tw:set_atclose(removeListener)

	-- This function will be called once for each packet
	function tap.packet(pinfo,tvb)
        tcp_table = processPackets(pinfo,tvb, tcp_table)
	end

	-- This function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()

        local dangerous_flows = {}
        local ok_flows = {}
		
        for flow, data in pairs(tcp_table) do
			local payload = data["payload"]
			local contacted_ports = data["contacted_ports"]

            if tonumber(payload) == 0 and tonumber(contacted_ports) > 10 then
                dangerous_flows[#dangerous_flows + 1] = data
                dangerous_flows[#dangerous_flows]["flow"] = flow
            else
                ok_flows[#ok_flows + 1] = data
                ok_flows[#ok_flows]["flow"] = flow
            end
		end

        if #dangerous_flows > 0 then
            tw:append("------------- DETECTED TCP SYN SCAN -------------\n\n")
            tw:append("TOT SUSPICIOUS FLOWS DETECTED:\t" .. #dangerous_flows .. "\n")
        else
            tw:append("------------- TCP SYN SCAN NOT DETECTED -------------\n\n")
        end

        tw:append("TOTAL FLOWS DETECTED:\t\t" .. #dangerous_flows + #ok_flows .. "\n\n")
        
        for _, data in pairs(dangerous_flows) do
            local flow = data["flow"]
			local payload = data["payload"]
			local contacted_ports = data["contacted_ports"]

            tw:append(flow .. ":\n\tTotal ports scanned:\t" .. tostring(contacted_ports) .. "\n\n");
        end
	end

	-- This function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		tcp_table = {}
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- Register the menu Entry
register_menu("Sharkfest/TCP SYN Scan", tcpSynScan, MENU_TOOLS_UNSORTED)
