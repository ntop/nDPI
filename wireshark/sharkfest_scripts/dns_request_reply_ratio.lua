--
-- (C) 2021 - ntop.org
--
-- This is going to be an example of a lua script that can be written for cybersecurity reasons.
-- DNS Request/Reply Ratio:

local f_dns = Field.new("dns")
local f_dns_response_flag = Field.new("dns.flags.response")
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")

--############################################

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

--############################################

local function processResponse(dns_table, req_or_rep, src, dst)
    local key = src .. " -> " .. dst

    -- Create the table entry if needed
    if not dns_table[key] then
        dns_table[key] = {
            requests = 0,
            replies = 0,
        }
    end

    -- Increase the stats
    dns_table[key][req_or_rep] = dns_table[key][req_or_rep] + 1

    return dns_table
end

--############################################

local function processPackets(pinfo,tvb, dns_table) 
    -- Call the function that extracts the field
    local dns_traffic = f_dns()
    local dns_flag = f_dns_response_flag()

    --Check if there is an DNS request or reply
    if dns_traffic then
        if dns_flag.value == false then
            local src = getstring(f_ip_src().value)
            local dst = getstring(f_ip_dst().value)

            dns_table = processResponse(dns_table, "requests", src, dst)
        else
            local dst = getstring(f_ip_src().value)
            local src = getstring(f_ip_dst().value)

            dns_table = processResponse(dns_table, "replies", src, dst)
        end
    end

    return dns_table
end

--############################################

local function dnsReqRepRatio()
	-- Declare the window we will use
	local tw = TextWindow.new("DNS Request/Reply Ratio")

	local dns_table = {}

	local tap = Listener.new();

	local function removeListener()
		-- This way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- We tell the window to call the remove() function when closed
	tw:set_atclose(removeListener)

	-- This function will be called once for each packet
	function tap.packet(pinfo,tvb)
        dns_table = processPackets(pinfo,tvb, dns_table)
	end

	-- This function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()

        local dangerous_flows = {}
        local ok_flows = {}
		
        for flow, data in pairs(dns_table) do
			local requests = dns_table[flow]["requests"]
			local replies = dns_table[flow]["replies"]
            local ratio = 0

            if replies == 0 then
                ratio = 0
            else
                ratio = requests/replies
            end

            if ratio ~= 1 then
                dangerous_flows[#dangerous_flows + 1] = data
                dangerous_flows[#dangerous_flows]["flow"] = flow
                dangerous_flows[#dangerous_flows]["ratio"] = ratio
            else
                ok_flows[#ok_flows + 1] = data
                ok_flows[#ok_flows]["flow"] = flow
                ok_flows[#ok_flows]["ratio"] = ratio
            end
		end

        if #dangerous_flows > 0 then
	   tw:append("------------- DETECTED DNS REQUEST/REPLY RATIO -------------\n")
	   tw:append("TOT SUSPICIOUS FLOWS DETECTED:\t" .. #dangerous_flows .. " -------------\n")
        else
	   tw:append("------------- DNS REQUEST/REPLY RATIO SEEMS FINE -------------\n\n")
        end

        tw:append("TOTAL DNS FLOWS DETECTED:\t\t" .. #dangerous_flows + #ok_flows .. " -------------\n\n")
        
        for _, data in pairs(dangerous_flows) do
            local flow = data["flow"]
			local requests = data["requests"]
			local replies = data["replies"]
            local ratio = data["ratio"]

            tw:append(flow .. ":\n\tRatio:\t\t" .. (ratio) .. "\n\tRequests:\t\t" .. requests .. "\n\tReplies:\t\t" .. replies .. "\n\n");
        end
	end

	-- This function will be called whenever a reset is needed
	-- e.g. when reloading the capture file
	function tap.reset()
		tw:clear()
		dns_table = {}
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- Register the menu Entry
register_menu("Sharkfest/DNS Request-Reply Ratio", dnsReqRepRatio, MENU_TOOLS_UNSORTED)
