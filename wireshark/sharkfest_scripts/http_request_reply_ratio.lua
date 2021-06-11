--
-- (C) 2021 - ntop.org
--
-- This is going to be an example of a lua script that can be written for cybersecurity reasons.
-- HTTP Request/Reply Ratio:
-- the ratio of HTTP requests and replies should be alwais close to 1, because, if not, usually means
-- that there are problems with the client that is sending the requests or there are problems with
-- the server that should receive those requests.

local f_http = Field.new("http")
local f_http_request = Field.new("http.request")
local f_http_reply = Field.new("http.response")
local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")

--############################################

local function getstring(finfo)
	local ok, val = pcall(tostring, finfo)
	if not ok then val = "(unknown)" end
	return val
end

--############################################

local function processResponse(http_table, req_or_rep, src, dst)
    local key = src .. " -> " .. dst

    -- Create the table entry if needed
    if not http_table[key] then
        http_table[key] = {
            requests = 0,
            replies = 0,
        }
    end

    -- Increase the stats
    http_table[key][req_or_rep] = http_table[key][req_or_rep] + 1

    return http_table
end

--############################################

local function processPackets(pinfo,tvb, http_table) 
    -- Call the function that extracts the field
    local http_traffic = f_http()
    local http_request = f_http_request()
    local http_reply = f_http_reply()

    --Check if there is an HTTP request or reply
    if http_traffic then
        if http_request then
            local src = getstring(f_ip_src().value)
            local dst = getstring(f_ip_dst().value)

            http_table = processResponse(http_table, "requests", src, dst)
        elseif http_reply then
            local dst = getstring(f_ip_src().value)
            local src = getstring(f_ip_dst().value)

            http_table = processResponse(http_table, "replies", src, dst)
        end
    end

    return http_table
end

--############################################

local function httpReqRepRatio()
	-- Declare the window we will use
	local tw = TextWindow.new("HTTP Request/Reply Ratio")

	local http_table = {}

	local tap = Listener.new();

	local function removeListener()
		-- This way we remove the listener that otherwise will remain running indefinitely
		tap:remove();
	end

	-- We tell the window to call the remove() function when closed
	tw:set_atclose(removeListener)

	-- This function will be called once for each packet
	function tap.packet(pinfo,tvb)
        http_table = processPackets(pinfo,tvb, http_table)
	end

	-- This function will be called once every few seconds to update our window
	function tap.draw(t)
		tw:clear()
		
        local dangerous_flows = {}
        local ok_flows = {}

        for flow, data in pairs(http_table) do
			local requests = http_table[flow]["requests"]
			local replies = http_table[flow]["replies"]
            local ratio = 0
            local danger = ""

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
            tw:append("------------- DETECTED HTTP REQUEST/REPLY RATIO -------------\n\n")
            tw:append("TOT SUSPICIOUS FLOWS DETECTED:\t" .. #dangerous_flows .. " -------------\n")
        else
            tw:append("------------- HTTP REQUEST/REPLY RATIO SEEMS FINE -------------\n\n")
        end

        tw:append("TOTAL HTTP FLOWS DETECTED:\t\t" .. #dangerous_flows + #ok_flows .. " -------------\n\n")
        
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
		http_table = {}
	end

	-- Ensure that all existing packets are processed.
	retap_packets()
end

-- Register the menu Entry
register_menu("Sharkfest/HTTP Request-Reply Ratio", httpReqRepRatio, MENU_TOOLS_UNSORTED)
