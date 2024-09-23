-- Define the fields to be captured
local fields = {
    quic = Field.new("tls.quic.parameter.type"),    -- QUIC transport parameter type field
    tls = Field.new("tls.handshake.extension.type") -- TLS extension type field
}
local tps_values = {
    tp_max_idle_timeout                      = Field.new("tls.quic.parameter.max_idle_timeout"), -- 0x01
    tp_max_udp_payload_size                  = Field.new("tls.quic.parameter.max_udp_payload_size"), -- 0x03
    tp_initial_max_data                      = Field.new("tls.quic.parameter.initial_max_data"), -- 0x04
    tp_initial_max_stream_data_bidi_local    = Field.new("tls.quic.parameter.initial_max_stream_data_bidi_local"), -- 0x05
    tp_initial_max_stream_data_bidi_remote   = Field.new("tls.quic.parameter.initial_max_stream_data_bidi_remote"), -- 0x06
    tp_initial_max_stream_data_uni           = Field.new("tls.quic.parameter.initial_max_stream_data_uni"), -- 0x07
    tp_initial_max_streams_bidi              = Field.new("tls.quic.parameter.initial_max_streams_bidi"), -- 0x08
    tp_initial_max_streams_uni               = Field.new("tls.quic.parameter.initial_max_streams_uni"), -- 0x09
    tp_active_connection_id_limit            = Field.new("tls.quic.parameter.active_connection_id_limit"), -- 0x0e
    tp_max_datagram_frame_size               = Field.new("tls.quic.parameter.max_datagram_frame_size"), -- 0x20
}

-- Define the lookup tables for TLS extensions and transport parameters
local lookup_tls_extensions = {
    ["43"] = true, -- supported_versions
    ["51"] = true  -- key_share
}

local lookup_transport_parameters = {
    -- ["0x0"] = true, --  original_destination_connection_id	
    -- ["0x1"] = true, --	max_idle_timeout	
    -- ["0x2"] = true, --  stateless_reset_token	
    ["0x3"] = true, --	max_udp_payload_size	
    ["0x4"] = true, --	initial_max_data	
    -- ["0x5"] = true, --	initial_max_stream_data_bidi_local	
    ["0x6"] = true, --	initial_max_stream_data_bidi_remote	
    ["0x7"] = true, --	initial_max_stream_data_uni	
    ["0x8"] = true, --	initial_max_streams_bidi	
    -- ["0x9"] = true, --	initial_max_streams_uni	
    ["0xa"] = true, --	ack_delay_exponent	
    ["0xb"] = true, --	max_ack_delay	
    ["0xc"] = true, --	disable_active_migration	
    -- ["0xd"] = true, --	preferred_address	
    -- ["0xe"] = true, --	active_connection_id_limit	
    ["0xf"] = true, --	initial_source_connection_id	
    -- ["0x10"] = true, --	retry_source_connection_id	
}

-- Micro-db for known QUIC fingerprints
local known_fingerprints = {
    ["43_51-0x6_0x7_0x4_0x8_0x3_0xb_0xc_0xf"]     = "quic-go",
    ["51_43-0xf_0x7_0x4"]                         = "ngtcp2",
    ["43_51-0x6_0x7_0x4_0x8_0xa_0x3_0xf"]         = "mvfst",
    ["51_43-0x3_0x4_0x6_0x7_0x8_0xa_0xb_0xc_0xf"] = "quiche",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xa_0xb_0xf"]     = "kwik",
    ["51_43-0x4_0x8_0x3_0x6_0x7_0xb_0xf"]         = "picoquic",
    ["51_43-0x4_0x6_0x7_0x8_0xa_0xb_0xf"]         = "aioquic",
    ["43_51-0x3_0x4_0x6_0x7_0xa_0xb_0xf"]         = "msquic",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xc_0xf"]         = "xquic",
    ["51_43-0x4_0x7_0x8_0xf"]                     = "lsquic",
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xf"]             = "quinn",
    ["43_51-0x4_0x6_0x7_0x8_0xf"]                 = "s2n-quic",
    ["43_51-0x3_0x4_0x6_0x7_0xc_0xf"]             = "go-x-net",
    ["43_51-0x6_0x7_0x4_0x8_0xa_0x3"]             = "mvfst(pre rfc)", --- mvfst draft-27
    ["43_51-0xf_0x6_0x7_0x4_0x3"]		  = "mvfst",
    ["51_43-0x3_0x4_0x6_0x7_0x8_0xa_0xb_0xf"]     = "tquic"
}

local known_fingerprints_sorted = {
    ["43_51-0x3_0x4_0x6_0x7_0x8_0xf"]     = "google-quiche",
    ["51_43-0x3_0x4_0x6_0x7_0x8_0xf"]     = "google-quiche",
    ["51_43-0x4_0x6_0x7_0x8_0xb_0xc_0xf"] = "neqo",
    ["51_43-0x4_0x6_0x7_0xf"]             = "applequic",
    ["43_51-0x4_0x6_0x7_0x8_0xf"]         = "applequic", --- seen with mask.icloud.com
}

local known_fingerprints_tp_values = {
    ["30000_M_25165824_12582912_1048576_1048576_16_16_8_1200"] = "Firefox",

    ["30000_1452_6291456_163840_163840_163840_2048_2048_5_M"] = "Generic Meta apps",
    ["60000_1500_6291456_163840_163840_163840_2048_2048_5_M"] = "Instagram app",
    ["60000_1280_6291456_163840_163840_163840_2048_2048_5_M"] = "Instagram app",
    ["30000_1280_6291456_163840_163840_163840_2048_2048_5_M"] =  "Instagram app",
    ["30000_1280_6291456_163840_262144_262144_M_100_7_M"] =  "Instagram app",
    ["30000_1252_6291456_163840_262144_262144_2048_100_2_M"] =  "Instagram app",
    ["30000_1252_1000000000_163840_1000000000_1000000000_2048_100_2_M"] =  "Instagram app",

    ["20000_1472_15728640_6291456_6291456_6291456_100_103_M_65536"] = "Snapchat app",
    ["240000_1472_15728640_6291456_6291456_6291456_100_103_M_65536"] = "Snapchat app",
    ["30000_1472_16384_16384_16384_16384_100_100_M_65536"] = "Snapchat app; audio/video call",

    ["120000_1472_15728640_6291456_6291456_6291456_100_103_M_65536"] = "Youtube app (android)",

    ["30000_1472_15728640_6291456_6291456_6291456_100_103_M_65536"] = "Generic Chrome-like",
    ["300000_1472_15728640_6291456_6291456_6291456_100_103_M_65536"] = "Android OS traffic",

    ["M_M_33554432_2097152_2097152_2097152_M_103_64_M"] = "Generic app on iOS",
    ["M_M_16777216_2097152_2097152_2097152_M_103_64_M"] = "Generic app on iOS",
    ["M_M_2097152_131072_131072_131072_M_103_64_M"] = "Generic app on iOS",
    ["M_M_1048576_131072_131072_131072_M_103_64_M"] = "Generic app on iOS",

    ["M_M_16777216_2097152_2097152_2097152_8_8_64_65535"] = "iCloud Private Relay",
    ["M_1472_16777216_2097152_2097152_2097152_8_8_64_65535"] = "iCloud Private Relay",
    ["30000_M_33554432_2097152_2097152_2097152_8_8_64_65535"] = "iCloud Private Relay",
    ["30000_M_16777216_2097152_2097152_2097152_8_8_64_65535"] = "iCloud Private Relay",
    ["30000_1472_16777216_2097152_2097152_2097152_8_8_64_65535"] = "iCloud Private Relay",

    ["60000_M_1000000_256000_256000_256000_1_100_7_M"] = "Temu app (iOS)",

    ["120000_1500_34359738368_16777216_16777216_16777216_1024_1024_8_M"] = "AliExpress app",

    ["M_1472_16777216_32768_32768_32768_M_M_4_M"] = "Windows SMB",
    ["M_1472_16777216_65536_65536_65536_M_M_4_M"] = "Windows SMB",
}

-- Create a new protocol for registering a post-dissector
local proto = Proto("quic_fingerprint", "QUIC FP")

-- Create a field for the fingerprint
local field_fingerprint_simple               = ProtoField.string("quic_fingerprint.simple", "QUIC Fingerprint (simple)")
local field_fingerprint_simple_sorted        = ProtoField.string("quic_fingerprint.simple.sorted", "QUIC Fingerprint (simple) Sorted")
local field_fingerprint_all                  = ProtoField.string("quic_fingerprint.all", "QUIC Fingerprint (all parameters)")
local field_fingerprint_all_sorted           = ProtoField.string("quic_fingerprint.all.sorted", "QUIC Fingerprint (all parameters) Sorted")
local field_guessed_library                  = ProtoField.string("quic_fingerprint.library", "QUIC Library")
local field_guessed_app                      = ProtoField.string("quic_fingerprint.app", "QUIC Application")
local field_fingerprint_values               = ProtoField.string("quic_fingerprint.values", "QUIC Fingerprint (values)") -- Only sorted version
proto.fields = {
    field_fingerprint_simple,
    field_fingerprint_simple_sorted,
    field_fingerprint_all,
    field_fingerprint_all_sorted,
    field_guessed_library,
    field_guessed_app,
    field_fingerprint_values,
}

local function is_grease(value)
    if (tonumber(value) - 27) % 31 == 0 then
        return true
    end
    return false
end

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

-- The dissector function callback
function proto.dissector(tvb, pinfo, tree)
    local fingerprint = { {}, {} }
    local fingerprint_all = { {}, {} }
    for name, field in pairs(fields) do
        local values = { field() }
        if #values == 0 then return end
        for _, value in ipairs(values) do
            if name == "tls" then
                value = tostring(value)
                if lookup_tls_extensions[value] then
                    table.insert(fingerprint[1], value)
                    --table.insert(fingerprint_all[1], value)
                end
            elseif name == "quic" then
                value = string.format("0x%x", tostring(value))
                if lookup_transport_parameters[value] then
                    table.insert(fingerprint[2], value)
                end
		if is_grease(value) == false then
                    table.insert(fingerprint_all[2], value)
		end
            end
        end
    end
    if #fingerprint[1] == 0 or #fingerprint[2] == 0 then return end

    local fingerprint_values = {}
    local tp_value

    tps_value = tps_values.tp_max_idle_timeout()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_max_udp_payload_size()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_data()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_stream_data_bidi_local()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_stream_data_bidi_remote()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_stream_data_uni()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_streams_bidi()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_initial_max_streams_uni()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_active_connection_id_limit()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))
    tps_value = tps_values.tp_max_datagram_frame_size()
    table.insert(fingerprint_values, tps_value == nil and "M" or tostring(tps_value))

    -- Create a string representation of the fingerprint
    local fingerprint_str = table.concat(fingerprint[1], "_") .. "-" .. table.concat(fingerprint[2], "_")
    --local fingerprint_all_str = table.concat(fingerprint_all[1], "_") .. "-" .. table.concat(fingerprint_all[2], "_")
    local fingerprint_all_str = table.concat(fingerprint_all[2], "_")

    -- Sort the transport parameters
    table.sort(fingerprint[2])
    local fingerprint_str_sorted = table.concat(fingerprint[1], "_") .. "-" .. table.concat(fingerprint[2], "_")
    
    table.sort(fingerprint_all[2])
    --local fingerprint_all_str_sorted = table.concat(fingerprint_all[1], "_") .. "-" .. table.concat(fingerprint_all[2], "_")
    local fingerprint_all_str_sorted = table.concat(fingerprint_all[2], "_")

    -- Guess the libraries
    local guesses = {}
    table.insert(guesses, known_fingerprints[fingerprint_str])
    table.insert(guesses, known_fingerprints_sorted[fingerprint_str_sorted])

    print(dump(fingerprint_values))
    local fingerprint_values_str = table.concat(fingerprint_values, "_")
    
    -- Guess the application
    local guessed_app = {}
    table.insert(guessed_app, known_fingerprints_tp_values[fingerprint_values_str])

    -- Add the fingerprint to the dissection tree
    local fingerprint_tree = tree:add(proto):set_generated()
    fingerprint_tree:add(field_fingerprint_simple, fingerprint_str):set_generated()
    fingerprint_tree:add(field_fingerprint_simple_sorted, fingerprint_str_sorted):set_generated()

    fingerprint_tree:add(field_guessed_library, #guesses > 0 and table.concat(guesses, ", ") or "Unknown"):set_generated()

    fingerprint_tree:add(field_fingerprint_all, fingerprint_all_str):set_generated()
    fingerprint_tree:add(field_fingerprint_all_sorted, fingerprint_all_str_sorted):set_generated()
    fingerprint_tree:add(field_guessed_app, #guessed_app > 0 and table.concat(guessed_app, ", ") or "Unknown"):set_generated()

    fingerprint_tree:add(field_fingerprint_values, fingerprint_values_str):set_generated()

end

-- Register the protocol as a post-dissector
register_postdissector(proto)
