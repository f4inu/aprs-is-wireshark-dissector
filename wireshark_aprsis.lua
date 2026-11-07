-- wireshark_aprsis.lua
-- APRS-IS dissector (personal Lua plugin)
--
-- Decodes APRS-IS TCP sessions (ports 10152 and 14580):
--   * TCP line reassembly (APRS frames may span TCP segments)
--   * server chatter (# aprsc, # logresp), login lines, blank-line heartbeats
--   * source / destination / digipeater path / q-construct
--   * information-field parsing for the APRS 1.01 + 1.1 + 1.2 data types:
--     position (!, =, /, @, compressed), status (>), message (: incl. multi-addressee,
--     ack/rej/multi-ack, BLN/NWS bulletins), object (; incl. base-91 timestamps,
--     killed status, no-position placeholder), item () and DF item ("),
--     Mic-E (` ' and 0x1c..0x1e) with destination-call latitude digits,
--     weather (_ and post-position _ extension), telemetry (T incl. T#, T=, T!,
--     T^, labels), capabilities (<), raw NMEA/GPS ($), third-party (}, recursive),
--     positionless course/speed (, and -), query (?), user-defined ({),
--     Maidenhead beacon ([), Peet/Agrelo/map/shelter/space-wx (raw).
--   * comment extras: /A= altitude, FFF.FFFMHz frequency, PHG/DFS, !DAO!,
--     base-91 comment telemetry |...|
--
-- Install: copy to the personal Lua plugins folder, then start Wireshark.
--   $ cp wireshark_aprsis.lua ~/.local/lib/wireshark/plugins/
--
-- Original dissector: ports 10152 only, source/dest/path/q-construct,
-- message/status/position/weather basics.

-- Déclaration du protocole
local aprsis_proto = Proto("aprsis", "APRS-IS Protocol")

---------------------------------------------------------------------------
-- Header fields (names kept from the original dissector for filter compat)
---------------------------------------------------------------------------
-- Définition des champs
local f_source = ProtoField.string("aprsis.source", "Source Callsign")
local f_src_ssid = ProtoField.string("aprsis.source.ssid", "Source SSID")
local f_dstcallsign = ProtoField.string("aprsis.destination_callsign", "Destination Callsign")
local f_dstcallsign_ssid = ProtoField.string("aprsis.destination_callsign.ssid", "Destination SSID")
local f_digipeater_path_raw = ProtoField.string("aprsis.digipeater_path.raw", "Digipeater Path (Raw)")
local f_digipeater_callsign = ProtoField.string("aprsis.digipeater.callsign", "Digipeater Callsign")
local f_digipeater_direct = ProtoField.bool("aprsis.digipeater.direct", "Heard Directly (path used)")

-- Champs pour le q-construct
local f_q_construct_code = ProtoField.string("aprsis.q_construct.code", "Q-Construct Code")
local f_q_construct_description = ProtoField.string("aprsis.q_construct.description", "Q-Construct Description")
local f_q_construct_callsign = ProtoField.string("aprsis.q_construct.callsign", "Q-Construct Callsign/Server")

-- Champs génériques pour le champ d'information
local f_info_field_raw = ProtoField.string("aprsis.info_field.raw", "Information Field (Raw)")
local f_info_field_type_char = ProtoField.string("aprsis.info_field.type_char", "Information Field Type Character")
local f_info_field_type_decoded = ProtoField.string("aprsis.info_field.type_decoded", "Information Field Type")

---------------------------------------------------------------------------
-- Session / server fields
---------------------------------------------------------------------------
local f_login_user = ProtoField.string("aprsis.login.user", "Login User")
local f_login_passcode = ProtoField.string("aprsis.login.passcode", "Login Passcode")
local f_login_options = ProtoField.string("aprsis.login.options", "Login Options (vers/filter/...)")
local f_server_line = ProtoField.string("aprsis.server.line", "Server Comment Line")
local f_server_software = ProtoField.string("aprsis.server.software", "Server Software")
local f_logresp_call = ProtoField.string("aprsis.logresp.call", "Login Response Callsign")
local f_logresp_result = ProtoField.string("aprsis.logresp.result", "Login Response Result (verified/unverified)")
local f_logresp_server = ProtoField.string("aprsis.logresp.server", "Connected Server")

---------------------------------------------------------------------------
-- Message fields
---------------------------------------------------------------------------
-- Champs spécifiques aux messages (type ':')
local f_message_recipient = ProtoField.string("aprsis.message.recipient", "Message Recipient")
local f_message_text = ProtoField.string("aprsis.message.text", "Message Text")
local f_message_id = ProtoField.string("aprsis.message.id", "Message ID")
local f_message_action = ProtoField.string("aprsis.message.action", "Message Action (msg/ack/rej/mult-ack/bulletin)")

-- Champs spécifiques aux statuts (type '>')
local f_status_text = ProtoField.string("aprsis.status.text", "Status Text")

---------------------------------------------------------------------------
-- Position fields
---------------------------------------------------------------------------
-- Champs spécifiques aux rapports de position (types '!', '=', '/', '@')
local f_latitude = ProtoField.string("aprsis.position.latitude", "Latitude")
local f_longitude = ProtoField.string("aprsis.position.longitude", "Longitude")
local f_lat_deg = ProtoField.double("aprsis.position.lat_deg", "Latitude (decimal degrees)")
local f_lon_deg = ProtoField.double("aprsis.position.lon_deg", "Longitude (decimal degrees)")
local f_symbol_table = ProtoField.string("aprsis.position.symbol_table", "Symbol Table")
local f_symbol_code = ProtoField.string("aprsis.position.symbol_code", "Symbol Code")
local f_symbol_name = ProtoField.string("aprsis.position.symbol_name", "Symbol Name")
local f_timestamp = ProtoField.string("aprsis.position.timestamp", "Timestamp")
local f_timestamp_b91 = ProtoField.string("aprsis.position.timestamp_base91", "Base-91 Timestamp")
local f_pos_unknown = ProtoField.bool("aprsis.position.unknown", "Position Unknown (blank placeholder)")
local f_compressed = ProtoField.bool("aprsis.position.compressed", "Compressed Position")
local f_course = ProtoField.uint16("aprsis.position.course", "Course (deg)")
local f_speed = ProtoField.uint16("aprsis.position.speed", "Speed (knots)")
local f_altitude = ProtoField.int32("aprsis.position.altitude", "Altitude (feet)")
local f_altitude_m = ProtoField.int32("aprsis.position.altitude_m", "Altitude /A= (meters)")
local f_comment = ProtoField.string("aprsis.position.comment", "Comment")

---------------------------------------------------------------------------
-- Comment extras
---------------------------------------------------------------------------
local f_freq = ProtoField.string("aprsis.freq", "Frequency (FFF.FFFMHz)")
local f_dao = ProtoField.string("aprsis.dao", "!DAO! High-Precision Position")
local f_phg = ProtoField.string("aprsis.phg", "PHG Pattern")
local f_dfs = ProtoField.string("aprsis.dfs", "DFS Signal Strength")
local f_b91_telem = ProtoField.string("aprsis.telemetry.b91_comment", "Base-91 Comment Telemetry |...|")

---------------------------------------------------------------------------
-- Object / item
---------------------------------------------------------------------------
local f_object_name = ProtoField.string("aprsis.object.name", "Object Name")
local f_object_status = ProtoField.string("aprsis.object.status", "Object Status (live/killed)")
local f_item_name = ProtoField.string("aprsis.item.name", "Item Name")
local f_item_status = ProtoField.string("aprsis.item.status", "Item Status (live/killed)")
local f_item_overlay = ProtoField.string("aprsis.item.overlay", "Item Symbol Overlay")

---------------------------------------------------------------------------
-- Mic-E
---------------------------------------------------------------------------
local f_mice_dst_lat = ProtoField.string("aprsis.mic_e.dst_lat", "Mic-E Latitude (from Destination Call)")
local f_mice_dst_msg = ProtoField.string("aprsis.mic_e.dst_msg", "Mic-E Message Status (from Destination Call)")
local f_mice_dst_ns = ProtoField.string("aprsis.mic_e.dst_ns", "Mic-E N/S (from Destination Call)")
local f_mice_dst_offset = ProtoField.string("aprsis.mic_e.dst_offset", "Mic-E Longitude Offset (from Destination Call)")
local f_mice_dst_we = ProtoField.string("aprsis.mic_e.dst_we", "Mic-E E/W (from Destination Call)")
local f_mice_alt = ProtoField.string("aprsis.mic_e.altitude", "Mic-E Altitude NNNN}")
local f_mice_mfr_type = ProtoField.string("aprsis.mic_e.mfr_type", "Mic-E Manufacturer Type Byte")
local f_mice_mfr_version = ProtoField.string("aprsis.mic_e.mfr_version", "Mic-E Manufacturer Version Byte")
local f_mice_status = ProtoField.string("aprsis.mic_e.status", "Mic-E Status/Text Field")
local f_mice_telemetry = ProtoField.string("aprsis.mic_e.telemetry", "Mic-E Telemetry Field")

---------------------------------------------------------------------------
-- Telemetry (DTI 'T')
---------------------------------------------------------------------------
local f_telem_seq = ProtoField.string("aprsis.telemetry.sequence", "Telemetry Sequence")
local f_telem_analog = ProtoField.string("aprsis.telemetry.analog", "Telemetry Analog Values")
local f_telem_bits = ProtoField.string("aprsis.telemetry.bits", "Telemetry Bits/Flags")
local f_telem_labels = ProtoField.string("aprsis.telemetry.labels", "Telemetry Labels/Config/Thresholds")

---------------------------------------------------------------------------
-- Weather
---------------------------------------------------------------------------
local f_weather_name = ProtoField.string("aprsis.weather.name", "Weather Station Name")
-- Champs spécifiques aux rapports météo (type '_')
local f_wind_direction = ProtoField.uint16("aprsis.weather.wind_direction", "Wind Direction (deg)")
local f_wind_speed = ProtoField.uint16("aprsis.weather.wind_speed", "Wind Speed (mph)")
local f_wind_peak = ProtoField.uint16("aprsis.weather.wind_peak", "Peak Wind Gust (mph, last 5 min)")
local f_temperature = ProtoField.int16("aprsis.weather.temperature", "Temperature (deg F)")
local f_humidity = ProtoField.uint8("aprsis.weather.humidity", "Humidity (%)")
local f_pressure = ProtoField.uint16("aprsis.weather.pressure", "Barometric Pressure (hPa)")
local f_rainfall_1h = ProtoField.float("aprsis.weather.rainfall_1h", "Rainfall 1h (inches)")
local f_rainfall_24h = ProtoField.float("aprsis.weather.rainfall_24h", "Rainfall 24h (inches)")
local f_rainfall_midnight = ProtoField.float("aprsis.weather.rainfall_midnight", "Rainfall since Midnight (inches)")
local f_raw_rainfall = ProtoField.uint16("aprsis.weather.raw_rainfall", "Raw Rainfall Counter")
local f_luminosity = ProtoField.uint16("aprsis.weather.luminosity", "Luminosity (W/m^2)")
local f_snow_1h = ProtoField.uint16("aprsis.weather.snow_1h", "Snow 24h (inches)")
local f_snow_30d = ProtoField.uint16("aprsis.weather.snow_30d", "Snow 30d (inches)")
local f_weather_unit = ProtoField.string("aprsis.weather.unit", "Software ID / Unit Bytes")
local f_weather_comment = ProtoField.string("aprsis.weather.comment", "Weather Comment")

---------------------------------------------------------------------------
-- Other DTIs
---------------------------------------------------------------------------
local f_caps_xml = ProtoField.string("aprsis.caps.xml", "Station Capabilities XML")
local f_nmea = ProtoField.string("aprsis.raw.nmea", "Raw NMEA/GPS Sentence")
local f_raw_dtibody = ProtoField.string("aprsis.raw.dti_body", "Information Body (unparsed DTI)")
local f_3rdparty_path = ProtoField.string("aprsis.third_party.path", "Third-Party Original Path")
local f_query = ProtoField.string("aprsis.query", "Query")
local f_msg_count = ProtoField.uint32("aprsis.line_count", "APRS Packets in Segment")
local f_line_len = ProtoField.uint32("aprsis.line.length", "Line Length (bytes)")

local f_expert_malformed = ProtoField.string("aprsis.malformed", "Malformed APRS Line")

aprsis_proto.fields = {
    f_source, f_src_ssid, f_dstcallsign, f_dstcallsign_ssid,
    f_digipeater_path_raw, f_digipeater_callsign, f_digipeater_direct,
    f_q_construct_code, f_q_construct_description, f_q_construct_callsign,
    f_info_field_raw, f_info_field_type_char, f_info_field_type_decoded,
    f_login_user, f_login_passcode, f_login_options,
    f_server_line, f_server_software, f_logresp_call, f_logresp_result, f_logresp_server,
    f_message_recipient, f_message_text, f_message_id, f_message_action,
    f_status_text,
    f_latitude, f_longitude, f_lat_deg, f_lon_deg, f_symbol_table, f_symbol_code, f_symbol_name,
    f_timestamp, f_timestamp_b91, f_pos_unknown, f_compressed,
    f_course, f_speed, f_altitude, f_altitude_m, f_comment,
    f_freq, f_dao, f_phg, f_dfs, f_b91_telem,
    f_object_name, f_object_status, f_item_name, f_item_status, f_item_overlay,
    f_mice_dst_lat, f_mice_dst_msg, f_mice_dst_ns, f_mice_dst_offset, f_mice_dst_we,
    f_mice_alt, f_mice_mfr_type, f_mice_mfr_version, f_mice_status, f_mice_telemetry,
    f_telem_seq, f_telem_analog, f_telem_bits, f_telem_labels,
    f_weather_name, f_wind_direction, f_wind_speed, f_wind_peak, f_temperature,
    f_humidity, f_pressure, f_rainfall_1h, f_rainfall_24h, f_rainfall_midnight,
    f_raw_rainfall, f_luminosity, f_snow_1h, f_snow_30d, f_weather_unit, f_weather_comment,
    f_caps_xml, f_nmea, f_raw_dtibody, f_3rdparty_path, f_query,
    f_msg_count, f_line_len, f_expert_malformed,
}

---------------------------------------------------------------------------
-- Lookup tables
---------------------------------------------------------------------------
-- APRS 1.01 + 1.1 + 1.2 data type identifiers.
-- Table de correspondance pour les types de champs d'information APRS
local info_field_type_map = {
    [":"]  = "Message",
    [">"]  = "Status",
    ["!"]  = "Position (no timestamp, or compressed, or Ultimeter WX)",
    ["="]  = "Position (no timestamp) + messaging extension",
    ["/"]  = "Position (with timestamp)",
    ["@"]  = "Position (with timestamp) + messaging extension",
    ["_"]  = "Weather Report (no position)",
    [";"]  = "Object Report",
    [")"]  = "Item",
    ['"']  = "Item (DF station)",
    ["`"]  = "Mic-E (current data, msg-capable)",
    ["'"]  = "Mic-E (old data, or one-way tracker)",
    ["T"]  = "Telemetry Data",
    ["<"]  = "Station Capabilities",
    ["$"]  = "Raw GPS / NMEA",
    ["?"]  = "Query",
    ["}"]  = "Third-Party Traffic",
    ["{"]  = "User-Defined Data",
    ["["]  = "Maidenhead Grid Beacon (obsolete)",
    [","]  = "Course and Speed (no position, APRS 1.1)",
    ["-"]  = "Course and Speed (no position, APRS 1.1)",
    ["#"]  = "Peet Bros U-II Weather Station",
    ["*"]  = "Peet Bros U-II Weather Station (raw) / PHG",
    ["%"]  = "Agrelo DFJr / MicroFinder",
    ["&"]  = "Map Feature",
    ["+"]  = "Shelter Data with Time",
    ["."]  = "Space Weather",
    ["("]  = "MWX2 Raw (unimplemented)",
    [string.char(0x1c)] = "Mic-E (current, rev 0)",
    [string.char(0x1d)] = "Mic-E (old, rev 0)",
    [string.char(0x1e)] = "Status or Information (rev 0)",
    [string.char(0x1f)] = "Information (rev 0)",
}

-- Q-construct lookup table (descriptions combinées pour les codes ambigus)
local q_construct_map = {
    ["qAC"] = "Server: Verified login via bidirectional port.",
    ["qAX"] = "Server: Unverified login (deprecated).",
    ["qAU"] = "Server: Direct via UDP.",
    ["qAo"] = "Server: Gated via client-only port.",
    ["qAO"] = "Gated from RF without messaging (Client) / Non-gated via send-only port or indirect via client-only port (Server).",
    ["qAS"] = "Server: Packet via server without q construct.",
    ["qAr"] = "Server: Gated using ,I construct from remote IGate.",
    ["qAR"] = "Gated from RF (Client) / Gated using ,I construct with verified IGate login (Server).",
    ["qAZ"] = "Client/Server: Command packet (not propagated).",
    ["qAI"] = "Client: Trace packet.",
    ["qTS"] = "Igate: packet sent to RF, source path report (APRS 1.2).",
    ["qTR"] = "Igate: RF packet gated upstream, path report (APRS 1.2).",
}

-- Mic-E destination-call encoding (original APRS 1.01 scheme, same table as
-- Wireshark's packet-aprs.c). NOTE: modern transmitters may use the 2016
-- "Mic-E TOCALL" variant (aprs.org/aprs12, digits and letters swap message
-- bits and give explicit hemispheres); decoding with the 2016 table is a
-- TODO -- hemispheres/message bits may be wrong for 2016-style traffic.
local mice_dst_table = {}
for c = string.byte("0"), string.byte("9") do
    mice_dst_table[c] = { digit = string.char(c), msg = 0, ns = "S", off = 0, we = "E" }
end
for c = string.byte("A"), string.byte("J") do
    mice_dst_table[c] = { digit = tostring(c - string.byte("A")), msg = 1, ns = "?", off = 0, we = "?" }
end
mice_dst_table[string.byte("K")] = { digit = " ", msg = 1, ns = "?", off = 0, we = "?" }
mice_dst_table[string.byte("L")] = { digit = " ", msg = 0, ns = "S", off = 0, we = "E" }
for c = string.byte("P"), string.byte("Y") do
    mice_dst_table[c] = { digit = tostring(c - string.byte("P")), msg = 1, ns = "N", off = 100, we = "W" }
end
mice_dst_table[string.byte("Z")] = { digit = " ", msg = 1, ns = "N", off = 100, we = "W" }

local mice_msg_table = {
    [0] = "Emergency", [1] = "Priority", [2] = "Special", [3] = "Committed",
    [4] = "Returning", [5] = "In Service", [6] = "En Route", [7] = "Off Duty",
    [8] = "Custom 6", [9] = "Custom 5", [10] = "Custom 4", [11] = "Custom 3",
    [12] = "Custom 2", [13] = "Custom 1", [14] = "Custom 0",
}

-- symbol code names for the most common codes (primary table '/')
local symbol_names = {
    ["#"] = "Number/Digit", ["$"] = "Antenna", ["("] = "Call Center (D-STAR)",
    [")"] = "Bar and Shield (D-STAR)", ["+"] = "House QTH DX", ["-"] = "Mobile",
    ["?"] = "Unknown", ["/"] = "Center dot (primary symbol)", ["<"] = "Ambulance",
    [">"] = "Direction Finder", ["A"] = "Aid station", ["B"] = "BBS",
    ["b"] = "Balloon", ["C"] = "Canoe/Kayak", ["c"] = "Cooper (HW-220)",
    ["D"] = "DF direction finding", ["d"] = "Diamond", ["E"] = "EPIR/Emergency 1st",
    ["e"] = "Ice", ["F"] = "RX only", ["f"] = "Fire", ["G"] = "Grid locator",
    ["g"] = "GPS (satellite)", ["H"] = "Hotel", ["h"] = "Heliport",
    ["I"] = "HTTP/TCP", ["i"] = "Packet iGate", ["J"] = "Event/Jamboree",
    ["K"] = "KML source", ["k"] = "School", ["L"] = "Aid", ["M"] = "AM/FM radio",
    ["m"] = "Mic-E repeater", ["N"] = "Node (stationary)", ["n"] = "W32/64-bit",
    ["O"] = "Ballot", ["o"] = "Discipline", ["P"] = "RV", ["p"] = "Rover",
    ["Q"] = "QTH (locator)", ["q"] = "Yagi", ["R"] = "RX+TX", ["r"] = "Roofer",
    ["S"] = "Shuttle", ["s"] = "Satellite", ["T"] = "Antenna tower",
    ["t"] = "Mountain", ["U"] = "Urban", ["u"] = "Multipart", ["V"] = "Van",
    ["v"] = "Truck", ["W"] = "Weather", ["w"] = "Special, wx station",
    ["X"] = "HELO", ["x"] = "Transceiver", ["Y"] = "RC6", ["y"] = "TNC/SS",
    ["Z"] = "Object", ["z"] = "SSTV", ["["] = "Shooting star", ["\\"] = "HF gateway",
    ["^"] = "Moonbounce", ["_"] = "DF antenna", ["`"] = "Handheld",
    ["a"] = "Amb", ["c"] = "Cooper", ["l"] = "LoG (log)", ["n"] = "WP",
}

---------------------------------------------------------------------------
-- Small helpers
---------------------------------------------------------------------------
local function add_str(tree, field, boff, len, value)
    if value == nil then return end
    if len and len > 0 then
        tree:add(field, value)
    else
        tree:add(field, value)
    end
end

-- Add a byte-backed string field.
local function add_range(tree, field, buffer, boff, len)
    if len == nil or len <= 0 then return end
    tree:add(field, buffer:range(boff, len))
end

-- Convert "DDMM.SSN" / "DDDMM.SSW" to decimal degrees.
local function dmm_to_deg(s)
    local deg = tonumber(s:sub(1, s:len() - 6))
    local min = tonumber(s:sub(s:len() - 4))
    if deg == nil or min == nil then return nil end
    local v = deg + min / 60.0
    local hemi = s:sub(-1)
    if hemi == "S" or hemi == "W" then v = -v end
    return v
end

-- Parse a position+symbol+extension run and attach comment extras.
-- pos_str starts at the latitude. Returns consumed length, or nil on no match.
local function parse_position(tree, buffer, boff, pos_str, default_symtable)
    -- Cette fonction tente d'analyser les formats non compressés les plus courants.
    -- Cf APRS 1.01, Section 9 pour tous les détails.
    local consumed = 0
    local unknown = false

    -- timestamp forms
    local ts = pos_str:match("^%d%d%d%d%d%d[z/h]")
    if ts then
        add_range(tree, f_timestamp, buffer, boff, 7)
        pos_str = pos_str:sub(8)
        consumed = consumed + 7
    end

    -- uncompressed position: symbol table may be ANY single character
    local lat, stab, lon, rest = pos_str:match(
        "^(%d%d%d%d%.%d%d[NnSs])(.)(%d%d%d%d%d%.%d%d[EeWw])(.*)$")
    if not lat then
        -- "no position" placeholder (space-filled), used by objects/gateways
        lat, stab, lon, rest = pos_str:match(
            "^(%d%d%d%d%.  [NSEW])(.)(%d%d%d%d%d%.  [EeWw])(.*)$")
        if lat then unknown = true end
    end

    if lat then
        add_range(tree, f_latitude, buffer, boff + consumed, 8)
        add_range(tree, f_symbol_table, buffer, boff + consumed + 8, 1)
        add_range(tree, f_longitude, buffer, boff + consumed + 9, 9)
        local latv = dmm_to_deg(lat)
        local lonv = dmm_to_deg(lon)
        if latv then tree:add(f_lat_deg, unknown and 0.0 or latv) end
        if lonv then tree:add(f_lon_deg, unknown and 0.0 or lonv) end
        if unknown then tree:add(f_pos_unknown, true) end
        consumed = consumed + 18

        local symc = rest:sub(1, 1)
        add_range(tree, f_symbol_code, buffer, boff + consumed, 1)
        consumed = consumed + 1
        local comment = rest:sub(2)
        local name = symbol_names[symc]
        if name then tree:add(f_symbol_name, name) end
        return consumed, lat, lon, stab, symc, comment
    end

    -- compressed position: symbol-table char + 4 lat + 4 lon + symbol code
    -- (valid only when the first char is printable and not a digit)
    local first = pos_str:sub(1, 1)
    local b1 = first:byte()
    if b1 and b1 >= 33 and b1 <= 126 and not first:match("%d") then
        local stab2 = first
        local latc = pos_str:sub(2, 5)
        local lonc = pos_str:sub(6, 9)
        local symc = pos_str:sub(10, 10)
        local rest2 = pos_str:sub(11)
        if latc:len() == 4 and lonc:len() == 4 then
            local function dec4(s)
                local v = 0
                for i = 1, 4 do v = (v + s:byte(i) - 33) end
                -- base-91 positional
                v = 0
                for i = 1, 4 do v = v * 91 + (s:byte(i) - 33) end
                return v
            end
            local lv = dec4(latc)
            local ov = dec4(lonc)
            local latv2 = 90.0 - lv / 380926.0
            local lonv2 = ov / 190463.0 - 180.0
            add_range(tree, f_symbol_table, buffer, boff, 1)
            add_str(tree, f_latitude, boff + 1, 4, string.format("%.4f", latv2))
            add_str(tree, f_longitude, boff + 5, 4, string.format("%.4f", lonv2))
            tree:add(f_lat_deg, latv2)
            tree:add(f_lon_deg, lonv2)
            add_range(tree, f_symbol_code, buffer, boff + 9, 1)
            tree:add(f_compressed, true)
            return 10, latv2, lonv2, stab2, symc, rest2
        end
    end
    return nil
end

-- Attach comment extras and return (course, speed, alt_ft) if the comment
-- starts with a course/speed extension. Mutates comment scan fields.
local function parse_comment_extras(tree, comment)
    local cse, spd, alt = nil, nil, nil
    local rest = comment
    if rest:match("^%d%d%d/%d%d%d") then
        cse = tonumber(rest:sub(1, 3))
        spd = tonumber(rest:sub(5, 7))
        rest = rest:sub(8)
        local a = rest:match("^/%d(%d%d%d%d%d)")
        if a then
            alt = tonumber(a)
            if alt >= 80000 then alt = alt - 190000 end
            rest = rest:sub(7)
        end
        if cse and cse ~= 0 then tree:add(f_course, cse) end
        if spd and spd ~= 0 then tree:add(f_speed, spd) end
        if alt then tree:add(f_altitude, alt) end
    end
    if cse == 0 and spd == 0 then
        -- wx-style "000/000" is wind dir/speed, handled by weather parser
    end
    local am = rest:match("/A=([+%-]%d%d%d%d%d)")
    if am then tree:add(f_altitude_m, tonumber(am)) end
    local fq = rest:match("(%d%d?%d?%d%.%d%d)MHz")
    if fq then tree:add(f_freq, fq .. "MHz") end
    local dao = rest:match("!(%b!!)")
    if dao then tree:add(f_dao, dao) end
    local phg = rest:match("(PHG%d%d%d%d)")
    if phg then tree:add(f_phg, phg) end
    local dfs = rest:match("(DFS%d%d%d%d)")
    if dfs then tree:add(f_dfs, dfs) end
    local b91 = rest:match("!(%|%d%d?%d?%,?[^!]-|)!")
    if b91 then tree:add(f_b91_telem, b91) end
    return rest
end

-- Weather fields letter-scan. wx_str starts after the symbol '_' or DTI '_'.
    -- Tenter d'extraire les paramètres météo courants
local function parse_weather(tree, buffer, boff, wx_str)
    local off = 0
    -- station name (1.0: n + 3 chars; 1.1: n + name up to space)
    local n3 = wx_str:match("^n(%d%d%d)")
    local nlong = wx_str:match("^n(%S+)%s")
    if n3 then
        add_range(tree, f_weather_name, buffer, boff, 4)
        off = 4
    elseif nlong then
        add_range(tree, f_weather_name, buffer, boff, 1 + nlong:len())
        off = 1 + nlong:len()
    end
    wx_str = wx_str:sub(off + 1)
    boff = boff + off

    -- optional wind direction/speed/gust: ddd/sssggg or ddd/sss (with unknown "...")
    local wd, ws, wp = wx_str:match("^(%d%d%d)/(%d%d%d)(/g(%d%d%d))?")
    if not wd then
        wd, ws, wp = wx_str:match("^(%d%d%d)/(%d%d%d)")
    end
    if wd then
        if wd ~= "..." then
            tree:add(f_wind_direction, tonumber(wd))
            if tonumber(ws) < 500 then tree:add(f_wind_speed, tonumber(ws)) end
        end
        local skip = 7
        local g = wx_str:match("^%d%d%d/%d%d%d/g(%d%d%d)")
        if g then tree:add(f_wind_peak, tonumber(g)); skip = 11 end
        wx_str = wx_str:sub(skip + 1)
        boff = boff + skip
    elseif wx_str:match("^%.%.%./%.%.%.") then
        -- unknown wind (".../...")
        wx_str = wx_str:sub(8)
        boff = boff + 7
    end

    -- letter fields, positional scan
    local consumed = 0
    local snow_seen = false
    while wx_str:len() > 0 do
        local ch = wx_str:sub(1, 1)
        local v
        local flen = 0
        if ch == "c" then v = wx_str:match("^c(%d%d%d)"); flen = 4
            if v then tree:add(f_wind_direction, tonumber(v)) end
        elseif ch == "s" then v = wx_str:match("^s(%-%-?%d?%d?%d)"); flen = 2 + (v and v:len() or 0)
            if v and v ~= "--" and tonumber(v) ~= nil then tree:add(f_wind_speed, tonumber(v)) end
        elseif ch == "g" then v = wx_str:match("^g(%-%-?%d?%d?%d)"); flen = 2 + (v and v:len() or 0)
            if v and v ~= "--" and tonumber(v) ~= nil then tree:add(f_wind_peak, tonumber(v)) end
        elseif ch == "t" then v = wx_str:match("^t([+%-]?%d%d?%d)"); flen = 2 + (v and v:len() or 0)
            if v and tonumber(v) ~= nil and tonumber(v) > -200 then tree:add(f_temperature, tonumber(v)) end
        elseif ch == "r" then v = wx_str:match("^r(%d%d%.%d)"); flen = 5
            if v then tree:add(f_rainfall_1h, tonumber(v)) end
        elseif ch == "p" then v = wx_str:match("^p(%d%d%.%d)"); flen = 5
            if v then tree:add(f_rainfall_24h, tonumber(v)) end
        elseif ch == "P" then v = wx_str:match("^P(%d%d%.%d)"); flen = 5
            if v then tree:add(f_rainfall_midnight, tonumber(v)) end
        elseif ch == "h" then v = wx_str:match("^h(%d%d%d?)"); flen = 2 + (v and v:len() or 0)
            -- humidity: 2 or 3 digits (3-digit = tenths resolution)
            if v then tree:add(f_humidity, tonumber(v)) end
        elseif ch == "b" then v = wx_str:match("^b(%d%d%d%d%d%d?)"); flen = 2 + (v and v:len() or 0)
            if v then
                local p = tonumber(v)
                if v:len() == 6 then p = p / 10 end
                tree:add(f_pressure, p)
            end
        elseif ch == "l" or ch == "L" then v = wx_str:match("^[lL](%d%d%d)"); flen = 4
            if v then tree:add(f_luminosity, tonumber(v)) end
        elseif ch == "S" then v = wx_str:match("^S(%d%d%d)"); flen = 4
            if v then
                -- first S = 24h snowfall, second S = 30d snowfall
                if not snow_seen then
                    tree:add(f_snow_1h, tonumber(v)); snow_seen = true
                else
                    tree:add(f_snow_30d, tonumber(v))
                end
            end
        elseif ch == "#" then v = wx_str:match("^#(%d%d%d%d)"); flen = 5
            if v then tree:add(f_raw_rainfall, tonumber(v)) end
        else
            break
        end
        if not v then break end
        consumed = consumed + flen
        wx_str = wx_str:sub(flen + 1)
    end

    -- remaining: software id char + unit char (a-zA-Z), then comment
    local sw, unit = wx_str:match("^([a-zA-Z])([a-zA-Z])")
    if sw then
        add_range(tree, f_weather_unit, buffer, boff + consumed, 2)
        consumed = consumed + 2
        wx_str = wx_str:sub(3)
    end
    if wx_str:len() > 0 then
        add_range(tree, f_weather_comment, buffer, boff + consumed, wx_str:len())
    end
end

-- Mic-E destination-call decoding. dst is the callsign string (no SSID).
local function mice_decode_dst(tree, dst)
    if not dst or dst:len() < 6 then return end
    local digits = {}
    local msgbits = {}
    for i = 1, 6 do
        local e = mice_dst_table[dst:byte(i)]
        if not e then return end
        digits[i] = e.digit
        if i <= 3 then table.insert(msgbits, e.msg) end
        if i == 4 then tree:add(f_mice_dst_ns, e.ns) end
        if i == 5 and e.off > 0 then tree:add(f_mice_dst_offset, "+" .. e.off) end
        if i == 6 then tree:add(f_mice_dst_we, e.we) end
    end
    tree:add(f_mice_dst_lat, string.format("%s%s%s%s.%s%s",
        digits[1], digits[2], digits[3], digits[4], digits[5], digits[6]))
    if msgbits[1] == 1 and msgbits[2] == 1 and msgbits[3] == 1 then
        tree:add(f_mice_dst_msg, "Custom (all 1s)")
    else
        local m = msgbits[1] * 4 + msgbits[2] * 2 + msgbits[3]
        tree:add(f_mice_dst_msg, mice_msg_table[m] or "?")
    end
end

---------------------------------------------------------------------------
-- Information-field parsers (each returns nothing, adds fields to tree)
---------------------------------------------------------------------------
local parse_info  -- forward declaration (third-party recursion)

local function parse_message(tree, info)
    -- Format: :recipient:message_text{id}
    -- info starts after DTI ':'
    local body = info:sub(2)
    local recipients = {}
    local pos = 1
    while true do
        if body:sub(pos, pos) ~= ":" then
            -- first addressee may omit leading ':' in some clients
        end
        local field = body:sub(pos, pos + 9)
        local call = field:match("^(%S+%s*)")
        if not call then break end
        table.insert(recipients, (call:gsub("%s+$", "")))
        pos = pos + call:len()
        local sep = body:sub(pos, pos)
        if sep == ":" or sep == "" then break end
        pos = pos + 1  -- skip ',' '}' ']' separator
    end
    local text = body:sub(pos + 1)
    local action = "Message"
    if recipients[1] and recipients[1]:match("^BLN") then action = "Bulletin" end
    if recipients[1] and recipients[1]:match("^<") then action = "Bulletin (NWS/typed)" end
    if #recipients > 1 then action = "Multi-address message" end
    local id = text:match("{(%d%d%d%d%d%d?%d?%d?)}$")
    if id then text = text:sub(1, text:len() - id:len() - 2) end
    local acknum = text:match("^ack ?(%d+)")
    local rejnum = text:match("^rej ?(%d+)")
    if acknum then action = "Ack"; text = "ack " .. acknum end
    if rejnum then action = "Reject"; text = "rej " .. rejnum end
    if text == "" and action == "Message" and body:match("^:%S+%s*%}+$") then
        action = "Multi-ack"
    end
    for _, r in ipairs(recipients) do tree:add(f_message_recipient, r) end
    if action ~= "Multi-ack" and text:len() > 0 then tree:add(f_message_text, text) end
    tree:add(f_message_action, action)
    if id then tree:add(f_message_id, id) end
end

local function parse_object(tree, buffer, boff, info)
    -- ;NAME9STATUS ts position sym comment
    local body = info:sub(2)
    if body:len() < 11 then tree:add(f_raw_dtibody, info) return end
    add_range(tree, f_object_name, buffer, boff, 9)
    local status = body:sub(10, 10)
    local statxt = ({ ["*"] = "live (1.0)", ["!"] = "live (1.1)",
        ["_"] = "killed (1.0)", ["}"] = "killed (1.1)", ["'"] = "live" })[status] or status
    tree:add(f_object_status, statxt)
    local rest = body:sub(11)
    local rboff = boff + 10
    -- timestamp: DHM/HMS/MDHM or base-91
    if rest:match("^%d%d%d%d%d%d[z/h]") then
        add_range(tree, f_timestamp, buffer, rboff, 7)
        rest = rest:sub(8); rboff = rboff + 7
    elseif rest:match("^!%d%d%d%d%d%d!") then
        add_range(tree, f_timestamp, buffer, rboff, 7)
        rest = rest:sub(8); rboff = rboff + 7
    elseif rest:sub(1, 1) == "!" then
        -- base-91 timestamp: ! + 7 chars + !  (aprs 1.1)
        local b91 = rest:match("^!([0-9A-Za-v][0-9A-Za-v][0-9A-Za-v][0-9A-Za-v][0-9A-Za-v][0-9A-Za-v][0-9A-Za-v])!")
        if b91 then
            local secs = 0
            for i = 1, 7 do secs = secs * 91 + (b91:byte(i) - 33) end
            tree:add(f_timestamp_b91, string.format("!%s! = %d s", b91, secs))
            rest = rest:sub(9); rboff = rboff + 9
        end
    end
    local consumed = parse_position(tree, buffer, rboff, rest)
    if consumed then
        local after = rest:sub(consumed + 1)
        -- if symbol code is '_' a weather extension follows the position
        local symc_pos = rboff + consumed - 1
        if rest:sub(consumed, consumed) == "_" then
            parse_weather(tree, buffer, rboff + consumed, after)
        else
            local remainder = parse_comment_extras(tree, after)
            if remainder:len() > 0 then
                add_range(tree, f_comment, buffer, rboff + consumed, remainder:len())
            end
        end
    else
        add_range(tree, f_raw_dtibody, buffer, rboff, rest:len())
    end
end

local function parse_item(tree, buffer, boff, info, overlay_mode)
    -- ) or DTI '"' : NAME9! or NAME9_ position sym overlay
    local body = info:sub(2)
    if body:len() < 11 then tree:add(f_raw_dtibody, info) return end
    add_range(tree, f_item_name, buffer, boff, 9)
    local st = body:sub(10, 10)
    tree:add(f_item_status, st == "!" and "live" or (st == "_" and "killed" or st))
    local rest = body:sub(11)
    local rboff = boff + 10
    local consumed = parse_position(tree, buffer, rboff, rest)
    if consumed then
        if overlay_mode then
            add_range(tree, f_item_overlay, buffer, rboff, 1)
        end
        local after = rest:sub(consumed + 1)
        after = parse_comment_extras(tree, after)
        if after:len() > 0 then
            add_range(tree, f_comment, buffer, rboff + consumed, after:len())
        end
    else
        add_range(tree, f_raw_dtibody, buffer, rboff, rest:len())
    end
end

local function parse_mice(tree, buffer, boff, info, dstcall)
    local dti = info:sub(1, 1)
    local body = info:sub(2)
    -- 9 position/cse/spd chars + 2 symbol chars (code first, then table/overlay)
    if body:len() < 11 then tree:add(f_raw_dtibody, info) return end
    local deg = body:byte(1) - 28
    if deg >= 180 and deg <= 189 then deg = deg - 80
    elseif deg >= 190 and deg <= 199 then deg = deg - 190 end
    local min = body:byte(2) - 28
    if min >= 60 then min = min - 60 end
    local hund = body:byte(3) - 28
    local spd = ((body:byte(4) - 28) * 10) + math.floor((body:byte(5) - 28) / 10)
    if spd >= 800 then spd = spd - 800 end
    local cse = ((body:byte(5) - 28) % 10) * 100 + (body:byte(6) - 28)
    if cse >= 400 then cse = cse - 400 end
    -- seconds field: byte 7 encodes lat seconds + long offset + E/W
    local secs = body:byte(7) - 28
    local sym_code = body:sub(8, 8)
    local sym_table = body:sub(9, 9)
    tree:add(f_speed, spd)
    if cse ~= 0 then tree:add(f_course, cse) end
    add_range(tree, f_symbol_code, buffer, boff + 7, 1)
    add_range(tree, f_symbol_table, buffer, boff + 8, 1)
    mice_decode_dst(tree, dstcall)
    local text = body:sub(11)
    local rboff = boff + 10
    -- optional NNNN} altitude
    local alt4 = text:match("^(%d%d%d%d)}")
    if alt4 then
        add_range(tree, f_mice_alt, buffer, rboff, 5)
        text = text:sub(6); rboff = rboff + 5
    end
    -- optional FFF.FFFMHz frequency (must be first text)
    if text:match("^%d%d?%d?%d%.%d%dMHz") then
        add_range(tree, f_freq, buffer, rboff, 10)
        text = text:sub(11)
    end
    -- manufacturer type+version bytes for ' and ` DTI: last two chars after a space
    if (dti == "'" or dti == "`") and text:len() >= 2 and text:sub(-3, -2) == " M" then
        -- heuristic per mic-e-types.txt: trailing " Xv" where X = MFR byte
    end
    if (dti == "'" or dti == "`") and text:len() >= 3 then
        local tail2 = text:sub(-2)
        if tail2:match("^[%l%u]$") == nil and tail2:match("^[]%-%+/%*%!%#%?>]%d$") then
            tree:add(f_mice_mfr_type, tail2:sub(1, 1))
            tree:add(f_mice_mfr_version, tail2:sub(2, 2))
            text = text:sub(1, -3)
        end
    end
    if text:match("^/%.") or text:sub(1, 2) == "]1" then
        -- D7-style type byte
    end
    if text:match("^[%/]%]") then
        add_range(tree, f_mice_telemetry, buffer, rboff, text:len())
    else
        add_range(tree, f_mice_status, buffer, rboff, text:len())
    end
end

local function parse_telemetry(tree, buffer, boff, info)
    -- info after DTI 'T'
    local seq = info:sub(2, 2)
    if seq ~= "#" then
        add_range(tree, f_raw_dtibody, buffer, boff, info:len())
        return
    end
    local body = info:sub(3)
    local sq = body:match("^(%w+%w*)")
    if sq then
        add_range(tree, f_telem_seq, buffer, boff + 2, sq:len())
        body = body:sub(sq:len() + 1)
    end
    if body:sub(1, 1) == "=" then
        local vals = body:match("^=[%d%.]+/[%d%.%/]+") or body:match("^=.-/%.") or "="
        add_range(tree, f_telem_analog, buffer, boff + 2 + (sq and sq:len() or 0), vals:len())
    elseif body:sub(1, 1) == "!" then
        add_range(tree, f_telem_bits, buffer, boff + 2 + (sq and sq:len() or 0),
            (body:match("^!%d%d?%d?!") or "!") :len())
    elseif body:sub(1, 1) == "^" then
        add_range(tree, f_telem_bits, buffer, boff + 2 + (sq and sq:len() or 0),
            (body:match("^^%d%d?%d?^") or "^"):len())
    elseif sq and sq:match("^L") or (sq and sq:sub(1, 1) == "B") then
        add_range(tree, f_telem_labels, buffer, boff + 2, body:len() + (sq and 0 or 0))
    elseif body:len() > 0 then
        add_range(tree, f_raw_dtibody, buffer, boff + 2, body:len())
    end
end

parse_info = function(tree, buffer, boff, info, dstcall)
    local dti = info:sub(1, 1)
    local dti_byte = info:byte(1)
    add_range(tree, f_info_field_raw, buffer, boff, info:len())
    add_range(tree, f_info_field_type_char, buffer, boff, 1)
    tree:add(f_info_field_type_decoded, info_field_type_map[dti] or "Unknown/Other")

    if dti == ":" then
        parse_message(tree, info)
    elseif dti == ">" then
        local t = info:sub(2)
        local ts = t:match("^%d%d%d%d%d%d[z/h]")
        if ts then
            add_range(tree, f_timestamp, buffer, boff + 1, 7)
            add_range(tree, f_status_text, buffer, boff + 8, t:len() - 7)
        else
            add_range(tree, f_status_text, buffer, boff + 1, t:len())
        end
        local t2 = t:match("^%d%d%d%d%d%d[z/h]") and t:sub(8) or t
        parse_comment_extras(tree, t2)
    elseif dti == "!" or dti == "=" or dti == "/" or dti == "@" then
        local body = info:sub(2)
        if body:sub(1, 1) == "!" then
            -- Ultimeter 2000 weather station
            add_range(tree, f_raw_dtibody, buffer, boff + 1, body:len())
            return
        end
        local consumed = parse_position(tree, buffer, boff + 1, body, nil)
        if consumed then
            local after = body:sub(consumed + 1)
            if body:sub(consumed, consumed) == "_" then
                parse_weather(tree, buffer, boff + 1 + consumed, after)
            else
                local remainder = parse_comment_extras(tree, after)
                if remainder:len() > 0 then
                    add_range(tree, f_comment, buffer, boff + 1 + consumed, remainder:len())
                end
            end
        else
            add_range(tree, f_raw_dtibody, buffer, boff + 1, body:len())
        end
    elseif dti == "_" then
        parse_weather(tree, buffer, boff + 1, info:sub(2))
    elseif dti == ";" then
        parse_object(tree, buffer, boff + 1, info)
    elseif dti == ")" then
        parse_item(tree, buffer, boff + 1, info, true)
    elseif dti == '"' then
        parse_item(tree, buffer, boff + 1, info, true)
    elseif dti == "`" or dti == "'" or dti_byte == 0x1c or dti_byte == 0x1d then
        parse_mice(tree, buffer, boff + 1, info, dstcall)
    elseif dti == "T" then
        parse_telemetry(tree, buffer, boff, info)
    elseif dti == "<" then
        add_range(tree, f_caps_xml, buffer, boff + 1, info:len() - 1)
    elseif dti == "$" then
        add_range(tree, f_nmea, buffer, boff + 1, info:len() - 1)
    elseif dti == "?" then
        add_range(tree, f_query, buffer, boff + 1, info:len() - 1)
    elseif dti == "}" then
        -- third-party: path until next ':' then full info field again
        local body = info:sub(2)
        local colon = body:find(":")
        if colon then
            add_range(tree, f_3rdparty_path, buffer, boff + 1, colon - 1)
            local inner = body:sub(colon + 1)
            local inner_dst = body:match("^([^,]+)")
            parse_info(tree:add("aprsis.third_party.inner", "Inner APRS Packet"),
                buffer, boff + 1 + colon, inner, inner_dst and inner_dst:gsub("%-%d+$", ""))
        else
            add_range(tree, f_raw_dtibody, buffer, boff + 1, body:len())
        end
    elseif dti == "," or dti == "-" then
        -- positionless course/speed
        local cse = tonumber(info:sub(2, 4))
        local spd = tonumber(info:sub(6, 8))
        if cse then tree:add(f_course, cse) end
        if spd then tree:add(f_speed, spd) end
        if info:len() > 8 then
            local c = parse_comment_extras(tree, info:sub(9))
            if c:len() > 0 then add_range(tree, f_comment, buffer, boff + 8, c:len()) end
        end
    else
        add_range(tree, f_raw_dtibody, buffer, boff + 1, info:len() - 1)
    end
end

---------------------------------------------------------------------------
-- Path / address parsing
---------------------------------------------------------------------------
local function parse_header_and_path(packet_tree, line, boff, buffer)
    local gt = line:find(">")
    -- Trouver le premier '>' pour séparer la source de la destination/chemin/info
    if not gt then
        packet_tree:add_proto_expert_info(f_expert_malformed, "warn", "Missing '>' separator")
        packet_tree:add(f_raw_dtibody, line)
        return nil, nil
    end
    local source = line:sub(1, gt - 1)
    local src_call, src_ssid = source:match("^([%w]+)%-?(%d*)$")
    packet_tree:add(f_source, source)
    if src_ssid and src_ssid ~= "" then packet_tree:add(f_src_ssid, src_ssid) end

    local rest = line:sub(gt + 1)
    -- Trouver le premier ':' pour séparer la destination/chemin du champ d'information
    local colon = rest:find(":")
    local dst_path_part = colon and rest:sub(1, colon - 1) or rest
    local dpp_boff = boff + gt

    -- Analyser la destination et le chemin
    local path_parts = {}
    for part in dst_path_part:gmatch("[^,]+") do table.insert(path_parts, part) end
    if #path_parts == 0 then return rest, nil end

    -- La première partie est le callsign de destination
    local dst = path_parts[1]
    local dst_call, dst_ssid = dst:match("^([%w]+)%-?(%d*)$")
    packet_tree:add(f_dstcallsign, dst)
    if dst_ssid and dst_ssid ~= "" then packet_tree:add(f_dstcallsign_ssid, dst_ssid) end

    if #path_parts > 1 then
        local digi_elements = {}
        local q_code_index = nil
        -- Itérer à partir du deuxième élément (après le callsign de destination)
        for i = 2, #path_parts do
            local part = path_parts[i]
            -- Vérifier si c'est un code q-construct
            if part:match("^q[%a][%a]$") then
                q_code_index = i
                break
            end
            table.insert(digi_elements, { call = part, direct = part:sub(-1) == "*" })
        end
        if #digi_elements > 0 then
            packet_tree:add(f_digipeater_path_raw, table.concat(
                (function() local t = {} for _, d in ipairs(digi_elements) do t[#t + 1] = d.call end return t end)(), ","))
            local digi_subtree = packet_tree:add("aprsis.digipeaters", "Digipeaters")
            for _, d in ipairs(digi_elements) do
                local ds = digi_subtree:add(f_digipeater_callsign, d.call)
                ds:add(f_digipeater_direct, d.direct)
            end
        end
        -- Ajouter le q-construct si trouvé
        if q_code_index then
            local q_subtree = packet_tree:add("aprsis.q_construct", "Q-Construct Information")
            local q_code = path_parts[q_code_index]
            q_subtree:add(f_q_construct_code, q_code)
            q_subtree:add(f_q_construct_description, q_construct_map[q_code] or "Unknown Q-Construct")
            if q_code_index + 1 <= #path_parts then
                q_subtree:add(f_q_construct_callsign, path_parts[q_code_index + 1])
            else
                q_subtree:add(f_q_construct_description, "Unknown Q-Construct (Missing Callsign)")
            end
        end
    end
    if colon then
        return rest, colon
    end
    return rest, nil
end

---------------------------------------------------------------------------
-- Main dissector with TCP line reassembly
---------------------------------------------------------------------------
function aprsis_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    pinfo.cols.protocol = "APRS-IS"

    -- Raw, byte-exact string of the payload. NOTE: Tvbuff:string() UTF-8
    -- sanitizes (invalid bytes become U+FFFD, 3 bytes), which shifts every
    -- byte offset after an invalid byte and corrupts field ranges. Decoding
    -- the hex dump gives the exact bytes.
    local hex = buffer:range(0, length):bytes():tohex()
    local data = (hex:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))
    local nlines = 0

    -- Desegmentation: if the segment ends mid-line, ask TCP for one more
    -- segment and only dissect through the last complete CRLF.
    local deseg_offset = nil
    -- Les flux APRS-IS peuvent contenir plusieurs paquets par segment TCP,
    -- séparés par '\r\n'. Les lignes de commentaire APRS-IS commencent par '#'.
    local last_crlf = nil
    local i = 1
    while true do
        local nxt = data:find("\r\n", i, true)
        if not nxt then break end
        last_crlf = nxt
        i = nxt + 2
    end
    if last_crlf and last_crlf + 2 <= length then
        -- trailing partial line exists
        deseg_offset = last_crlf + 2 - 1  -- 0-based offset into TCP payload
    elseif not last_crlf then
        if length < 65535 then
            pinfo.desegment_offset = 0
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
        -- huge unterminated blob: dissect what we have as one line
        last_crlf = nil
    end

    local subtree = tree:add(aprsis_proto, buffer(), "APRS-IS" ..
        (last_crlf and (" (" .. select(2, data:gsub("\r\n", "")) .. " lines)") or ""))

    local first_summary = nil
    local line_start = 0
    local scan_end = deseg_offset and deseg_offset or length
    local sdata = data:sub(1, scan_end)
    -- Only append a synthetic CRLF when sdata doesn't already end with one.
    local scan = (sdata:sub(-2) == "\r\n") and sdata or (sdata .. "\r\n")
    for line in scan:gmatch("([^\r]*)\r\n") do
        local line_boff = line_start
        line_start = line_start + line:len() + 2
        if line:len() == 0 then
            subtree:add("aprsis.heartbeat", "APRS-IS Heartbeat (keep-alive)")
            nlines = nlines + 1
        elseif line:sub(1, 1) == "#" then
            local ct = subtree:add("aprsis.server", "APRS-IS Server: " .. line)
            ct:add(f_server_line, line)
            local sw = line:match("^#%s*(aprsc)%s+(%S+)")
            if sw then
                ct:add(f_server_software, sw .. " " .. select(2, line:match("^#%s*(aprsc)%s+(%S+)")))
            end
            local lr_call, lr_res, lr_srv = line:match("^#%s*logresp%s+(%S+)%s+(verified|unverified),?%s*server%s+(%S+)")
            if lr_call then
                ct:add(f_logresp_call, lr_call)
                ct:add(f_logresp_result, lr_res)
                ct:add(f_logresp_server, lr_srv)
            end
            nlines = nlines + 1
        elseif line:match("^user%s+") then
            local lt = subtree:add("aprsis.login", "APRS-IS Login: " .. line)
            local u, p, opts = line:match("^user%s+(%S+)%s+pass%s+(%-?%d+)%s*(.*)$")
            if u then
                lt:add(f_login_user, u)
                lt:add(f_login_passcode, p)
                if opts and opts:len() > 0 then lt:add(f_login_options, opts) end
            else
                lt:add(f_raw_dtibody, line)
            end
            nlines = nlines + 1
        else
            -- Traiter comme un paquet APRS
            local packet_tree = subtree:add("aprsis.packet", "APRS Packet: " .. line)
            packet_tree:add(f_line_len, line:len())
            local rest, colon = parse_header_and_path(packet_tree, line, line_boff, buffer)
            if colon then
                local info_boff = line_boff + (line:len() - rest:len()) + colon
                local info = rest:sub(colon + 1)
                local dstcall = line:sub(line:find(">") + 1):match("^([^,]+)")
                if dstcall then dstcall = dstcall:match("^(%S+)"):gsub("%-%d+$", "") end
                parse_info(packet_tree, buffer, info_boff, info, dstcall)
                if not first_summary then
                    local src = line:sub(1, line:find(">") - 1)
                    local dti = info:sub(1, 1)
                    first_summary = src .. " " .. (info_field_type_map[dti] or ("type " .. dti))
                end
            else
                packet_tree:add(f_raw_dtibody, line)
                if not first_summary then
                    first_summary = line:sub(1, line:find(">") and (line:find(">") - 1) or 12) .. " (no info field)"
                end
            end
            nlines = nlines + 1
        end
    end

    if nlines > 0 then
        subtree:add(f_msg_count, nlines)
    end
    if first_summary then
        pinfo.cols.info = first_summary .. (nlines > 1 and (" (+" .. (nlines - 1) .. " more)") or "")
    end

    if deseg_offset then
        pinfo.desegment_offset = deseg_offset
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
    end
end

---------------------------------------------------------------------------
-- Registration
---------------------------------------------------------------------------
-- Enregistrement du dissector sur les ports APRS-IS (14580 standard, 10152 client)
local aprsis_port = DissectorTable.get("tcp.port")
aprsis_port:add(10152, aprsis_proto)  -- client-only port
aprsis_port:add(14580, aprsis_proto)  -- standard APRS-IS port
