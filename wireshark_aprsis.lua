-- Déclaration du protocole
local aprsis_proto = Proto("aprsis", "APRS-IS Protocol")

-- Définition des champs
local f_source = ProtoField.string("aprsis.source", "Source Callsign")
local f_dstcallsign = ProtoField.string("aprsis.destination_callsign", "Destination Callsign")
local f_digipeater_path_raw = ProtoField.string("aprsis.digipeater_path.raw", "Digipeater Path (Raw)")
local f_digipeater_callsign = ProtoField.string("aprsis.digipeater.callsign", "Digipeater Callsign")

-- Champs génériques pour le champ d'information
local f_info_field_raw = ProtoField.string("aprsis.info_field.raw", "Information Field (Raw)")
local f_info_field_type_char = ProtoField.string("aprsis.info_field.type_char", "Information Field Type Character")
local f_info_field_type_decoded = ProtoField.string("aprsis.info_field.type_decoded", "Information Field Type")

-- Champs spécifiques aux messages (type ':')
local f_message_recipient = ProtoField.string("aprsis.message.recipient", "Message Recipient")
local f_message_text = ProtoField.string("aprsis.message.text", "Message Text")
local f_message_id = ProtoField.string("aprsis.message.id", "Message ID")

-- Champs spécifiques aux statuts (type '>')
local f_status_text = ProtoField.string("aprsis.status.text", "Status Text")

-- Champs spécifiques aux rapports de position (types '!', '=', '/', '@')
local f_latitude = ProtoField.string("aprsis.position.latitude", "Latitude")
local f_longitude = ProtoField.string("aprsis.position.longitude", "Longitude")
local f_symbol_table = ProtoField.string("aprsis.position.symbol_table", "Symbol Table")
local f_symbol_code = ProtoField.string("aprsis.position.symbol_code", "Symbol Code")
local f_timestamp = ProtoField.string("aprsis.position.timestamp", "Timestamp")
local f_course = ProtoField.uint16("aprsis.position.course", "Course (deg)")
local f_speed = ProtoField.uint16("aprsis.position.speed", "Speed (knots)")
local f_altitude = ProtoField.int32("aprsis.position.altitude", "Altitude (feet)")
local f_comment = ProtoField.string("aprsis.position.comment", "Comment")

-- Champs spécifiques aux rapports météo (type '_')
local f_wind_direction = ProtoField.uint16("aprsis.weather.wind_direction", "Wind Direction (deg)")
local f_wind_speed = ProtoField.uint16("aprsis.weather.wind_speed", "Wind Speed (knots)")
local f_temperature = ProtoField.int16("aprsis.weather.temperature", "Temperature (C)")
local f_humidity = ProtoField.uint8("aprsis.weather.humidity", "Humidity (%)")
local f_pressure = ProtoField.uint16("aprsis.weather.pressure", "Barometric Pressure (hPa)")
local f_rainfall_1h = ProtoField.float("aprsis.weather.rainfall_1h", "Rainfall 1h (mm)")
local f_rainfall_24h = ProtoField.float("aprsis.weather.rainfall_24h", "Rainfall 24h (mm)")
local f_rainfall_midnight = ProtoField.float("aprsis.weather.rainfall_midnight", "Rainfall since Midnight (mm)")
local f_luminosity = ProtoField.uint16("aprsis.weather.luminosity", "Luminosity (W/m^2)")
local f_weather_comment = ProtoField.string("aprsis.weather.comment", "Weather Comment")

-- Nouveaux champs pour le q-construct
local f_q_construct_code = ProtoField.string("aprsis.q_construct.code", "Q-Construct Code")
local f_q_construct_description = ProtoField.string("aprsis.q_construct.description", "Q-Construct Description")
local f_q_construct_callsign = ProtoField.string("aprsis.q_construct.callsign", "Q-Construct Callsign/Server")


aprsis_proto.fields = {
    f_source, f_dstcallsign, f_digipeater_path_raw, f_digipeater_callsign,
    f_info_field_raw, f_info_field_type_char, f_info_field_type_decoded,
    f_message_recipient, f_message_text, f_message_id,
    f_status_text,
    f_latitude, f_longitude, f_symbol_table, f_symbol_code, f_timestamp, f_course, f_speed, f_altitude, f_comment,
    f_wind_direction, f_wind_speed, f_temperature, f_humidity, f_pressure,
    f_rainfall_1h, f_rainfall_24h, f_rainfall_midnight, f_luminosity, f_weather_comment,
    f_q_construct_code, f_q_construct_description, f_q_construct_callsign
}

-- Table de correspondance pour les types de champs d'information APRS
local info_field_type_map = {
    [":"] = "Message",
    [">"] = "Status",
    ["!"] = "Position (no timestamp)",
    ["="] = "Position (no timestamp, compressed)",
    ["/"] = "Position (with timestamp)",
    ["@"] = "Position (with timestamp, compressed)",
    ["_"] = "Weather Report",
    ["#"] = "Mic-E (compressed position)",
    [";"] = "Object Report",
    ["T"] = "Telemetry Data",
    ["`"] = "Current Mic-E Data",
    ["'"] = "Maidenhead Locator",
    ["$"] = "NMEA Sentence",
    ["("] = "Item Report",
    [")"] = "Item Report", -- Same as (
    ["*"] = "Station Capabilities",
    ["%"] = "Position (DF)",
    ["{"] = "User-Defined",
    ["}"] = "Third-Party Software",
    ["["] = "DF Report",
    ["?"] = "Query",
    ["|"] = "Current Mic-E Data (old format)",
    ["^"] = "User-Defined",
    ["~"] = "User-Defined",
    ["+"] = "User-Defined",
    ["\\"] = "User-Defined"
}

-- Q-construct lookup table (descriptions combinées pour les codes ambigus)
local q_construct_map_combined = {
    ["qAC"] = "Server: Verified login via bidirectional port.",
    ["qAX"] = "Server: Unverified login (deprecated).",
    ["qAU"] = "Server: Direct via UDP.",
    ["qAo"] = "Server: Gated via client-only port.",
    ["qAO"] = "Gated from RF without messaging (Client) / Non-gated via send-only port or indirect via client-only port (Server).",
    ["qAS"] = "Server: Packet via server without q construct.",
    ["qAr"] = "Server: Gated using ,I construct from remote IGate.",
    ["qAR"] = "Gated from RF (Client) / Gated using ,I construct with verified IGate login (Server).",
    ["qAZ"] = "Client/Server: Command packet (not propagated).",
    ["qAI"] = "Client: Trace packet."
}


--- Fonction d'aide pour analyser les données de position (types '!', '=', '/', '@')
-- @param packet_tree L'arbre Wireshark où ajouter les champs.
-- @param info_field_raw Le champ d'information brut (incluant le caractère de type).
local function parse_position_data(packet_tree, info_field_raw)
    -- Cette fonction tente d'analyser les formats non compressés les plus courants.
    -- Cf APRS 1.01, Section 9 pour tous les détails.

    local data_to_parse = info_field_raw

    -- Tenter d'analyser l'horodatage (DDHHMMz, DDHHMMh, DDHHMM/)
    local timestamp_match = data_to_parse:match("^(%d%d%d%d%d%d[z/h])")
    if timestamp_match then
        packet_tree:add(f_timestamp, timestamp_match)
        data_to_parse = data_to_parse:sub(#timestamp_match + 1) -- Supprimer la partie horodatage
    end

    -- Analyser la Latitude, Longitude, Table de Symboles, Code de Symbole et Commentaire
    -- Format courant : DDMM.HHN/DDDMM.HHEsComment
    -- Ou : DDMM.HHN\DDDMM.HHEsComment
    local lat_lon_pattern = "^(%d%d%d%d%.%d%d[NnSs])([%/%'\\])(%d%d%d%d%d%.%d%d[EeWw])(.*)"
    local lat_lon_match = data_to_parse:match(lat_lon_pattern)

    if lat_lon_match then
        packet_tree:add(f_latitude, lat_lon_match[1])
        packet_tree:add(f_symbol_table, lat_lon_match[2])
        packet_tree:add(f_longitude, lat_lon_match[3])

        local symbol_code_and_comment = lat_lon_match[4]
        if #symbol_code_and_comment > 0 then
            packet_tree:add(f_symbol_code, symbol_code_and_comment:sub(1,1))
            local comment_part = symbol_code_and_comment:sub(2)

            -- Tenter d'analyser le Cap/Vitesse/Altitude du commentaire (ex: /CRS/SPD/ALT)
            -- Ou PHG (Power/Height/Gain) et Altitude (ex: PHG0000)
            local sca_pattern = "^(%d%d%d)/(%d%d%d)/(%d%d%d%d%d)(.*)" -- ex: /090/005/00000
            local phg_alt_pattern = "^(PHG%d%d%d%d)(.*)" -- ex: PHG0000
            local alt_pattern = "^(%d%d%d%d%d)(.*)" -- ex: 00000 (altitude seule)

            local sca_match = comment_part:match(sca_pattern)
            local phg_alt_match = comment_part:match(phg_alt_pattern)
            local alt_match = comment_part:match(alt_pattern)

            if sca_match then
                packet_tree:add(f_course, tonumber(sca_match[1]))
                packet_tree:add(f_speed, tonumber(sca_match[2]))
                packet_tree:add(f_altitude, tonumber(sca_match[3]))
                packet_tree:add(f_comment, sca_match[4])
            elseif phg_alt_match then
                -- Le dissector actuel ne sépare pas PHG de l'altitude, on le met dans le commentaire.
                packet_tree:add(f_altitude, tonumber(phg_alt_match[1]:sub(4)))
                packet_tree:add(f_comment, phg_alt_match[2])
            elseif alt_match then
                packet_tree:add(f_altitude, tonumber(alt_match[1]))
                packet_tree:add(f_comment, alt_match[2])
            else
                packet_tree:add(f_comment, comment_part)
            end
        end
    else
        -- Si le motif ci-dessus ne correspond pas, il peut s'agir d'un autre format ou d'un paquet malformé.
        -- Pour l'instant, ajouter les données restantes comme un commentaire générique.
        packet_tree:add(f_comment, data_to_parse)
    end
end

--- Fonction d'aide pour analyser les données météo (type '_')
-- @param packet_tree L'arbre Wireshark où ajouter les champs.
-- @param info_field_raw Le champ d'information brut (incluant le caractère de type).
local function parse_weather_data(packet_tree, info_field_raw)

    local function add_param_if_found(data_str, param_char, field_obj, is_float)
        local pattern = param_char .. "([%-?%d%.]+)"
        local value_str = data_str:match(pattern)
        if value_str then
            local value = is_float and tonumber(value_str) or tonumber(value_str)
            if value then
                packet_tree:add(field_obj, value)
            end
        end
    end

    -- Tenter d'extraire les paramètres météo courants
    add_param_if_found(info_field_raw, "c", f_wind_direction)
    add_param_if_found(info_field_raw, "s", f_wind_speed)
    add_param_if_found(info_field_raw, "t", f_temperature)
    add_param_if_found(info_field_raw, "r", f_rainfall_1h, true)
    add_param_if_found(info_field_raw, "p", f_rainfall_24h, true)
    add_param_if_found(info_field_raw, "P", f_rainfall_midnight, true)
    add_param_if_found(info_field_raw, "h", f_humidity)
    add_param_if_found(info_field_raw, "b", f_pressure)
    add_param_if_found(info_field_raw, "L", f_luminosity)
    -- La profondeur de neige ('S') est moins courante, et 's' est ambigu.

    -- Le reste de la chaîne brute est ajouté comme commentaire météo.
    packet_tree:add(f_weather_comment, info_field_raw)
end


-- Fonction de désassemblage principale
function aprsis_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = aprsis_proto.name

    local length = buffer:len()
    if length == 0 then return end

    -- Créer un arbre pour le protocole
    local subtree = tree:add(aprsis_proto, buffer(), "APRS-IS Protocol Data")

    -- Extraire les données sous forme de chaîne
    -- Attention : buffer():string() (et buffer:string()) « sanitise » l'UTF-8 :
    -- chaque octet invalide est remplacé par U+FFFD (3 octets), ce qui
    -- décale tous les offsets au-delà du premier octet non-UTF-8 (fréquent
    -- dans les commentaires APRS : degré, flèches, accents en Latin-1).
    -- Les buffer:range(current_offset, ...) héritent alors de lengths fausses
    -- et Wireshark lève « Range is out of bounds »
    -- Le décodage hexadécimal ci-dessous rend les octets exacts.
    local hex = buffer:range(0, length):bytes():tohex()
    local data = (hex:gsub("%x%x", function(cc) return string.char(tonumber(cc, 16)) end))

    -- Les flux APRS-IS peuvent contenir plusieurs paquets par segment TCP, séparés par '\r\n'.
    -- Les lignes de commentaire APRS-IS commencent par '#'.
    local current_offset = 0
    local start_pos = 1

    while start_pos <= #data do
        local end_pos = data:find("\r\n", start_pos)
        local line_content
        local line_full_len

        if end_pos then
            line_content = data:sub(start_pos, end_pos - 1)
            line_full_len = (end_pos - start_pos) + #"\r\n"
        else
            -- C'est la dernière ligne et elle ne se termine pas par \r\n
            line_content = data:sub(start_pos)
            line_full_len = #data - start_pos + 1
        end

        if #line_content == 0 then
            -- Ligne vide, passer à la suivante
            current_offset = current_offset + line_full_len
            start_pos = start_pos + line_full_len
            goto continue_loop
        end

        if line_content:sub(1,1) == '#' then
            -- C'est une ligne de commentaire APRS-IS, l'ignorer pour le parsing des paquets
            local comment_tree = subtree:add(aprsis_proto, buffer:range(current_offset, #line_content), "APRS-IS Comment: " .. line_content)
            comment_tree:set_text("APRS-IS Comment: " .. line_content)
        else
            -- Traiter comme un paquet APRS
            local packet_tree = subtree:add(aprsis_proto, buffer:range(current_offset, #line_content), "APRS Packet: " .. line_content)

            -- Trouver le premier '>' pour séparer la source de la destination/chemin/info
            local greater_than_index = line_content:find(">")
            if greater_than_index then
                local source = line_content:sub(1, greater_than_index - 1)
                packet_tree:add(f_source, source)

                local rest_of_packet = line_content:sub(greater_than_index + 1)

                -- Trouver le premier ':' pour séparer la destination/chemin du champ d'information
                local colon_index = rest_of_packet:find(":")
                if colon_index then
                    local dst_path_part = rest_of_packet:sub(1, colon_index - 1)
                    local info_field_raw = rest_of_packet:sub(colon_index + 1)

                    packet_tree:add(f_info_field_raw, info_field_raw)

                    -- Analyser la destination et le chemin
                    local path_parts = {}
                    for part in dst_path_part:gmatch("([^,]+)") do
                        table.insert(path_parts, part)
                    end

                    if #path_parts > 0 then
                        packet_tree:add(f_dstcallsign, path_parts[1]) -- La première partie est le callsign de destination

                        local digipeater_elements = {}
                        local q_code_index = -1
                        local q_callsign_index = -1

                        -- Itérer à partir du deuxième élément (après le callsign de destination)
                        for i = 2, #path_parts do
                            local part = path_parts[i]
                            if part:match("^q[A-Z][A-Z]$") then -- Vérifier si c'est un code q-construct
                                q_code_index = i
                                -- Le prochain élément devrait être le callsign associé
                                if (i + 1) <= #path_parts then
                                    q_callsign_index = i + 1
                                end
                                break -- q-construct trouvé, arrêter d'ajouter des digipeaters normaux
                            end
                            table.insert(digipeater_elements, part)
                        end

                        -- Ajouter les digipeaters normaux
                        if #digipeater_elements > 0 then
                            packet_tree:add(f_digipeater_path_raw, table.concat(digipeater_elements, ","))
                            local digi_subtree = packet_tree:add("aprsis.digipeaters", "Digipeaters")
                            for _, digi in ipairs(digipeater_elements) do
                                digi_subtree:add(f_digipeater_callsign, digi)
                            end
                        end

                        -- Ajouter le q-construct si trouvé
                        if q_code_index ~= -1 and q_callsign_index ~= -1 then
                            local q_subtree = packet_tree:add("aprsis.q_construct", "Q-Construct Information")
                            local q_code = path_parts[q_code_index]
                            q_subtree:add(f_q_construct_code, q_code)
                            q_subtree:add(f_q_construct_description, q_construct_map_combined[q_code] or "Unknown Q-Construct")
                            q_subtree:add(f_q_construct_callsign, path_parts[q_callsign_index])
                        elseif q_code_index ~= -1 then -- q-code sans callsign suivant (malformé)
                            local q_subtree = packet_tree:add("aprsis.q_construct", "Q-Construct Information (Malformed)")
                            local q_code = path_parts[q_code_index]
                            q_subtree:add(f_q_construct_code, q_code)
                            q_subtree:add(f_q_construct_description, (q_construct_map_combined[q_code] or "Unknown Q-Construct") .. " (Missing Callsign)")
                        end

                    end

                    -- Analyser le champ d'information en fonction de son caractère de type
                    local info_field_type_char = ""
                    if #info_field_raw > 0 then
                        info_field_type_char = info_field_raw:sub(1, 1)
                    end

                    packet_tree:add(f_info_field_type_char, info_field_type_char)
                    packet_tree:add(f_info_field_type_decoded, info_field_type_map[info_field_type_char] or "Unknown/Other")


                    if info_field_type_char == ":" then -- Message
                        -- Format: :recipient:message_text{id}
                        local first_colon_after_type = info_field_raw:find(":", 2) -- Chercher le 2ème ':'
                        if first_colon_after_type then
                            local recipient = info_field_raw:sub(2, first_colon_after_type - 1)
                            local message_text_with_id = info_field_raw:sub(first_colon_after_type + 1)
                            packet_tree:add(f_message_recipient, recipient)

                            local id_start = message_text_with_id:find("{")
                            if id_start then
                                packet_tree:add(f_message_text, message_text_with_id:sub(1, id_start - 1))
                                packet_tree:add(f_message_id, message_text_with_id:sub(id_start + 1, -2)) -- Supprimer le '}' final
                            else
                                packet_tree:add(f_message_text, message_text_with_id)
                            end
                        else
                            -- Pas de destinataire de message explicite, tout est le message
                            packet_tree:add(f_message_text, info_field_raw:sub(2))
                        end
                    elseif info_field_type_char == ">" then -- Statut
                        packet_tree:add(f_status_text, info_field_raw:sub(2))
                    elseif info_field_type_char == "!" or info_field_type_char == "=" or
                           info_field_type_char == "/" or info_field_type_char == "@" then -- Rapport de position
                        parse_position_data(packet_tree, info_field_raw)
                    elseif info_field_type_char == "_" then -- Rapport météo
                        parse_weather_data(packet_tree, info_field_raw)
                    -- Ajoutez d'autres types ici si nécessaire (ex: ';': Object Report, 'T': Telemetry, etc.)
                    else
                        -- Type de champ d'information non reconnu ou non analysé, ajouter les données brutes comme message générique
                        packet_tree:add(f_message_text, info_field_raw)
                    end

                else
                    -- Pas de champ d'information (pas de deux-points après la destination/chemin)
                    -- C'est généralement une erreur ou un paquet très court.
                    -- Traiter le reste comme destination/chemin et potentiellement un court message.
                    local dst_path_part = rest_of_packet
                    local path_parts = {}
                    for part in dst_path_part:gmatch("([^,]+)") do
                        table.insert(path_parts, part)
                    end
                    if #path_parts > 0 then
                        packet_tree:add(f_dstcallsign, path_parts[1])
                        -- Pas de q-construct possible ici car il n'y a pas de champ d'information
                        if #path_parts > 1 then
                            local path_str = table.concat(path_parts, ",", 2)
                            packet_tree:add(f_digipeater_path_raw, path_str)
                            local digi_subtree = packet_tree:add("aprsis.digipeaters", "Digipeaters")
                            for i = 2, #path_parts do
                                digi_subtree:add(f_digipeater_callsign, path_parts[i])
                            end
                        end
                    end
                    packet_tree:add(f_message_text, "No information field (missing colon)")
                end
            else
                -- Pas de '>' trouvé, paquet malformé
                packet_tree:add(f_message_text, "Malformed packet (missing '>')")
            end
        end
        current_offset = current_offset + line_full_len
        start_pos = start_pos + line_full_len
        ::continue_loop:: -- Label pour le goto
    end
end

-- Enregistrement du dissector sur le port APRS-IS (10152)
local aprsis_port = DissectorTable.get("tcp.port")
aprsis_port:add(10152, aprsis_proto)
