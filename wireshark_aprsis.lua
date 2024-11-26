-- Déclaration du protocole
local aprsis_proto = Proto("aprsis", "APRS-IS Protocol")

-- Définition des champs
local f_source = ProtoField.string("aprsis.source", "Source")
local f_dstcallsign = ProtoField.string("aprsis.dstcallsign", "Destination Callsign")
local f_path = ProtoField.string("aprsis.path", "Path")
local f_message = ProtoField.string("aprsis.message", "Message")
local f_destination = ProtoField.string("aprsis.destination", "Destination")

aprsis_proto.fields = { f_source, f_dstcallsign, f_path, f_message, f_destination }

-- Fonction de désassemblage
function aprsis_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = aprsis_proto.name

    local length = buffer:len()
    if length == 0 then return end

    -- Créer un arbre pour le protocole
    local subtree = tree:add(aprsis_proto, buffer(), "APRS-IS Protocol Data")

    -- Extraire les données
    local data = buffer():string()

    -- Séparer les paquets par '\r\n'
    for packet in data:gmatch("([^\r\n]+)") do
        -- Initialisation des champs
        local source, dstcallsign, path, destination, message = "", "", "", "", ""

        -- Trouver le délimiteur '>'
        local greater_than_index = packet:find(">")
        if greater_than_index then
            source = packet:sub(1, greater_than_index - 1)
            local rest = packet:sub(greater_than_index + 1)

            -- Trouver le délimiteur ','
            local comma_index = rest:find(",")
            if comma_index then
                dstcallsign = rest:sub(1, comma_index - 1)
                rest = rest:sub(comma_index + 1)

                -- Trouver le délimiteur ':'
                local colon_index = rest:find(":")
                if colon_index then
                    path = rest:sub(1, colon_index - 1)
                    rest = rest:sub(colon_index + 1)

                    -- Vérifier si le premier caractère est ':'
                    if rest:sub(1, 1) == ":" then
                        destination = rest:sub(2, 10) -- 9 caractères pour la destination
                        message = rest:sub(12) -- Reste du texte après la destination
                    else
                        message = rest -- Pas de destination, tout le reste est le message
                    end
                else
                    message = rest -- Pas de ':' trouvé, tout le reste est le message
                end
            end
        end

        -- Ajouter les champs à l'arbre pour chaque paquet
        local packet_tree = subtree:add(aprsis_proto, packet)
        packet_tree:add(f_source, source)
        packet_tree:add(f_dstcallsign, dstcallsign)
        packet_tree:add(f_path, path)
        packet_tree:add(f_destination, destination)
        packet_tree:add(f_message, message)
    end
end

-- Enregistrement du dissector sur le port APRS-IS (10152)
local aprsis_port = DissectorTable.get("tcp.port")
aprsis_port:add(10152, aprsis_proto)

