-- Wireshark dissector for Perception Neuron v1 protocol
-- Can be used with both usb and wifi packets

pneuron = Proto("PNeuron", "Perception Neuron v1 Protocol")

pn_sof = ProtoField.uint8("pneuron.start_of_frame", "Start Of Frame", base.HEX)
pn_type = ProtoField.uint8("pneuron.type", "Type", base.HEX)
pn_id = ProtoField.uint16("pneuron.id", "Transaction id", base.HEX)
pn_key = ProtoField.uint8("pneuron.key", "Key", base.HEX)
pn_len = ProtoField.uint8("pneuron.len", "Length", base.HEX)
pn_data = ProtoField.bytes("pneuron.data", "Data", base.SPACE)
pn_crc = ProtoField.uint8("pneuron.crc8", "Checksum", base.HEX)
pn_eof = ProtoField.uint8("pneuron.end_of_frame", "End Of Frame", base.HEX)

pn_unk = ProtoField.uint16("pneuron.unknown", "Src/Dest?", base.HEX)

pneuron.fields = {
    pn_sof, pn_type, pn_id, pn_unk, pn_key, pn_len, pn_data, pn_crc, pn_eof
}

function parse_01(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_02(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_03(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_04(t, pinfo, root)
    local data_length = t(1,1):uint() - 7
    root:add(pn_key, t(0, 1))
    root:add(pn_len, t(1, 1))
    root:add(pn_data, t(2, data_length-2))
    return t(data_length, -1)
end

function parse_07(t, pinfo, root)
    local data_length = t:len()-2
    root:add(pn_data, t(0, data_length))
    return t(data_length, -1)
end


function parse_09(t, pinfo, root)
    local data_length = 30
    root:add(pn_data, t(0, data_length))
    return t(data_length, -1)
end

function parse_0a(t, pinfo, root)
    local data_length = t(1,1):uint() - 7
    root:add(pn_key, t(0, 1))
    root:add(pn_len, t(1, 1))
    root:add(pn_data, t(2, data_length-2))
    return t(data_length, -1)
end

function parse_header(t, pinfo, subtree)
    subtree:add(pn_sof, t(0,1))
    subtree:add(pn_type, t(1,1))

    type = t(1,1):uint()

    local payload_offset = 2
    if type == 0x07 then
        subtree:add_le(pn_id, t(2,2))
        subtree:add(pn_unk, t(4,2))
        payload_offset = payload_offset + 4
    else
        subtree:add(pn_id, t(2,1))
        subtree:add(pn_unk, t(3,2))
        payload_offset = payload_offset + 3
    end

    return t(payload_offset, -1)
end

function parse_packet(tvbuf, pinfo, root)
    local pktlen = tvbuf:len()

    local rem

    if pktlen > 2 and tvbuf(0,1):uint() == 0xfd then
        pinfo.cols.protocol = pneuron.name

        local subtree = root:add(pneuron, tvbuf(0,pktlen), "Perception Neuron Frame")

        rem = parse_header(tvbuf, pinfo, subtree)

        if type == 0x01 then
            rem = parse_01(rem, pinfo, subtree)
        elseif type == 0x02 then
            rem = parse_02(rem, pinfo, subtree)
        elseif type == 0x03 then
            rem = parse_03(rem, pinfo, subtree)
        elseif type == 0x04 then
            rem = parse_04(rem, pinfo, subtree)
        elseif type == 0x07 then
            rem = parse_07(rem, pinfo, subtree)
        elseif type == 0x09 then
            rem = parse_09(rem, pinfo, subtree)
        elseif type == 0x0a then
            rem = parse_0a(rem, pinfo, subtree)
        end

        subtree:add(pn_crc, rem(0,1))
        subtree:add(pn_eof, rem(1,1))
    end

    if rem:len() > 2 then
        parse_packet(rem(2,-1), pinfo, root)
    end
end

function pneuron.dissector(tvbuf, pinfo, root)

    parse_packet(tvbuf, pinfo, root)

end

function pneuron.init()

    local usb_bulk_dissectors = DissectorTable.get("usb.bulk")
    usb_bulk_dissectors:add(0xFFFF, pneuron)

    local udptab = DissectorTable.get("udp.port")
    udptab:add(7009, pneuron)

end
