-- Wireshark dissector for Perception Neuron v1 protocol
-- Can be used with both usb and wifi packets

pneuron = Proto("PNeuron", "Perception Neuron v1 Protocol")

local types = {
    [0x01] = "Request",
    [0x02] = "Response",
    [0x03] = "Value",
    [0x04] = "Data",
    [0x07] = "Firmware Upload",
}

local keys = {
   [0x01] = "Hub Firmware Version?",
   [0x15] = "Hub Serial Number",
   [0x71] = "Node Firmware Version?",
   [0x73] = "Node Serial Numbers",
}

pn_sof = ProtoField.uint8("pneuron.start_of_frame", "Start Of Frame", base.HEX)
pn_type = ProtoField.uint8("pneuron.type", "Type", base.HEX, types)
pn_id = ProtoField.uint16("pneuron.id", "Transaction id", base.HEX)
pn_key = ProtoField.uint8("pneuron.key", "Key", base.HEX, keys)
pn_len = ProtoField.uint8("pneuron.len", "Length", base.HEX)
pn_data = ProtoField.bytes("pneuron.data", "Data", base.SPACE)
pn_crc = ProtoField.uint8("pneuron.crc8", "Checksum", base.HEX)
pn_eof = ProtoField.uint8("pneuron.end_of_frame", "End Of Frame", base.HEX)

pn_unk = ProtoField.uint16("pneuron.unknown", "Src/Dest?", base.HEX)

-- local type = Field.new("pneuron.key")

pneuron.fields = {
    pn_sof, pn_type, pn_id, pn_unk, pn_key, pn_len, pn_data, pn_crc, pn_eof
}

function parse_header(t, pinfo, root)
    root:add(pn_sof, t(0,1))
    root:add(pn_type, t(1,1))

    type = t(1,1):uint()

    return t(2, -1)
end

function parse_id(t, pinfo, root)
    root:add(pn_id, t(0,1))
    root:add(pn_unk, t(1,2))
    return t(3, -1)
end

function parse_long_id(t, pinfo, root)
    root:add_le(pn_id, t(0,2))
    root:add(pn_unk, t(2,2))
    return t(3, -1)
end

function parse_01(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_02(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_03(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_04(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    local data_length = t(1,1):uint() - 7
    local key = t(0, 1)
    root:add(pn_key, key)
    root:add(pn_len, t(1, 1))
    root:add(pn_data, t(2, data_length-2))
    return t(data_length, -1)
end

function parse_07(t, pinfo, root)
    t = parse_long_id(t, pinfo, root)
    local data_length = t:len()-2
    root:add(pn_data, t(0, data_length))
    return t(data_length, -1)
end

function parse_09(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    local data_length = 30
    root:add(pn_data, t(0, data_length))
    return t(data_length, -1)
end

function parse_0a(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    local data_length = t(1,1):uint() - 7
    root:add(pn_key, t(0, 1))
    root:add(pn_len, t(1, 1))
    root:add(pn_data, t(2, data_length-2))
    return t(data_length, -1)
end

local command_table = {
    [0x01] = parse_01,
    [0x02] = parse_02,
    [0x03] = parse_03,
    [0x04] = parse_04,
    [0x07] = parse_07,
    [0x09] = parse_09,
    [0x0a] = parse_0a,
}

function parse_packet(tvbuf, pinfo, root)
    local pktlen = tvbuf:len()

    local t

    if pktlen > 2 and tvbuf(0,1):uint() == 0xfd then
        pinfo.cols.protocol = pneuron.name

        local subtree = root:add(pneuron, tvbuf(0,pktlen), "Perception Neuron Frame")

        t = parse_header(tvbuf, pinfo, subtree)

        t = command_table[type](t, pinfo, subtree)

        subtree:add(pn_crc, t(0,1))
        subtree:add(pn_eof, t(1,1))

        subtree:set_len(t:offset()+2)
    end

    if t and t:len() > 2 then
        parse_packet(t(2,-1), pinfo, root)
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
