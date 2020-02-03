-- Wireshark dissector for Perception Neuron v1 protocol
-- Can be used with both usb and wifi packets

pneuron = Proto("PNeuron", "Perception Neuron v1 Protocol")

local types = {
    [0x01] = "Call",
    [0x02] = "Ack",
    [0x03] = "Value",
    [0x04] = "Data",
    [0x07] = "Firmware Upload",
    [0x09] = "IMU data",
    [0x0a] = "Set",
}

local keys = {
   [0x01] = "Hub Firmware Version?",
   [0x15] = "Hub Serial Number",
   [0x18] = "Wifi Config",
   [0x19] = "Server Config",
   [0x30] = "Wifi Scan",
   [0x71] = "Node Firmware Version?",
   [0x73] = "Node Serial Numbers",
   [0x7c] = "Node Serial Numbers",
}

local nodes = {
    [0xa0] = "Server",
    [0xc0] = "Hub",
}

pn_sof = ProtoField.uint8("pneuron.start_of_frame", "Start Of Frame", base.HEX)
pn_type = ProtoField.uint8("pneuron.type", "Type", base.HEX, types)
pn_id = ProtoField.uint16("pneuron.id", "Transaction id", base.HEX)
pn_key = ProtoField.uint8("pneuron.key", "Key", base.HEX, keys)
pn_len = ProtoField.uint8("pneuron.len", "Length", base.HEX)
pn_data = ProtoField.bytes("pneuron.data", "Data", base.SPACE)
pn_crc = ProtoField.uint8("pneuron.crc8", "Checksum", base.HEX)
pn_eof = ProtoField.uint8("pneuron.end_of_frame", "End Of Frame", base.HEX)
pn_item_len = ProtoField.uint8("pneuron.item_len", "Item Length", base.HEX)
pn_item_num = ProtoField.uint8("pneuron.item_num", "Item Count", base.DEC)

pn_src = ProtoField.uint16("pneuron.src", "Source", base.HEX, nodes)
pn_dst = ProtoField.uint16("pneuron.dst", "Destination", base.HEX, nodes)

-- local type = Field.new("pneuron.key")

pneuron.fields = {
    pn_sof, pn_type, pn_id, pn_src, pn_dst, pn_key, pn_len, pn_data, pn_crc, pn_eof, pn_item_len, pn_item_num
}

function parse_header(t, pinfo, root)
    root:add(pn_sof, t(0,1))
    root:add(pn_type, t(1,1))

    type = t(1,1):uint()

    return t(2, -1)
end

function parse_id_no_dst(t, pinfo, root)
    root:add(pn_id, t(0,1))
    root:add(pn_src, t(1,1))
    return t(2, -1)
end

function parse_id(t, pinfo, root)
    root:add(pn_id, t(0,1))
    root:add(pn_src, t(1,1))
    root:add(pn_dst, t(2,1))
    return t(3, -1)
end

function parse_long_id(t, pinfo, root)
    root:add_le(pn_id, t(0,2))
    root:add(pn_src, t(2,1))
    root:add(pn_dst, t(3,1))
    return t(3, -1)
end

-- 01 03 0d 00 01 00 connect?
-- 01 02 00 00 00 00 disconnect?
-- 01 03 02 00 00 00 returns a 0x71
-- 01 03 07 00 00 00 returns a 0x73
-- 01 00 0b nn 01 01 flash node nn
-- 01 06 04 b0 40 00 Prepare for firmware upload
-- 01 06 04 c0 c4 00 "

function parse_01(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_02(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    -- reuses incoming packet buffer, so some bytes may be junk
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_03(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,4))
    root:add(pn_item_len, t(4,1))
    root:add(pn_item_num, t(5,1))
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

function parse_06(t, pinfo, root)
    t = parse_id(t, pinfo, root)
    root:add(pn_data, t(0,6))
    return t(6,-1)
end

function parse_07(t, pinfo, root)
    t = parse_long_id(t, pinfo, root)
    local data_length = t:len()-2
    root:add(pn_data, t(0, data_length))
    return t(data_length, -1)
end

function parse_09(t, pinfo, root)
    t = parse_id_no_dst(t, pinfo, root)
    local data_length = 31
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
    [0x06] = parse_06,
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
