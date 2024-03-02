-- otherland.lua - A protocol dissector for otherland RakNet messages
-- Copyright (C) 2024  Phil Lehmkuhl
-- 
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

local otherland_raknet = Proto("otherland.raknet", "Otherland Raknet")
local remote_time_field = ProtoField.uint32("otherland.raknet.remote_ime", "Remote Time", base.DEC)
local ack_packet_field = ProtoField.uint32("otherland.raknet.ack", "Ack", base.DEC)
local packet_no_field = ProtoField.uint32("otherland.raknet.messageNo", "Message No.", base.DEC)
local reliability_field = ProtoField.uint8("otherland.raknet.reliability", "Reliability", base.DEC)
local channel_field = ProtoField.uint8("otherland.raknet.reliability.channel", "Channel", base.DEC)
local index_field = ProtoField.uint32("otherland.raknet.reliability.index", "Index", base.DEC)
local split_id_field = ProtoField.uint16("otherland.raknet.split.id", "Split Id", base.DEC)
local split_index_field = ProtoField.uint32("otherland.raknet.split.index", "Split Index", base.DEC)
local split_count_field = ProtoField.uint32("otherland.raknet.split.count", "Split Count", base.DEC)
local payload = ProtoField.none("otherland.raknet.payload", "Payload")

otherland_raknet.fields = {
    remote_time_field,
    ack_packet_field,
    packet_no_field,
    reliability_field,
    channel_field,
    index_field,
    split_id_field,
    split_index_field,
    split_count_field,
    payload
}

local function read_bits_as_buffer(buffer, offset, len)
    local result = ByteArray.new()
    local bytes = math.ceil((offset % 8 + len) / 8)
    local result_bytes = math.ceil(len / 8);
    local start_offset = offset % 8;
    result:set_size(result_bytes)

    local byte_start = math.floor(offset / 8)
    local range = buffer(byte_start, bytes);

    for i = 0, result_bytes - 1 do
        local read_len = math.min(len, 8);

        local value = range:bitfield(start_offset, read_len)
        result:set_index(i, value)

        len = len - read_len
        start_offset = start_offset + read_len
        offset = offset + read_len
    end

    return offset, result
end

local function read_bits(buffer, offset, len)
    local byte_start = math.floor(offset / 8)
    local byte_end = math.floor((offset + len) / 8)
    local value = buffer(byte_start, byte_end - byte_start + 1):bitfield(offset % 8, len)

    return (offset + len), value
end

local function parse_compressed_bytes(buffer, offset, count, unsigned)
    local result = ByteArray.new()
    result:set_size(count)

    local byte_match, nibble_match
    if unsigned then
        byte_match = 0
        nibble_match = 0
    else
        byte_match = 0xFF
        nibble_match = 0xF0
    end

    -- Read upper bytes
    local upper_bytes = count - 1
    for b = 0, upper_bytes - 1 do
        local is_compressed
        offset, is_compressed = read_bits(buffer, offset, 1)

        if is_compressed == 1 then
            result:set_index(upper_bytes - b, byte_match)
        else
            for j = 0, count - b - 1 do
                local uncompressed
                offset, uncompressed = read_bits(buffer, offset, 8)
                result:set_index(j, uncompressed)
            end
            return offset, result
        end
    end

    -- Uncompress first byte, if all upper bytes were compressed (equal to byte_match)
    local is_negative
    local first_byte

    offset, is_negative = read_bits(buffer, offset, 1)
    if is_negative == 1 then
        offset, first_byte = read_bits(buffer, offset, 4)
        result:set_index(0, bit32.bor(nibble_match, first_byte))
    else
        offset, first_byte = read_bits(buffer, offset, 8)
        result:set_index(0, first_byte)
    end

    return offset, result
end

local function get_reliability_description(reliability) 
    if reliability == 0 then return "Unreliable"
    elseif reliability == 1 then return "Unreliable Sequenced"
    elseif reliability == 2 then return "Reliable"
    elseif reliability == 3 then return "Reliable Ordered"
    elseif reliability == 4 then return "Reliable Sequenced"
    else
        return "Unknown"
    end
end

local function read_uint16(byte_array)
    return (byte_array:get_index(1) * 256) + byte_array:get_index(0)
end

local packetformat_dissector

function otherland_raknet.init()
    packetformat_dissector = Dissector.get("otherland.packetformat")
end

function otherland_raknet.dissector(buffer, pinfo, tree)
    print("Dissect")

    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = otherland_raknet.name

    local subtree = tree:add(otherland_raknet, buffer(), "Otherland Raknet")

    local offset = 0
    local bits = buffer:len() * 8
    local remote_time

    local offset, has_acks = read_bits(buffer, offset, 1)
    if has_acks == 1 then
        local ackSubtree = subtree:add(otherland_raknet, buffer(), "Acks")

        offset, remote_time = read_bits_as_buffer(buffer, offset, 32)
        ackSubtree:add(remote_time_field, remote_time:le_uint())

        local ack_count
        offset, ack_count = parse_compressed_bytes(buffer, offset, 2, true)
        for i = 0, ack_count:le_uint(0, 2) - 1 do
            local min_ack, max_ack, max_equals_min
            offset, max_equals_min = read_bits(buffer, offset, 1)
            offset, min_ack = read_bits_as_buffer(buffer, offset, 32)
            if max_equals_min ~= 1 then
                offset, max_ack = read_bits_as_buffer(buffer, offset, 32)
            else
                max_ack = min_ack
                
            end

            for i = min_ack:le_uint(), max_ack:le_uint() do
                ackSubtree:add(ack_packet_field, i);
            end
        end
    end

    if bits - offset > 33 then
        local has_time
        offset, has_time = read_bits(buffer, offset, 1)

        if has_time == 1 then
            local timeSubtree = subtree:add(otherland_raknet, buffer(), "System Time")

            local local_time
            offset, local_time = read_bits_as_buffer(buffer, offset, 32)
            timeSubtree:add(remote_time_field, local_time:le_uint())
        end
    end

    if bits - offset > 32 then
        local headerSubtree = subtree:add(otherland_raknet, buffer(), "Header")

        local message_number
        offset, message_number = read_bits_as_buffer(buffer, offset, 32)
        headerSubtree:add(packet_no_field, message_number:le_uint())

        local reliabilitySubtree = subtree:add(otherland_raknet, buffer(), "Reliability")

        local reliability
        offset, reliability = read_bits_as_buffer(buffer, offset, 3)
        reliability = reliability:le_uint()
        reliabilitySubtree:add(reliability_field, reliability):append_text(" (" .. get_reliability_description(reliability) .. ") ")

        if reliability == 1 or reliability == 3 or reliability == 4 then
            local channel, index
            offset, channel = read_bits(buffer, offset, 5)
            offset, index = read_bits_as_buffer(buffer, offset, 32)

            reliabilitySubtree:add(channel_field, channel)
            reliabilitySubtree:add(index_field, index:le_uint())
        end

        local is_split
        offset, is_split = read_bits(buffer, offset, 1)

        if is_split == 1 then
            local splitSubtree = subtree:add(otherland_raknet, buffer(), "Split")
            local id, index, count

            offset, id = read_bits_as_buffer(buffer, offset, 16)
            offset, index = parse_compressed_bytes(buffer, offset, 4, true)
            offset, count = parse_compressed_bytes(buffer, offset, 4, true)

            splitSubtree:add_le(split_id_field, id:tvb("")(0, 2))
            splitSubtree:add(split_index_field, index:le_uint())
            splitSubtree:add(split_count_field, count:le_uint())
        end

        local message_length
        offset, message_length = parse_compressed_bytes(buffer, offset, 2, true)

        -- byte align offset
        local message_offset = math.ceil(offset / 8)

        local payload_range = buffer(message_offset, math.ceil(read_uint16(message_length) / 8))
        subtree:add(payload, payload_range)
        
        if packetformat_dissector ~= nil then
            local message_id = payload_range:range(0, 1):bytes():get_index(0)
            if message_id >= 100 then
                packetformat_dissector:call(payload_range:tvb(), pinfo, tree)
            end
        end
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(6112, otherland_raknet)
udp_port:add(6113, otherland_raknet)
udp_port:add(6114, otherland_raknet)