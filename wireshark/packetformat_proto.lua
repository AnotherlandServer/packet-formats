-- packetformat_proto.lua - Packet format protocol definition.
-- Copyright (C) 2024 Vince Kálmán
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

local Vtvb = require("vtvb")
local PacketFormat = require("packetformat")

local proto_name = "otherland.packetformat"

local format_ok, format = pcall(require, "packetformat_generated")
if not format_ok then
    error("Generated definitions are not available, plase create them with the PacketDocs tool first.")
end

local proto = Proto.new(proto_name, "Otherland Packet Format")

local expert_end_of_packet = ProtoExpert.new(
    ---@diagnostic disable-next-line
    proto_name..".exp.endofpacket", Vtvb.errors.end_of_packet,
    expert.group.MALFORMED, expert.severity.ERROR
)
Vtvb.errors.end_of_packet = {expert = expert_end_of_packet}

local expert_not_end_of_packet = ProtoExpert.new(
    proto_name.."exp.notendofpacket", "The packet was longer than expected, some data was not consumed.",
    expert.group.UNDECODED, expert.severity.WARN
)

local expert_bad_id = ProtoExpert.new(
    ---@diagnostic disable-next-line
    proto_name..".exp.badid", PacketFormat.errors.bad_id,
    expert.group.MALFORMED, expert.severity.ERROR
)
PacketFormat.errors.bad_id = {expert = expert_bad_id}

local expert_string_too_long = ProtoExpert.new(
    proto_name..".exp.stringtoolong", "The lenght of this string is longer than the expected maximum.",
    expert.group.PROTOCOL, expert.severity.WARN
)
PacketFormat.experts.string_too_long = expert_string_too_long

proto.experts = {
    expert_end_of_packet,
    expert_not_end_of_packet,
    expert_bad_id,
    expert_string_too_long
}

local packetformat_main = PacketFormat.new(format.main, proto_name)
local packetformat_nativeparam = PacketFormat.new(format.nativeparam, proto_name..".nativeparam")

packetformat_main:add_custom_dissector("packet", packetformat_main:get_discriminated_dissector_func(true))
packetformat_main:add_custom_dissector("nativeparam", packetformat_nativeparam:get_specific_dissector_func("struct", false))
packetformat_nativeparam:add_custom_dissector("nativeparam", packetformat_nativeparam:get_discriminated_dissector_func(true))

---@type ProtoField[]
local all_fields = {}
packetformat_main:add_all_fields(all_fields)
packetformat_nativeparam:add_all_fields(all_fields)
proto.fields = all_fields

function proto.dissector(tvb, pinfo, tree)
    pinfo.cols["protocol"]:set("Packet Format")
    pinfo.cols["info"]:clear()

    local vtvb = Vtvb.new(tvb)
    local proto_tree = tree:add(proto, tvb:range())

    local success, message = pcall(function ()
        vtvb = packetformat_main:dissect_discriminated(vtvb, proto_tree, pinfo.cols["info"])

        if vtvb:len() > 0 then
            proto_tree:add_proto_expert_info(expert_not_end_of_packet)
        end
    end)

    if not success then
        if type(message) == "table" and message.expert ~= nil then
            proto_tree:add_proto_expert_info(message.expert)
        else
            error(message)
        end
    end
end
