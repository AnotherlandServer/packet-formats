-- packetformat.lua - A dissectors for packet format definitions.
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

local proto_name = "otherland.packetformat"

local format_ok, format = pcall(require, "packetformat_generated")
if not format_ok then
    error("Generated definitions are not available, plase create them with the PacketDocs tool first.")
end

local proto = Proto.new(proto_name, "Otherland Packet Format")

local expert_end_of_packet = ProtoExpert.new(
    proto_name..".exp.endofpacket", "The end of the packet was reached, but more data was expected.",
    expert.group.MALFORMED, expert.severity.ERROR
)

local expert_bad_id = ProtoExpert.new(
    proto_name..".exp.badid", "Unknown packet id.",
    expert.group.MALFORMED, expert.severity.ERROR
)

local expert_string_too_long = ProtoExpert.new(
    proto_name..".exp.stringtoolong", "The lenght of this string is longer than the expected maximum.",
    expert.group.PROTOCOL, expert.severity.WARN
)

proto.experts = {
    expert_end_of_packet,
    expert_bad_id,
    expert_string_too_long
}

local primitive_type_to_ftype = {
    bool = ftypes.BOOLEAN,
    cstring = ftypes.STRING,
    wstring = ftypes.STRING,
    u8 = ftypes.UINT8,
    u16 = ftypes.UINT16,
    u32 = ftypes.UINT32,
    u64 = ftypes.UINT64,
    i8 = ftypes.INT8,
    i16 = ftypes.INT16,
    i32 = ftypes.INT32,
    i64 = ftypes.INT64,
    f32 = ftypes.FLOAT,
    f64 = ftypes.DOUBLE,
    uuid = ftypes.GUID,
    nativeparam = ftypes.NONE -- TODO
}

---@param t any
---@return integer
local function type_to_ftype(t)
    if type(t) == "number" then
        return ftypes.NONE
    elseif type(t) == "string" then
        return primitive_type_to_ftype[t]
    elseif type(t) == "table" then
        if t.name == "array" then
            return ftypes.NONE
        else
            return type_to_ftype(t.name)
        end
    end

    return ftypes.NONE
end

---@type ProtoField[]
local fields = {}
for k, v in ipairs(format.fieldDefinitions) do
    fields[k] = ProtoField.new(v.name, proto_name.."."..v.abbrev, type_to_ftype(v.type)) -- TODO: enums
end

---@type ProtoField[]
local packet_fields = {}
for k, v in ipairs(format.packets) do
    packet_fields[k] = ProtoField.new(v.name, proto_name..".packet."..v.name, ftypes.NONE)
end

---@type ProtoField[]
local struct_fields = {}
for k, v in ipairs(format.structures) do
    struct_fields[k] = ProtoField.new(v.name, proto_name..".struct."..v.name, ftypes.NONE)
end

---@param to table
---@param what table
local function add_range(to, what)
    local target_start = #to
    for k, v in ipairs(what) do
        to[k + target_start] = v
    end
end

---@type ProtoField[]
local all_fields = {}
add_range(all_fields, fields)
add_range(all_fields, packet_fields)
add_range(all_fields, struct_fields)
proto.fields = all_fields

---@class FakeEmptyRange: TvbRange
---@field offset_value number
local FakeEmptyRange = {}
FakeEmptyRange.__index = FakeEmptyRange

---@param offset number
---@return FakeEmptyRange
function FakeEmptyRange:new(offset)
    ---@type FakeEmptyRange
    local instance = { offset_value = offset }
    setmetatable(instance, self)
    return instance
end

---@return number
function FakeEmptyRange:len()
    return 0
end

---@return number
function FakeEmptyRange:offset()
    return self.offset_value
end

---@param tvb TvbRange
---@param offset number
---@return TvbRange
local function tvb_safe_offset(tvb, offset)
    if offset < tvb:len() then
        return tvb:range(offset)
    end
    return FakeEmptyRange:new(tvb:offset() + tvb:len())
end

---@param tvb Tvb|TvbRange
---@param len number
local function check_len(tvb, len)
    if tvb:len() < len then
        error({expert = expert_end_of_packet})
    end
end

local primitive_len = {
    bool = 1,
    u8 = 1,
    u16 = 2,
    u32 = 4,
    u64 = 8,
    i8 = 1,
    i16 = 2,
    i32 = 4,
    i64 = 8,
    f32 = 4,
    f64 = 8,
    uuid = 16
}

---@param n number
---@return number
local function sign_byte(n)
    if bit32.btest(n, 128) then
      return -1 * (bit32.band(bit32.bnot(n), 255) + 1)
    else
        return n
    end
end

---@type { [string]: fun(tvb: TvbRange): number }
local primitive_read = {
    bool = function (tvb) return tvb:bytes():get_index(0) end,
    u8 = function (tvb) return tvb:bytes():get_index(0) end,
    u16 = function (tvb) return tvb:le_uint() end,
    u32 = function (tvb) return tvb:le_uint() end,
    u64 = function (tvb) return tvb:le_uint64() end,
    i8 = function (tvb) return sign_byte(tvb:bytes():get_index(0)) end,
    i16 = function (tvb) return tvb:le_int() end,
    i32 = function (tvb) return tvb:le_int() end,
    i64 = function (tvb) return tvb:le_int64() end,
}

---@param tvb TvbRange
---@param tree TreeItem
---@param field ProtoField
---@param field_type string
---@param stash? table
---@return TvbRange, TreeItem
local function dissect_with_lenght(tvb, tree, field, field_type, stash)
    local len = primitive_len[field_type]

    check_len(tvb, len)
    local range = tvb:range(0, len)
    local new_tree = tree:add_le(field, range)

    if stash ~= nil then
        stash[stash.put_here] = primitive_read[field_type](range)
    end

    return tvb_safe_offset(tvb, len), new_tree
end

---@param tvb TvbRange
---@param tree TreeItem
---@param field ProtoField
---@param is_unicode boolean
---@param maxlen? number
---@param stash? table
---@return TvbRange, TreeItem
local function dissect_string(tvb, tree, field, is_unicode, maxlen, stash)
    local enc
    if is_unicode then
        enc = ENC_UTF_16 + ENC_LITTLE_ENDIAN
    else
        enc = ENC_ASCII
    end

    check_len(tvb, 2)
    local len = tvb:range(0, 2):le_uint()

    if is_unicode then
        len = len * 2
    end

    local value = ""
    if len > 0 then
        check_len(tvb, 2 + len)
        value = tvb:range(2, len):string(enc)
    end

    if stash ~= nil then
        stash[stash.put_here] = value
    end

    local string_tree = tree:add(field, tvb:range(0, 2 + len), value)

    if maxlen ~= nil and len > maxlen then
        string_tree:add_proto_expert_info(expert_string_too_long)
    end

    return tvb_safe_offset(tvb, 2 + len), string_tree
end

---@type fun(tvb: TvbRange, tree: TreeItem, proto_field: ProtoField|string, fields_list: any): TvbRange,TreeItem
local dissect_fields_list

---@param tvb TvbRange
---@param tree TreeItem
---@param proto_field ProtoField
---@param field_type any
---@param field_len? number
---@param stash? table
---@return TvbRange, TreeItem
local function dissect_simple(tvb, tree, proto_field, field_type, field_len, stash)
    if type(field_type) == "string" then
        if field_type == "cstring" then
            return dissect_string(tvb, tree, proto_field, false, field_len, stash)
        elseif field_type == "wstring" then
            return dissect_string(tvb, tree, proto_field, true, field_len, stash)
        elseif field_type == "nativeparam" then
            return tvb, tree -- TODO
        else
            return dissect_with_lenght(tvb, tree, proto_field, field_type, stash)
        end
    elseif type(field_type) == "number" then
        return dissect_fields_list(tvb, tree, struct_fields[field_type], format.structures[field_type])
    end

    return tvb, tree
end

---@param tvb TvbRange
---@param tree TreeItem
---@param stash table
---@param field_ref number|table
---@return TvbRange,TreeItem
local function dissect_field(tvb, tree, stash, field_ref)
    local field_index, field_len
    if type(field_ref) == "number" then
        field_index = field_ref
        field_len = nil
    elseif type(field_ref) == "table" then
        field_index = field_ref.index
        field_len = field_ref.len
    end

    local field_def = format.fieldDefinitions[field_index]
    local field_type = field_def.type
    local proto_field = fields[field_index]

    local field_stash = nil
    if field_def.stash ~= nil then
        stash.put_here = field_def.stash
        field_stash = stash
    end

    if type(field_type) == "table" then
        if field_type.name == "array" then
            local array_len
            if field_len < 0 then
                array_len = stash[field_len * -1]
            else
                array_len = field_len
            end

            tree = tree:add(proto_field, tvb)

            local new_tvb = tvb
            for i=1,array_len do
                local item_tree
                new_tvb, item_tree = dissect_field(new_tvb, tree, stash, field_type.items)
                item_tree:prepend_text("["..(i - 1).."] ")
            end

            tree:set_len(new_tvb:offset() - tvb:offset())

            return new_tvb, tree
        else
            return dissect_with_lenght(tvb, tree, proto_field, field_type.name, field_stash)
        end
    else
        return dissect_simple(tvb, tree, proto_field, field_type, field_len, field_stash)
    end
end

---@param tvb TvbRange
---@param tree TreeItem
---@param stash table
---@param branch table
---@return TvbRange
local function dissect_branch(tvb, tree, stash, branch)
    local field_value = stash[branch.field]

    local condition
    if branch.test_equal ~= nil then
        condition = (field_value == branch.test_equal)
    elseif branch.test_flag ~= nil then
        -- This won't work with 64 bit values, but the format definition literal also can't handle those right now.
        condition = (bit32.band(field_value, branch.test_flag) == branch.test_flag)
    else
        condition = (field_value ~= 0)
    end

    if condition then
        if branch.isTrue ~= nil then
            tvb, tree = dissect_fields_list(tvb, tree, "True", branch.isTrue)
        end
    else
        if branch.isFalse ~= nil then
            tvb, tree = dissect_fields_list(tvb, tree, "False", branch.isFalse)
        end
    end

    tree:set_generated(true)
    tree:set_len(0)

    return tvb
end

---@param tvb TvbRange
---@param tree TreeItem
---@param proto_field ProtoField|string
---@param fields_list any
---@return TvbRange,TreeItem
function dissect_fields_list(tvb, tree, proto_field, fields_list)
    local stash = {}

    tree = tree:add(proto_field, tvb)

    local new_tvb = tvb
    for k, v in ipairs(fields_list.fields) do
        if type(v) == "table" and v.branch ~= nil then
            new_tvb = dissect_branch(new_tvb, tree, stash, v.branch)
        else
            new_tvb = dissect_field(new_tvb, tree, stash, v)
        end
    end

    tree:set_len(new_tvb:offset() - tvb:offset())

    return new_tvb, tree
end

---@param tvb TvbRange
---@param tree TreeItem
---@param packet_index number
---@return TvbRange,TreeItem
local function dissect_packet(tvb, tree, packet_index)
    local packet = format.packets[packet_index]

    local inherit = packet.inherit
    if inherit ~= nil then
        tvb = dissect_packet(tvb, tree, inherit)
    end

    return dissect_fields_list(tvb, tree, packet_fields[packet_index], packet)
end

function proto.dissector(tvb, pinfo, tree)
    local proto_tree = tree:add(proto, tvb:range())

    local success, message = pcall(function ()
        check_len(tvb, 2)
        local ids = tvb:bytes(0, 2)

        local by_id_main = format.byId[ids:get_index(0)]
        if by_id_main == nil then
            error({expert = expert_bad_id})
        end

        local by_id_sub = by_id_main[ids:get_index(1)]
        if by_id_sub == nil then
            error({expert = expert_bad_id})
        end

        dissect_packet(tvb:range(2), proto_tree, by_id_sub)
    end)

    if not success then
        if type(message) == "table" and message.expert ~= nil then
            proto_tree:add_proto_expert_info(message.expert)
        else
            error(message)
        end
    end
end

