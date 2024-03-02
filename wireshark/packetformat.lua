-- packetformat.lua - A dissectors class for packet format definitions.
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

---@alias dissector_func fun(tvb: Vtvb, tree: TreeItem, info: Column): Vtvb,TreeItem

---@class PacketFormat
---@field private format any
---@field private fields ProtoField[]
---@field private packet_fields ProtoField[]
---@field private struct_fields ProtoField[]
---@field private custom_dissectors { [string]: dissector_func }
local PacketFormat = {}
PacketFormat.__index = PacketFormat
PacketFormat.errors = {
    bad_id = "Unknown packet id.",
    unknown_primitive_type = "Encountered unknown primitive type.",
    unknown_specific_type = "The requested packet or structure does not exist.",
    cant_stash_type = "Tried to stash a type that cannot be stashed."
}

---@type { [string]: ProtoExpert? }
PacketFormat.experts = {
    string_too_long = nil
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
}

---@param t any
---@return integer,table?
local function type_to_ftype(t)
    if type(t) == "number" then
        return ftypes.NONE
    elseif type(t) == "string" then
        local pt = primitive_type_to_ftype[t]
        if pt == nil then
            return ftypes.NONE
        end
        return pt
    elseif type(t) == "table" then
        if t.name == "array" then
            if t.items == -1 then
                return ftypes.BYTES
            else
                return ftypes.NONE
            end
        else
            return type_to_ftype(t.name), t.enum
        end
    end

    return ftypes.NONE
end

---@param format any
---@param proto_name string
---@return PacketFormat
function PacketFormat.new(format, proto_name)
    ---@type ProtoField[]
    local fields = {}
    for k, v in ipairs(format.fieldDefinitions) do
        fields[k] = ProtoField.new(v.name, proto_name.."."..v.abbrev, type_to_ftype(v.type))
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

    return setmetatable({
        format = format,
        fields = fields,
        packet_fields = packet_fields,
        struct_fields = struct_fields,
        custom_dissectors = {}
    }, PacketFormat)
end

---@param to table
---@param what table
local function add_range(to, what)
    local target_start = #to
    for k, v in ipairs(what) do
        to[k + target_start] = v
    end
end

---@param all_fields ProtoField[]
function PacketFormat:add_all_fields(all_fields)
    add_range(all_fields, self.fields)
    add_range(all_fields, self.packet_fields)
    add_range(all_fields, self.struct_fields)
end

---@param name string
---@param dissector dissector_func
function PacketFormat:add_custom_dissector(name, dissector)
    self.custom_dissectors[name] = dissector
end

---@param name string
---@return ProtoField,any
---@private
function PacketFormat:get_fields_list(name)
    for k,v in ipairs(self.format.packets) do
        if v.name == name then
            return self.packet_fields[k],v
        end
    end
    for k,v in ipairs(self.format.structures) do
        if v.name == name then
            return self.struct_fields[k],v
        end
    end

    error(PacketFormat.errors.unknown_specific_type)
end

---@param name string
---@return dissector_func
function PacketFormat:get_specific_dissector_func(name)
    local proto_field, fields_list = self:get_fields_list(name)
    return function (tvb, tree, info)
        return self:dissect_fields_list(tvb, tree, info, proto_field, fields_list)
    end
end

---@return dissector_func
function PacketFormat:get_discriminated_dissector_func()
    return function (tvb, tree, info)
        return self:dissect_discriminated(tvb, tree, info)
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

---@param tvb Vtvb
---@param tree TreeItem
---@param field ProtoField
---@param field_type string
---@param stash? table
---@return Vtvb,TreeItem
local function dissect_with_lenght(tvb, tree, field, field_type, stash)
    local len = primitive_len[field_type]

    if len == nil then
        error(PacketFormat.errors.unknown_primitive_type)
    end

    local range = tvb:slice(len)
    local new_tree = range:tree_add_le(tree, field)

    if stash ~= nil then
        local read_func = primitive_read[field_type]
        if read_func == nil then
            error(PacketFormat.errors.cant_stash_type)
        end
        stash[stash.put_here] = read_func(range:tvb())
    end

    return tvb:range(len), new_tree
end

---@param tvb Vtvb
---@param tree TreeItem
---@param field ProtoField
---@param is_unicode boolean
---@param maxlen? number
---@param stash? table
---@return Vtvb,TreeItem
local function dissect_string(tvb, tree, field, is_unicode, maxlen, stash)
    local enc
    if is_unicode then
        enc = ENC_UTF_16 + ENC_LITTLE_ENDIAN
    else
        enc = ENC_ASCII
    end

    local len = tvb:slice(2):tvb():le_uint()

    if is_unicode then
        len = len * 2
    end

    local value = ""
    if len > 0 then
        value = tvb:range(2, len):tvb():string(enc)
    end

    if stash ~= nil then
        stash[stash.put_here] = value
    end

    local string_tree = tvb:slice(2 + len):tree_add_le(tree, field, value)

    if maxlen ~= nil and len > maxlen then
        if PacketFormat.experts.string_too_long ~= nil then
            string_tree:add_proto_expert_info(PacketFormat.experts.string_too_long)
        end
    end

    return tvb:range(2 + len), string_tree
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@param proto_field ProtoField
---@param field_type any
---@param field_len? number
---@param stash? table
---@return Vtvb,TreeItem
---@private
function PacketFormat:dissect_simple(tvb, tree, info, proto_field, field_type, field_len, stash)
    if type(field_type) == "string" then
        local dissector_func = self.custom_dissectors[field_type]
        if dissector_func ~= nil then
            return dissector_func(tvb, tree, info)
        elseif field_type == "cstring" then
            return dissect_string(tvb, tree, proto_field, false, field_len, stash)
        elseif field_type == "wstring" then
            return dissect_string(tvb, tree, proto_field, true, field_len, stash)
        else
            return dissect_with_lenght(tvb, tree, proto_field, field_type, stash)
        end
    elseif type(field_type) == "number" then
        return self:dissect_fields_list(tvb, tree, info, self.struct_fields[field_type], self.format.structures[field_type])
    end

    return tvb, tree
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@param stash table
---@param field_ref number|table
---@return Vtvb,TreeItem
---@private
function PacketFormat:dissect_field(tvb, tree, info, stash, field_ref)
    local field_index, field_len
    if type(field_ref) == "number" then
        field_index = field_ref
        field_len = nil
    elseif type(field_ref) == "table" then
        field_index = field_ref.index
        field_len = field_ref.len
    end

    local field_def = self.format.fieldDefinitions[field_index]
    local field_type = field_def.type
    local proto_field = self.fields[field_index]

    local field_stash = nil
    if field_def.stash ~= nil then
        stash.put_here = field_def.stash
        field_stash = stash
    end

    if type(field_type) == "table" then
        if field_type.name == "array" then
            local array_len
            ---@cast field_len -nil
            if field_len < 0 then
                array_len = stash[field_len * -1]
            else
                array_len = field_len
            end

            if field_type.items == -1 then
                tree = tvb:slice(array_len):tree_add_le(tree, proto_field)
                tvb = tvb:range(array_len)
            else
                tree = tvb:tree_add_le(tree, proto_field)

                local new_tvb = tvb
                for i=1,array_len do
                    local item_tree
                    new_tvb, item_tree = self:dissect_field(new_tvb, tree, info, stash, field_type.items)
                    item_tree:prepend_text("["..(i - 1).."] ")
                end

                tree:set_len(tvb:length_to(new_tvb))
                tvb = new_tvb
            end

            return tvb, tree
        else
            return dissect_with_lenght(tvb, tree, proto_field, field_type.name, field_stash)
        end
    else
        return self:dissect_simple(tvb, tree, info, proto_field, field_type, field_len, field_stash)
    end
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@param stash table
---@param branch table
---@return Vtvb
---@private
function PacketFormat:dissect_branch(tvb, tree, info, stash, branch)
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
            tvb, tree = self:dissect_fields_list(tvb, tree, info, "True", branch.isTrue)
        end
    else
        if branch.isFalse ~= nil then
            tvb, tree = self:dissect_fields_list(tvb, tree, info, "False", branch.isFalse)
        end
    end

    tree:set_generated(true)
    tree:set_len(0)

    return tvb
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@param proto_field ProtoField|string
---@param fields_list any
---@return Vtvb,TreeItem
---@private
function PacketFormat:dissect_fields_list(tvb, tree, info, proto_field, fields_list)
    local stash = {}

    tree = tvb:tree_add_le(tree, proto_field)

    local new_tvb = tvb
    for k, v in ipairs(fields_list.fields) do
        if type(v) == "table" and v.branch ~= nil then
            new_tvb = self:dissect_branch(new_tvb, tree, info, stash, v.branch)
        else
            new_tvb = self:dissect_field(new_tvb, tree, info, stash, v)
        end
    end

    tree:set_len(tvb:length_to(new_tvb))

    return new_tvb, tree
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@param packet_index number
---@return Vtvb,TreeItem
---@private
function PacketFormat:dissect_packet(tvb, tree, info, packet_index)
    local packet = self.format.packets[packet_index]

    local inherit = packet.inherit
    if inherit ~= nil then
        tvb = self:dissect_packet(tvb, tree, info, inherit)
    end

    info:append(packet.name.." ")

    return self:dissect_fields_list(tvb, tree, info, self.packet_fields[packet_index], packet)
end

---@param tvb Vtvb
---@param tree TreeItem
---@param info Column
---@return Vtvb,TreeItem
function PacketFormat:dissect_discriminated(tvb, tree, info)
    local ids = tvb:slice(self.format.idLength):tvb():bytes()

    local by_id = self.format.byId;
    for i=1,self.format.idLength do
        by_id = by_id[ids:get_index(i - 1)]
        if by_id == nil then
            error(PacketFormat.errors.bad_id)
        end
    end

    return self:dissect_packet(tvb:range(self.format.idLength), tree, info, by_id)
end

return PacketFormat