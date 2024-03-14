-- vtvb.lua - Virtual Testy Virtual Buffer
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

---@class Vtvb
---@field private my_tvb Tvb
---@field private my_offset number
---@field private my_length number
---@field private my_explicit boolean
local Vtvb = {}
Vtvb.__index = Vtvb
Vtvb.errors = {
    end_of_packet = "The end of the packet was reached, but more data was expected.",
    end_of_range = "Tried to read outside of an explicitly sized range.",
    zero_lenght = "Can't create 0 length TvbRange."
}

---@param tvb Tvb
---@return Vtvb
function Vtvb.new(tvb)
    return setmetatable({
        my_tvb = tvb,
        my_offset = 0,
        my_length = tvb:len(),
        my_explicit = false
    }, Vtvb)
end

---@return number
function Vtvb:offset() return self.my_offset end

---@return number
function Vtvb:len() return self.my_length end

---@return TvbRange
function Vtvb:tvb()
    if self.my_length == 0 then
        error(Vtvb.errors.zero_lenght)
    end
    return self.my_tvb:range(self.my_offset, self.my_length)
end

---@param offset number
---@param lenght? number
---@return Vtvb
function Vtvb:range(offset, lenght)
    local explicit = true
    if lenght == nil then
        lenght = self.my_length - offset
        explicit = false
    end

    if offset < 0 or lenght < 0 then
        error(Vtvb.errors.end_of_range)
    end

    if offset > self.my_length or lenght > (self.my_length - offset) then
        if self.my_explicit then
            error(Vtvb.errors.end_of_range)
        else
            error(Vtvb.errors.end_of_packet)
        end
    end

    return setmetatable({
        my_tvb = self.my_tvb,
        my_offset = self.my_offset + offset,
        my_length = lenght,
        my_explicit = explicit
    }, Vtvb)
end

---@param length number
---@return Vtvb
function Vtvb:slice(length)
    return self:range(0, length)
end

---@param other Vtvb
---@return number
function Vtvb:length_to(other)
    return other.my_offset - self.my_offset
end

---@param tree TreeItem
---@param proto_field Proto|ProtoField 
---@param value? any
---@return TreeItem
function Vtvb:tree_add_le(tree, proto_field, value)
    if self.my_length ~= 0 then
        if value == nil then
            return tree:add_le(proto_field, self:tvb())
        else
            return tree:add_le(proto_field, self:tvb(), value)
        end
    else
        if value == nil then
            return tree:add_le(proto_field)
        else
            return tree:add_le(proto_field, value)
        end
    end
end

return Vtvb