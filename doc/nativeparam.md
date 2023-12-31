# Nativeparam format
## Introduction
The otherland networking packets and structs sometimes refer to a built-in `nativeparam` type. It's a simple binary format to transmit data in a flexible layout to and from the server. This document aims to explain the format used.

## General
The nativeparam format describes a stream of binary fields, each prefixed by a byted, used as a type identifier and, where required, an additional length attribute. The only exception to this is the very first field, where a `struct` type is expected and the type identifier is ommited. 

```
 0               1               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID       | Data          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


Using the `struct` type it's possible to encoded nested datastructures. More on that can be read in the datatype explanation bellow. 

The nativeparam format does not encode any field names, only data. Semantics of the given data have to be extracted from game code.

All types are little-endian encoded.

## Datatypes
### Type ID 1: uint8
```
 0               1               2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 1    | uint8         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 2: float32
```
 0               1               2               3               4               5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 2    | float32                                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 3: float64
```
 0               1               ...             8               9
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 3    | float64                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 4: int32
```
 0               1               2               3               4               5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 4    | int32                                                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 5: c-string
```
 0               1               2               3               n               
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 5    | uint16 (length)               | length ASCII characters ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Most strings used by the game tend to be ASCII, but the game might be able to handle utf-8.

### Type ID 6: struct
```
 0               1               2               n               
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 6    | uint8 (count) | count fields ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The struct is a somewhat special composite-type. Instead of encoding raw data as its contents, 
it encodes nativeparams. Therefore, each field is type prefixed as described in this document,
leading to a recursive data structure.

The `struct` type additionally is the default datatype assumed for the first field at the beginning of a nativeparam stream. The type id is ommited in that case.

```
 0               1               n                             
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| uint8 (count) | count fields ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 7: uuid
```
 0               1                               17
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 7    | COM/OLE style UUID            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

All inividual fields of the UUID are encoded little-endian.

```
0                1                 2                 3               4
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| time_low                                                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| time_mid                        | time_hi_and_version             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| clock_seq_hi  | clock_seq_lo    | node                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| node                                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 8: avatar-id
```
 0               1               8               9
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 8    | uint64                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The avatar-id is encoded as an unsigned 64-bit integer. The least significant nibble does encode
the type of the avatar. `1` denotes a player character, `2` an npc. Other types might be unearthed in the future.

```
 0               1               2               3               4               5               6               7
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type  | Avatar id                                                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 9: vector3
```
 0               1               5               9               13
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 9    | float32 (x)   | float32 (y)   | float32 (z)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 10: bool
```
 0               1               2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 10   | uint8         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Non-zero resolves to true, zero false.

### Type ID 11: json
```
 0               1               2               3               n               
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 11   | uint16 (length)               | length utf-8 characters ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Similar format as type id 5 c-string, but encoding a plain json document as string.

### Type ID 12: int32-array
```
 0               1               2               3               4               5               n
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 12   | uint32 (element count)                                        | element count int32s ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 13: int64
```
 0               1               8               9
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 13   | int64                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 14: buffer
```
 0               1               2               3               4               5               n
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 14   | uint32 (element count)                                        | element count bytes ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

A dynamic buffer, prefixed by a length attribute.

### Type ID 15: uint32
```
 0               1               2               3               4               5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 15   | uint32                                                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Type ID 16: uuid-array
```
 0               1               2               3               4               5               n
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 16   | uint32 (element count)                                        | element count uuids ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The `uuid` elements are encoded similar to type id 7 `uuid`, excluding the type id property.

### Type ID 17: c-string-array
```
 0               1               2               3               4               5               n
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type ID: 17   | uint32 (element count)                                        | element count c-strings ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The `c-string` elements are encoded similar to type id 5 `c-string`, excluding the type id property.

```
 0               1               2               3               n               
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| uint16 (element 1 length)     | length ASCII characters ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| uint16 (element 2 length)     | length ASCII characters ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
...
```


# Examples
For clarity this section draws the nativeparam structures in a tree-like fashion, omitting the byte count of the previous diagram. Examples are taken from real client requests.

## oaPktClusterClientToCommunity - Social Travel request
```
struct (type id omitted)
|- type id 4: int32 (Message type) = 0xb3
|- type id 8: avatar-id (Player character)
|- type id 5: c-string (Target map name)
|- type id 10: bool
```

## oaPktClusterClientToCommunity - Unknown request 0xa1
```
struct (type id omitted)
|- type id 4: int32 (Message type) = 0xa1
|- type id 8: avatar-id
|- type id 10: bool
```

## oaPktClusterClientToCommunity - Unknown request 0x77
```
struct (type id omitted)
|- type id 4: int32 (Message type) = 0x77
|- type id 8: avatar-id
```

# Conclusion
The nativeparam format is as simple as it gets for binary formats. Additionally, as far as we know, the game uses it only for some rather simple use-cases (as seen in the examples). In the future we might encounter more complex structures encoded that way.