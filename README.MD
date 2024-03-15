# Otherland Packet Structure

This repository documents the packet structure of the game "Otherland" in YAML format.

## Structure
- **otherland.packet.schema.yaml**: Defines the structure of the packet definition documents in JSON Schema format.
- **packets**: This folder contains the primary packet definition documents.
- **structs**: Contains miscellaneous user defined structures used by the packet definitions.
- **wireshark**: Dissectors for the Otherland RakNet transport protocol and application layer packets.

## Intrinsic Data Types

The packet definitions make use of same basic data types not directly defined by the definition documents. These should be implemented by the target languages that whish to operate with packets.

- **bool**: Boolean value, `true` or `false`. Encoded as a single byte, zero represents `false`, non-zero values represent `true`.
- **u8, u16, u32, u64**: Unsigned little endian integers of 8, 16, 32, and 64 bits respectively.
- **i8, i16, i32, i64**: Signed little endian integers of 8, 16, 32, and 64 bits respectively.
- **f32, f64**: Single and double precision little endian IEEE 754 floating point numbers.
- **cstring**: ANSI string of single byte characters, prefixed by its length in bytes encoded as a two byte little endian integer, has no terminating null character.
- **wstring**: Wide string of two byte, little endian UTF-16 characters, prefixed by its length in characters encoded as a two byte little endian integer, has no terminating null character.
- **nativeparam**: An Otherland specific structured data type. (See: [Nativeparam format](doc/nativeparam.md))
- **uuid**: A standard 128 bit, COM/OLE style, little endian Universally Unique Identifier.
- **packet**: Another embedded packet, starting with its two byte identifier.

The documents may also contain custom user defined data types and arrays of intrinsics or user defined types. These should be represented by appropriate data structures in the target language.

## Wireshark Dissectors

`otherland.lua` defines a dissector for the game's modified RakNet transport layer protocol. `packetformat_proto.lua` defines a dissector for the application layer packets described in the packet definition documents.

To use the application layer dissector, you first need to process the packet definition documents with the [TreeHouse.PacketDocs](https://github.com/DRKV333/TreeHouse) tool.

```
TreeHouse.PacketDocs.exe lua -d . -o ./wireshark/packetformat_generated.lua
```

## Licensing

The contents of this repository are provided under the CC0 license, except for the `wireshark` folder. These code files make use of Wireshark's API, so they are available under the GNU GPL.

## Contribute
Please feel free to contribute by submitting PRs or raising issues. Ensure your additions or changes follow the established schema format.