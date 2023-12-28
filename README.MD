# Otherland Packet Structure

This repository documents the packet structure of the game "Otherland" in YAML format.

## Structure
- **otherland.packet.schema.yaml**: Defines the structure of the packet definition documents in JSON Schema format.
- **packets**: This folder contains the primary packet definition documents.
- **structs**: Contains miscellaneous user defined structures used by the packet definitions.

## Intrinsic Data Types

The packet definitions make use of same basic data types not directly defined by the definition documents. These should be implemented by the target languages that whish to operate with packets.

- **bool**: Boolean value, `true` or `false`. Encoded as a single byte, zero represents `false`, non-zero values represent `true`.
- **u8, u16, u32, u64**: Unsigned little endian integers of 8, 16, 32, and 64 bits respectively.
- **i8, i16, i32, i64**: Signed little endian integers of 8, 16, 32, and 64 bits respectively.
- **f32, f64**: Single and double precision little endian IEEE 754 floating point numbers.
- **cstring**: ANSI string of single byte characters, prefixed by its length in bytes encoded as a two byte little endian integer, has no terminating null character.
- **wstring**: Wide string of two byte UTF-16 characters, prefixed by its length in bytes encoded as a two byte little endian integer, has no terminating null character.
- **nativeparam**: Atlas param object, whose format is described by `paramlist.ini`.
- **uuid**: A standard 128 bit, COM/OLE style, little endian Universally Unique Identifier.

The documents may also contain custom user defined data types and arrays of intrinsics or user defined types. These should be represented by appropriate data structures in the target language.

## Contribute
Please feel free to contribute by submitting PRs or raising issues. Ensure your additions or changes follow the established schema format.