# Otherland Packet Structure

This repository documents the packet structure of the game "Otherland" in YAML format.

## Structure
- **Root Folder**: Contains metafiles, README, and other primary documents.
- **Definitions**: Houses all packet definitions.

## Data Type Primitives

Below are the basic data types and their descriptions:

- **bool**: Boolean value (True or False).
- **u8, u16, u32, u64**: Unsigned integers of 8, 16, 32, and 64 bits respectively.
- **i8, i16, i32, i64**: Signed integers of 8, 16, 32, and 64 bits respectively.
- **cstring**: Ansi string prefixed by its length. Defined with a maximum length for serialization.
- **wstring**: Wide string, commonly used for Unicode characters. Prefixed in a manner similar to `cstring` and also defined with a maximum length for serialization.
- **array**: An array with a specified length and data type.

## Contribute
Please feel free to contribute by submitting PRs or raising issues. Ensure your additions or changes follow the established schema format.