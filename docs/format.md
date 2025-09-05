<!--
Copyright 2021 zombocoder (Taras Havryliak)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# BFC Format Specification v1

This document defines the on-disk format for Binary File Container (BFC) version 1.

## Overview

BFC is an append-only container format with the following structure:

```
[Header 4 KiB] [Data Objects...] [Index blob] [Footer 56 bytes]
```

All multi-byte integers are stored in little-endian format.

## Header (4 KiB at offset 0)

```c
struct BfcHeader {
  char     magic[8];       // "BFCFv1\0"
  uint32_t header_crc32;   // CRC32 of remaining header bytes
  uint32_t block_size;     // alignment boundary (default 4096)
  uint64_t features;       // feature flags (bit0:zstd, bit1:aead - reserved)
  uint8_t  uuid[16];       // RFC 4122 v4 UUID
  uint8_t  reserved[4056]; // zero-filled, reserved for future use
} __attribute__((packed));
```

## Data Objects

Each data object consists of a header, name, padding, and content:

```c
struct BfcObjHdr {
  uint8_t  type;        // 1=file, 2=dir, 3=symlink
  uint8_t  comp;        // compression type: 0=none, 1=zstd (reserved)
  uint16_t name_len;    // length of name in bytes
  uint32_t mode;        // POSIX mode bits
  uint64_t mtime_ns;    // modification time in nanoseconds since Unix epoch
  uint64_t orig_size;   // original (uncompressed) size
  uint64_t enc_size;    // encoded (compressed/encrypted) size
  uint32_t crc32c;      // CRC32C of original content
} __attribute__((packed));
```

Layout: `[BfcObjHdr][name_bytes][padding][content_bytes]`

### Path Rules

- Paths are UTF-8 encoded
- No leading slash, no `..` components
- Directory separators normalized to `/`
- Maximum path length: 65535 bytes

### Alignment

- Content starts at 16-byte boundary after header+name
- Padding bytes are zero-filled

### Object Types

- **Type 1 (File)**: Regular file with content
- **Type 2 (Directory)**: Directory entry with `orig_size=enc_size=0`
- **Type 3 (Symlink)**: Symbolic link with target path as content

## Index Structure

The index provides fast random access to objects:

```c
struct BfcIndexHeader {
  uint32_t version;     // index format version (1)
  uint32_t count;       // number of entries
} __attribute__((packed));
```

Followed by `count` entries, each containing:

```c
struct BfcIndexEntry {
  uint32_t path_len;    // length of path
  // path bytes (UTF-8)
  uint64_t obj_offset;  // file offset to BfcObjHdr
  uint64_t obj_size;    // total object size including header
  uint32_t mode;        // POSIX mode bits
  uint64_t mtime_ns;    // modification time
  uint32_t comp;        // compression type
  uint64_t orig_size;   // original size
  uint32_t crc32c;      // content checksum
} __attribute__((packed));
```

Entries are sorted by path for efficient binary search and prefix matching.

## Footer (56 bytes at EOF)

```c
struct BfcFooter {
  char     tag[8];         // "BFCFIDX"
  uint64_t index_size;     // size of index blob in bytes
  uint32_t index_crc32;    // CRC32 of index blob
  uint64_t index_offset;   // absolute offset to index blob start
  uint32_t container_crc;  // reserved (0 in v1)
  uint8_t  reserved[16];   // zero-filled
  char     end[8];         // "BFCFEND"
} __attribute__((packed));
```

## Opening Procedure

1. Seek to EOF - 56 bytes
2. Read and validate footer:
   - Check start tag "BFCFIDX" and end tag "BFCFEND"
   - Validate index_offset and index_size are reasonable
3. Seek to index_offset and read index_size bytes
4. Validate index CRC32
5. Parse index header and entries
6. Optionally memory-map index for performance

## Writing Procedure

1. Write header with placeholder CRC
2. For each file/directory:
   - Write object header with placeholder sizes
   - Write name and padding
   - Stream content while computing CRC and counting bytes
   - Update header with actual sizes and CRC
3. Build index in memory while writing objects
4. Write index blob
5. Write footer with index location and CRC
6. Sync to disk

## Integrity Guarantees

- **CRC32C** used for content validation (hardware accelerated when available)
- **Atomic commits** via index+footer write with fsync
- **Crash recovery** possible by scanning for previous valid footer
- **Tamper detection** via checksum validation on read

## Version Compatibility

- Version 1 containers are forward-compatible with reserved feature bits
- Unknown feature bits should be ignored by readers
- Magic number identifies format version unambiguously
