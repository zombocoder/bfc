/*
 * Copyright 2021 zombocoder (Taras Havryliak)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BFC_MAGIC "BFCFv1\0"
#define BFC_MAGIC_SIZE 8
#define BFC_HEADER_SIZE 4096
#define BFC_FOOTER_SIZE 56
#define BFC_IDX_TAG "BFCFIDX"
#define BFC_END_TAG "BFCFEND"
#define BFC_ALIGN 16

// Object types
#define BFC_TYPE_FILE 1
#define BFC_TYPE_DIR 2
#define BFC_TYPE_SYMLINK 3

// Compression types
#define BFC_COMP_NONE 0
#define BFC_COMP_ZSTD 1

// Encryption types
#define BFC_ENC_NONE 0
#define BFC_ENC_CHACHA20_POLY1305 1

// Feature flags
#define BFC_FEATURE_ZSTD (1ULL << 0)
#define BFC_FEATURE_AEAD (1ULL << 1)

#pragma pack(push, 1)

struct bfc_header {
  char magic[8];          // "BFCFv1\0"
  uint32_t header_crc32;  // CRC32 of remaining header bytes
  uint32_t block_size;    // alignment boundary (default 4096)
  uint64_t features;      // feature flags
  uint8_t uuid[16];       // RFC 4122 v4 UUID
  uint8_t enc_salt[32];   // salt for key derivation (when using password encryption)
  uint8_t reserved[4024]; // zero-filled
};

struct bfc_obj_hdr {
  uint8_t type;       // object type
  uint8_t comp;       // compression type
  uint8_t enc;        // encryption type
  uint8_t reserved;   // reserved for future use
  uint16_t name_len;  // length of name in bytes
  uint16_t padding;   // padding for alignment
  uint32_t mode;      // POSIX mode bits
  uint64_t mtime_ns;  // modification time in nanoseconds
  uint64_t orig_size; // original size
  uint64_t enc_size;  // encoded size (after compression + encryption)
  uint32_t crc32c;    // CRC32C of original content
};

struct bfc_index_hdr {
  uint32_t version; // index format version
  uint32_t count;   // number of entries
};

struct bfc_footer {
  char tag[8];            // "BFCFIDX"
  uint64_t index_size;    // size of index blob
  uint32_t index_crc32;   // CRC32 of index blob
  uint64_t index_offset;  // absolute offset to index blob
  uint32_t container_crc; // reserved
  uint8_t reserved[16];   // zero-filled
  char end[8];            // "BFCFEND"
};

#pragma pack(pop)

// Path normalization and validation
int bfc_path_normalize(const char* path, char** normalized);
int bfc_path_validate(const char* path);
void bfc_path_free(char* path);

// UUID generation
void bfc_uuid_generate(uint8_t uuid[16]);

// Serialization helpers (little-endian)
void bfc_write_le16(uint8_t* buf, uint16_t val);
void bfc_write_le32(uint8_t* buf, uint32_t val);
void bfc_write_le64(uint8_t* buf, uint64_t val);
uint16_t bfc_read_le16(const uint8_t* buf);
uint32_t bfc_read_le32(const uint8_t* buf);
uint64_t bfc_read_le64(const uint8_t* buf);

// Header/footer serialization
int bfc_header_serialize(const struct bfc_header* hdr, uint8_t buf[BFC_HEADER_SIZE]);
int bfc_header_deserialize(const uint8_t buf[BFC_HEADER_SIZE], struct bfc_header* hdr);
int bfc_footer_serialize(const struct bfc_footer* footer, uint8_t buf[BFC_FOOTER_SIZE]);
int bfc_footer_deserialize(const uint8_t buf[BFC_FOOTER_SIZE], struct bfc_footer* footer);

// Alignment helpers
size_t bfc_align_up(size_t size, size_t align);
size_t bfc_padding_size(size_t size, size_t align);