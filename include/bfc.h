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
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BFC_OK 0
typedef enum {
  BFC_E_BADMAGIC = -1,
  BFC_E_IO = -2,
  BFC_E_CRC = -3,
  BFC_E_INVAL = -4,
  BFC_E_EXISTS = -5,
  BFC_E_NOTFOUND = -6,
  BFC_E_PERM = -7,
} bfc_err_t;

// Compression types
#define BFC_COMP_NONE 0
#define BFC_COMP_ZSTD 1

// Encryption types
#define BFC_ENC_NONE 0
#define BFC_ENC_CHACHA20_POLY1305 1

// Feature flags
#define BFC_FEATURE_ZSTD (1ULL << 0)
#define BFC_FEATURE_AEAD (1ULL << 1)

typedef struct bfc bfc_t;

typedef struct {
  const char* path; // UTF-8
  uint32_t mode;    // POSIX bits
  uint64_t mtime_ns;
  uint32_t comp; // compression type
  uint32_t enc;  // encryption type
  uint64_t size; // uncompressed size
  uint32_t crc32c;
  uint64_t obj_offset;
  uint64_t obj_size;
} bfc_entry_t;

/* --- Writer API (append-only) --- */
int bfc_create(const char* filename, uint32_t block_size, uint64_t features, bfc_t** out);
int bfc_add_file(bfc_t* w, const char* container_path, FILE* src, uint32_t mode, uint64_t mtime_ns,
                 uint32_t* out_crc);
int bfc_add_dir(bfc_t* w, const char* container_dir, uint32_t mode, uint64_t mtime_ns);
int bfc_add_symlink(bfc_t* w, const char* container_path, const char* link_target, uint32_t mode,
                    uint64_t mtime_ns);

/* --- Compression Configuration --- */
int bfc_set_compression(bfc_t* w, uint8_t comp_type, int level);
int bfc_set_compression_threshold(bfc_t* w, size_t min_bytes);
uint8_t bfc_get_compression(bfc_t* w);

/* --- Encryption Configuration --- */
int bfc_set_encryption_password(bfc_t* w, const char* password, size_t password_len);
int bfc_set_encryption_key(bfc_t* w, const uint8_t key[32]);
int bfc_clear_encryption(bfc_t* w);
uint8_t bfc_get_encryption(bfc_t* w);
int bfc_has_encryption(bfc_t* r);

// Reader-specific encryption functions
int bfc_reader_set_encryption_password(bfc_t* r, const char* password, size_t password_len);
int bfc_reader_set_encryption_key(bfc_t* r, const uint8_t key[32]);

int bfc_finish(bfc_t* w); // writes index + footer, fsync
void bfc_close(bfc_t* w); // closes handle, safe to call after finish

/* --- Reader API --- */
int bfc_open(const char* filename, bfc_t** out);
void bfc_close_read(bfc_t* r);

int bfc_stat(bfc_t* r, const char* container_path, bfc_entry_t* out);
typedef int (*bfc_list_cb)(const bfc_entry_t* ent, void* user);
int bfc_list(bfc_t* r, const char* prefix_dir, bfc_list_cb cb, void* user);

size_t bfc_read(bfc_t* r, const char* container_path, uint64_t offset, void* buf,
                size_t len); // content only

/* --- Utilities --- */
int bfc_extract_to_fd(bfc_t* r, const char* container_path, int out_fd); // validates crc
int bfc_verify(bfc_t* r, int deep); // deep: read & crc contents

#ifdef __cplusplus
}
#endif