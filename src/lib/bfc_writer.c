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

#define _GNU_SOURCE
#include "bfc_compress.h"
#include "bfc_crc32c.h"
#include "bfc_encrypt.h"
#include "bfc_format.h"
#include "bfc_os.h"
#include "bfc_util.h"
#include <bfc.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef BFC_WITH_SODIUM
#include <sodium.h>
#endif

#define WRITE_BUFFER_SIZE 65536

typedef struct bfc_index_entry {
  char* path;
  uint64_t obj_offset;
  uint64_t obj_size;
  uint32_t mode;
  uint64_t mtime_ns;
  uint32_t comp;
  uint32_t enc;
  uint64_t orig_size;
  uint32_t crc32c;
} bfc_index_entry_t;

struct bfc {
  FILE* file;
  char* filename;
  int finished;

  // Header info
  uint32_t block_size;
  uint64_t features;
  uint8_t uuid[16];

  // Compression settings
  uint8_t compression_type;
  int compression_level;
  size_t compression_threshold;

  // Encryption settings
  uint8_t encryption_type;
  int has_encryption_key;
  uint8_t encryption_key[32];
  uint8_t encryption_salt[32];
  bfc_encrypt_key_t master_key; // Store complete key structure for consistent encryption

  // Index entries
  bfc_array_t index;

  // Path tracking for duplicates
  bfc_array_t paths;

  // Current position
  uint64_t current_offset;
};

static int add_path_to_index(bfc_t* w, const char* path, uint64_t obj_offset, uint64_t obj_size,
                             uint32_t mode, uint64_t mtime_ns, uint32_t comp, uint32_t enc,
                             uint64_t orig_size, uint32_t crc32c) {
  // Check for duplicate paths in current session
  for (size_t i = 0; i < bfc_array_size(&w->paths); i++) {
    char** existing = bfc_array_get(&w->paths, i);
    if (bfc_strcmp(*existing, path) == 0) {
      return BFC_E_EXISTS;
    }
  }

  char* path_copy = bfc_strdup(path);
  if (!path_copy) {
    return BFC_E_IO;
  }

  bfc_index_entry_t entry = {.path = path_copy,
                             .obj_offset = obj_offset,
                             .obj_size = obj_size,
                             .mode = mode,
                             .mtime_ns = mtime_ns,
                             .comp = comp,
                             .enc = enc,
                             .orig_size = orig_size,
                             .crc32c = crc32c};

  int result = bfc_array_push(&w->index, &entry);
  if (result != BFC_OK) {
    free(path_copy);
    return result;
  }

  result = bfc_array_push(&w->paths, &path_copy);
  if (result != BFC_OK) {
    // Remove from index
    w->index.size--;
    free(path_copy);
    return result;
  }

  return BFC_OK;
}

int bfc_create(const char* filename, uint32_t block_size, uint64_t features, bfc_t** out) {
  if (!filename || !out) {
    return BFC_E_INVAL;
  }

  if (block_size == 0) {
    block_size = BFC_HEADER_SIZE;
  }

  bfc_t* w = bfc_calloc(1, sizeof(bfc_t));
  if (!w) {
    return BFC_E_IO;
  }

  w->filename = bfc_strdup(filename);
  if (!w->filename) {
    bfc_free(w);
    return BFC_E_IO;
  }

  int result = bfc_os_open_write(filename, &w->file);
  if (result != BFC_OK) {
    bfc_free(w->filename);
    bfc_free(w);
    return result;
  }

  // Initialize arrays
  result = bfc_array_init(&w->index, sizeof(bfc_index_entry_t));
  if (result != BFC_OK) {
    bfc_os_close(w->file);
    bfc_free(w->filename);
    bfc_free(w);
    return result;
  }

  result = bfc_array_init(&w->paths, sizeof(char*));
  if (result != BFC_OK) {
    bfc_array_destroy(&w->index);
    bfc_os_close(w->file);
    bfc_free(w->filename);
    bfc_free(w);
    return result;
  }

  w->block_size = block_size;
  w->features = features;
  bfc_uuid_generate(w->uuid);
  w->current_offset = BFC_HEADER_SIZE;

  // Initialize compression settings
  w->compression_type = BFC_COMP_NONE; // Default to no compression
  w->compression_level = 3;            // Default compression level
  w->compression_threshold = 64;       // Don't compress files smaller than 64 bytes

  // If ZSTD features are enabled, use ZSTD compression by default
  if (features & BFC_FEATURE_ZSTD) {
    if (bfc_compress_is_supported(BFC_COMP_ZSTD)) {
      w->compression_type = BFC_COMP_ZSTD;
    }
  }

  // Initialize encryption settings
  w->encryption_type = BFC_ENC_NONE;
  w->has_encryption_key = 0;
  memset(w->encryption_key, 0, sizeof(w->encryption_key));
  memset(w->encryption_salt, 0, sizeof(w->encryption_salt));
  memset(&w->master_key, 0, sizeof(w->master_key));

  // Write header
  struct bfc_header hdr = {0};
  memcpy(hdr.magic, BFC_MAGIC, BFC_MAGIC_SIZE);
  hdr.block_size = block_size;
  hdr.features = features;
  memcpy(hdr.uuid, w->uuid, 16);

  uint8_t header_buf[BFC_HEADER_SIZE];
  result = bfc_header_serialize(&hdr, header_buf);
  if (result != BFC_OK) {
    bfc_array_destroy(&w->paths);
    bfc_array_destroy(&w->index);
    bfc_os_close(w->file);
    bfc_free(w->filename);
    bfc_free(w);
    return result;
  }

  if (fwrite(header_buf, 1, BFC_HEADER_SIZE, w->file) != BFC_HEADER_SIZE) {
    bfc_array_destroy(&w->paths);
    bfc_array_destroy(&w->index);
    bfc_os_close(w->file);
    bfc_free(w->filename);
    bfc_free(w);
    return BFC_E_IO;
  }

  *out = w;
  return BFC_OK;
}

int bfc_add_file(bfc_t* w, const char* container_path, FILE* src, uint32_t mode, uint64_t mtime_ns,
                 uint32_t* out_crc) {
  if (!w || !container_path || !src || w->finished) {
    return BFC_E_INVAL;
  }

  // Normalize path
  char* norm_path;
  int result = bfc_path_normalize(container_path, &norm_path);
  if (result != BFC_OK) {
    return result;
  }

  uint64_t obj_start = w->current_offset;

  // Create object header
  struct bfc_obj_hdr obj_hdr = {
      .type = BFC_TYPE_FILE,
      .comp = BFC_COMP_NONE,
      .enc = BFC_ENC_NONE,
      .reserved = 0,
      .name_len = (uint16_t) strlen(norm_path),
      .padding = 0,
      .mode = mode | S_IFREG, // Add file type bits
      .mtime_ns = mtime_ns,
      .orig_size = 0, // Will be filled later
      .enc_size = 0,  // Will be filled later
      .crc32c = 0     // Will be filled later
  };

  // Write object header (placeholder)
  if (fwrite(&obj_hdr, 1, sizeof(obj_hdr), w->file) != sizeof(obj_hdr)) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write path
  if (fwrite(norm_path, 1, obj_hdr.name_len, w->file) != obj_hdr.name_len) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write padding to 16-byte boundary
  size_t hdr_name_size = sizeof(obj_hdr) + obj_hdr.name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);
  if (padding > 0) {
    uint8_t pad[BFC_ALIGN] = {0};
    if (fwrite(pad, 1, padding, w->file) != padding) {
      bfc_path_free(norm_path);
      return BFC_E_IO;
    }
  }

  // First pass: read entire file to determine size and compression strategy
  long src_pos = ftell(src);
  if (src_pos < 0) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  fseek(src, 0, SEEK_END);
  long file_size = ftell(src);
  fseek(src, src_pos, SEEK_SET);

  if (file_size < 0) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Decide on compression type
  uint8_t use_compression = w->compression_type;
  if (use_compression != BFC_COMP_NONE && (size_t) file_size < w->compression_threshold) {
    use_compression = BFC_COMP_NONE; // File too small to compress
  }

  // Read sample for compression recommendation if using auto-detect
  uint8_t sample_buffer[512];
  size_t sample_size = 0;
  if (use_compression != BFC_COMP_NONE && file_size > 0) {
    sample_size = fread(sample_buffer, 1, sizeof(sample_buffer), src);
    fseek(src, src_pos, SEEK_SET);

    // Get recommendation and override if needed
    uint8_t recommended = bfc_compress_recommend((size_t) file_size, sample_buffer, sample_size);
    if (w->compression_type == BFC_COMP_NONE) {
      use_compression = recommended;
    }
  }

  // Decide on encryption type
  uint8_t use_encryption = w->encryption_type;
  if (use_encryption != BFC_ENC_NONE && !w->has_encryption_key) {
    use_encryption = BFC_ENC_NONE; // No key available
  }

  obj_hdr.comp = use_compression;
  obj_hdr.enc = use_encryption;

  // Process file content: read -> compress -> encrypt -> write
  bfc_crc32c_ctx_t crc_ctx;
  bfc_crc32c_reset(&crc_ctx);

  uint64_t total_bytes = 0;
  uint64_t encoded_bytes = 0;

  // Step 1: Read entire file into memory
  void* file_data = malloc((size_t) file_size);
  if (!file_data) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  size_t actual_read = fread(file_data, 1, (size_t) file_size, src);
  if (actual_read != (size_t) file_size) {
    free(file_data);
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Calculate CRC of original data
  bfc_crc32c_update(&crc_ctx, file_data, actual_read);
  total_bytes = actual_read;

  void* current_data = file_data;
  size_t current_size = actual_read;
  int needs_free_current = 0;

  // Step 2: Compress if needed
  if (use_compression != BFC_COMP_NONE) {
    bfc_compress_result_t compress_result =
        bfc_compress_data(use_compression, current_data, current_size, w->compression_level);

    if (compress_result.error != BFC_OK) {
      free(file_data);
      bfc_path_free(norm_path);
      return compress_result.error;
    }

    // Check if compression actually helped
    if (compress_result.compressed_size >= current_size) {
      // Compression didn't help, fall back to uncompressed
      free(compress_result.data);
      obj_hdr.comp = BFC_COMP_NONE;
      use_compression = BFC_COMP_NONE;
    } else {
      // Compression helped, use compressed data
      current_data = compress_result.data;
      current_size = compress_result.compressed_size;
      needs_free_current = 1;
    }
  }

  // Step 3: Encrypt if needed
  if (use_encryption != BFC_ENC_NONE) {
    // Use the master key directly (no need to re-derive)
    bfc_encrypt_key_t* encrypt_key = &w->master_key;

    // Create associated data (file path for additional authentication)
    bfc_encrypt_result_t encrypt_result =
        bfc_encrypt_data(encrypt_key, current_data, current_size, norm_path, strlen(norm_path));

    if (encrypt_result.error != BFC_OK) {
      if (needs_free_current)
        free(current_data);
      free(file_data);
      bfc_path_free(norm_path);
      return encrypt_result.error;
    }

    // Switch to encrypted data
    if (needs_free_current)
      free(current_data);
    current_data = encrypt_result.data;
    current_size = encrypt_result.encrypted_size;
    needs_free_current = 1;
  }

  // Step 4: Write final data to container
  if (fwrite(current_data, 1, current_size, w->file) != current_size) {
    if (needs_free_current)
      free(current_data);
    free(file_data);
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  encoded_bytes = current_size;

  // Cleanup
  if (needs_free_current)
    free(current_data);
  free(file_data);

  if (ferror(src)) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  uint32_t crc = bfc_crc32c_final(&crc_ctx);
  if (out_crc) {
    *out_crc = crc;
  }

  // Update object header with actual sizes and CRC
  obj_hdr.orig_size = total_bytes;
  obj_hdr.enc_size = encoded_bytes;
  obj_hdr.crc32c = crc;

  long current_pos = ftell(w->file);
  if (current_pos < 0) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  if (fseek(w->file, (long) obj_start, SEEK_SET) != 0) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  if (fwrite(&obj_hdr, 1, sizeof(obj_hdr), w->file) != sizeof(obj_hdr)) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  if (fseek(w->file, current_pos, SEEK_SET) != 0) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Add to index
  uint64_t obj_size = (uint64_t) current_pos - obj_start;
  result = add_path_to_index(w, norm_path, obj_start, obj_size, mode | S_IFREG, mtime_ns,
                             obj_hdr.comp, obj_hdr.enc, total_bytes, crc);

  if (result == BFC_OK) {
    w->current_offset = (uint64_t) current_pos;
  }

  bfc_path_free(norm_path);
  return result;
}

int bfc_add_dir(bfc_t* w, const char* container_dir, uint32_t mode, uint64_t mtime_ns) {
  if (!w || !container_dir || w->finished) {
    return BFC_E_INVAL;
  }

  // Normalize path
  char* norm_path;
  int result = bfc_path_normalize(container_dir, &norm_path);
  if (result != BFC_OK) {
    return result;
  }

  uint64_t obj_start = w->current_offset;

  // Create object header for directory
  struct bfc_obj_hdr obj_hdr = {.type = BFC_TYPE_DIR,
                                .comp = BFC_COMP_NONE,
                                .name_len = (uint16_t) strlen(norm_path),
                                .mode = mode | S_IFDIR, // Add directory type bits
                                .mtime_ns = mtime_ns,
                                .orig_size = 0,
                                .enc_size = 0,
                                .crc32c = 0};

  // Write object header
  if (fwrite(&obj_hdr, 1, sizeof(obj_hdr), w->file) != sizeof(obj_hdr)) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write path
  if (fwrite(norm_path, 1, obj_hdr.name_len, w->file) != obj_hdr.name_len) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write padding to 16-byte boundary
  size_t hdr_name_size = sizeof(obj_hdr) + obj_hdr.name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);
  if (padding > 0) {
    uint8_t pad[BFC_ALIGN] = {0};
    if (fwrite(pad, 1, padding, w->file) != padding) {
      bfc_path_free(norm_path);
      return BFC_E_IO;
    }
  }

  uint64_t obj_size = sizeof(obj_hdr) + obj_hdr.name_len + padding;

  // Add to index
  result = add_path_to_index(w, norm_path, obj_start, obj_size, mode | S_IFDIR, mtime_ns,
                             BFC_COMP_NONE, BFC_ENC_NONE, 0, 0);

  if (result == BFC_OK) {
    w->current_offset = obj_start + obj_size;
  }

  bfc_path_free(norm_path);
  return result;
}

int bfc_add_symlink(bfc_t* w, const char* container_path, const char* link_target, uint32_t mode, uint64_t mtime_ns) {
  if (!w || !container_path || !link_target || w->finished) {
    return BFC_E_INVAL;
  }

  // Normalize path
  char* norm_path;
  int result = bfc_path_normalize(container_path, &norm_path);
  if (result != BFC_OK) {
    return result;
  }

  uint64_t obj_start = w->current_offset;
  size_t target_len = strlen(link_target);

  // Create object header for symlink
  struct bfc_obj_hdr obj_hdr = {.type = BFC_TYPE_SYMLINK,
                                .comp = BFC_COMP_NONE,
                                .enc = BFC_ENC_NONE,
                                .reserved = 0,
                                .name_len = (uint16_t) strlen(norm_path),
                                .padding = 0,
                                .mode = mode | S_IFLNK, // Add symlink type bits
                                .mtime_ns = mtime_ns,
                                .orig_size = target_len,
                                .enc_size = target_len,
                                .crc32c = 0}; // Will be calculated below

  // Calculate CRC32C of link target
  uint32_t crc = bfc_crc32c_compute(link_target, target_len);
  obj_hdr.crc32c = crc;

  // Write object header
  if (fwrite(&obj_hdr, 1, sizeof(obj_hdr), w->file) != sizeof(obj_hdr)) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write path
  if (fwrite(norm_path, 1, obj_hdr.name_len, w->file) != obj_hdr.name_len) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write padding after path to 16-byte boundary
  size_t hdr_name_size = sizeof(obj_hdr) + obj_hdr.name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);
  if (padding > 0) {
    uint8_t pad[BFC_ALIGN] = {0};
    if (fwrite(pad, 1, padding, w->file) != padding) {
      bfc_path_free(norm_path);
      return BFC_E_IO;
    }
  }

  // Write link target data
  if (fwrite(link_target, 1, target_len, w->file) != target_len) {
    bfc_path_free(norm_path);
    return BFC_E_IO;
  }

  // Write padding after target to 16-byte boundary
  size_t target_padding = bfc_padding_size(target_len, BFC_ALIGN);
  if (target_padding > 0) {
    uint8_t pad[BFC_ALIGN] = {0};
    if (fwrite(pad, 1, target_padding, w->file) != target_padding) {
      bfc_path_free(norm_path);
      return BFC_E_IO;
    }
  }

  uint64_t obj_size = sizeof(obj_hdr) + obj_hdr.name_len + padding + target_len + target_padding;

  // Add to index
  result = add_path_to_index(w, norm_path, obj_start, obj_size, mode | S_IFLNK, mtime_ns,
                             BFC_COMP_NONE, BFC_ENC_NONE, target_len, crc);

  if (result == BFC_OK) {
    w->current_offset = obj_start + obj_size;
  }

  bfc_path_free(norm_path);
  return result;
}

static int index_entry_compare(const void* a, const void* b) {
  const bfc_index_entry_t* ea = (const bfc_index_entry_t*) a;
  const bfc_index_entry_t* eb = (const bfc_index_entry_t*) b;
  return bfc_strcmp(ea->path, eb->path);
}

int bfc_finish(bfc_t* w) {
  if (!w || w->finished) {
    return BFC_E_INVAL;
  }

  uint64_t index_offset = w->current_offset;

  // Sort index by path
  if (bfc_array_size(&w->index) > 1) {
    qsort(w->index.data, bfc_array_size(&w->index), sizeof(bfc_index_entry_t), index_entry_compare);
  }

  // Write index header
  struct bfc_index_hdr idx_hdr = {.version = 1, .count = (uint32_t) bfc_array_size(&w->index)};

  if (fwrite(&idx_hdr, 1, sizeof(idx_hdr), w->file) != sizeof(idx_hdr)) {
    return BFC_E_IO;
  }

  // Write index entries
  for (size_t i = 0; i < bfc_array_size(&w->index); i++) {
    bfc_index_entry_t* entry = bfc_array_get(&w->index, i);

    uint32_t path_len = (uint32_t) strlen(entry->path);
    if (fwrite(&path_len, 1, sizeof(path_len), w->file) != sizeof(path_len)) {
      return BFC_E_IO;
    }

    if (fwrite(entry->path, 1, path_len, w->file) != path_len) {
      return BFC_E_IO;
    }

    uint8_t entry_data[8 + 8 + 4 + 8 + 4 + 4 + 8 + 4];
    bfc_write_le64(entry_data, entry->obj_offset);
    bfc_write_le64(entry_data + 8, entry->obj_size);
    bfc_write_le32(entry_data + 16, entry->mode);
    bfc_write_le64(entry_data + 20, entry->mtime_ns);
    bfc_write_le32(entry_data + 28, entry->comp);
    bfc_write_le32(entry_data + 32, entry->enc);
    bfc_write_le64(entry_data + 36, entry->orig_size);
    bfc_write_le32(entry_data + 44, entry->crc32c);

    if (fwrite(entry_data, 1, sizeof(entry_data), w->file) != sizeof(entry_data)) {
      return BFC_E_IO;
    }
  }

  long index_end_pos = ftell(w->file);
  if (index_end_pos < 0) {
    return BFC_E_IO;
  }
  uint64_t index_end = (uint64_t) index_end_pos;
  uint64_t index_size = index_end - index_offset;

  // Calculate index CRC
  if (fseek(w->file, (long) index_offset, SEEK_SET) != 0) {
    return BFC_E_IO;
  }

  bfc_crc32c_ctx_t crc_ctx;
  bfc_crc32c_reset(&crc_ctx);

  uint8_t buffer[WRITE_BUFFER_SIZE];
  uint64_t remaining = index_size;

  while (remaining > 0) {
    size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
    size_t bytes_read = fread(buffer, 1, chunk, w->file);
    if (bytes_read != chunk) {
      return BFC_E_IO;
    }
    bfc_crc32c_update(&crc_ctx, buffer, chunk);
    remaining -= chunk;
  }

  uint32_t index_crc = bfc_crc32c_final(&crc_ctx);

  // Seek to end
  if (fseek(w->file, (long) index_end, SEEK_SET) != 0) {
    return BFC_E_IO;
  }

  // Write footer
  struct bfc_footer footer = {0};
  memcpy(footer.tag, BFC_IDX_TAG, 8);
  footer.index_size = index_size;
  footer.index_crc32 = index_crc;
  footer.index_offset = index_offset;
  footer.container_crc = 0; // Reserved
  memcpy(footer.end, BFC_END_TAG, 8);

  uint8_t footer_buf[BFC_FOOTER_SIZE];
  int result = bfc_footer_serialize(&footer, footer_buf);
  if (result != BFC_OK) {
    return result;
  }

  if (fwrite(footer_buf, 1, BFC_FOOTER_SIZE, w->file) != BFC_FOOTER_SIZE) {
    return BFC_E_IO;
  }

  // Update header with encryption salt if encryption is enabled
  if (w->has_encryption_key) {
    if (fseek(w->file, 0, SEEK_SET) != 0) {
      return BFC_E_IO;
    }

    struct bfc_header hdr = {0};
    memcpy(hdr.magic, BFC_MAGIC, BFC_MAGIC_SIZE);
    hdr.block_size = w->block_size;
    hdr.features = w->features;
    memcpy(hdr.uuid, w->uuid, 16);
    memcpy(hdr.enc_salt, w->encryption_salt, 32);

    uint8_t header_buf[BFC_HEADER_SIZE];
    result = bfc_header_serialize(&hdr, header_buf);
    if (result != BFC_OK) {
      return result;
    }

    if (fwrite(header_buf, 1, BFC_HEADER_SIZE, w->file) != BFC_HEADER_SIZE) {
      return BFC_E_IO;
    }
  }

  // Sync to disk
  result = bfc_os_sync(w->file);
  if (result != BFC_OK) {
    return result;
  }

  w->finished = 1;
  return BFC_OK;
}

void bfc_close(bfc_t* w) {
  if (!w) {
    return;
  }

  if (w->file) {
    bfc_os_close(w->file);
  }

  // Free index entries
  for (size_t i = 0; i < bfc_array_size(&w->index); i++) {
    bfc_index_entry_t* entry = bfc_array_get(&w->index, i);
    if (entry->path) {
      bfc_free(entry->path);
    }
  }
  bfc_array_destroy(&w->index);

  // Free path tracking (paths are already freed in index cleanup, just destroy array)
  bfc_array_destroy(&w->paths);

  if (w->filename) {
    bfc_free(w->filename);
  }

  // Clear master encryption key
  bfc_encrypt_key_clear(&w->master_key);

  bfc_free(w);
}

/* --- Compression Configuration Functions --- */

int bfc_set_compression(bfc_t* w, uint8_t comp_type, int level) {
  if (!w) {
    return BFC_E_INVAL;
  }

  if (w->finished) {
    return BFC_E_INVAL;
  }

  if (!bfc_compress_is_supported(comp_type)) {
    return BFC_E_INVAL;
  }

  // Validate compression level
  if (level < 0)
    level = 0; // Use default
  if (comp_type == BFC_COMP_ZSTD && level > 22)
    level = 22; // Max ZSTD level

  w->compression_type = comp_type;
  w->compression_level = level;

  // Update features flag if using ZSTD
  if (comp_type == BFC_COMP_ZSTD) {
    w->features |= BFC_FEATURE_ZSTD;
  }

  return BFC_OK;
}

int bfc_set_compression_threshold(bfc_t* w, size_t min_bytes) {
  if (!w) {
    return BFC_E_INVAL;
  }

  if (w->finished) {
    return BFC_E_INVAL;
  }

  w->compression_threshold = min_bytes;
  return BFC_OK;
}

uint8_t bfc_get_compression(bfc_t* w) {
  if (!w) {
    return BFC_COMP_NONE;
  }

  return w->compression_type;
}

/* --- Encryption Configuration Functions --- */

int bfc_set_encryption_password(bfc_t* w, const char* password, size_t password_len) {
  if (!w || !password || password_len == 0) {
    return BFC_E_INVAL;
  }

  if (w->finished) {
    return BFC_E_INVAL;
  }

  // Clear previous key
  memset(w->encryption_key, 0, sizeof(w->encryption_key));
  memset(w->encryption_salt, 0, sizeof(w->encryption_salt));
  bfc_encrypt_key_clear(&w->master_key);

  // Create master encryption key structure
  int result = bfc_encrypt_key_from_password(password, password_len, NULL, &w->master_key);
  if (result != BFC_OK) {
    return result;
  }

  // Store key and salt for header
  memcpy(w->encryption_key, w->master_key.key, sizeof(w->encryption_key));
  memcpy(w->encryption_salt, w->master_key.salt, sizeof(w->encryption_salt));

  w->encryption_type = BFC_ENC_CHACHA20_POLY1305;
  w->has_encryption_key = 1;

  // Enable AEAD feature
  w->features |= BFC_FEATURE_AEAD;

  return BFC_OK;
}

int bfc_set_encryption_key(bfc_t* w, const uint8_t key[32]) {
  if (!w || !key) {
    return BFC_E_INVAL;
  }

  if (w->finished) {
    return BFC_E_INVAL;
  }

#ifndef BFC_WITH_SODIUM
  (void) key;
  return BFC_E_INVAL; // Encryption not supported
#else
  // Clear previous key and salt
  memset(w->encryption_key, 0, sizeof(w->encryption_key));
  memset(w->encryption_salt, 0, sizeof(w->encryption_salt));
  bfc_encrypt_key_clear(&w->master_key);

  // Create master encryption key structure from raw key
  int result = bfc_encrypt_key_from_bytes(key, &w->master_key);
  if (result != BFC_OK) {
    return result;
  }

  // Store key for encryption operations
  memcpy(w->encryption_key, key, 32);

  w->encryption_type = BFC_ENC_CHACHA20_POLY1305;
  w->has_encryption_key = 1;

  // Enable AEAD feature
  w->features |= BFC_FEATURE_AEAD;

  return BFC_OK;
#endif
}

int bfc_clear_encryption(bfc_t* w) {
  if (!w) {
    return BFC_E_INVAL;
  }

  if (w->finished) {
    return BFC_E_INVAL;
  }

  // Clear encryption settings
  w->encryption_type = BFC_ENC_NONE;
  w->has_encryption_key = 0;

#ifdef BFC_WITH_SODIUM
  sodium_memzero(w->encryption_key, sizeof(w->encryption_key));
  sodium_memzero(w->encryption_salt, sizeof(w->encryption_salt));
#else
  // Fallback without libsodium
  volatile uint8_t* key_p = (volatile uint8_t*) w->encryption_key;
  volatile uint8_t* salt_p = (volatile uint8_t*) w->encryption_salt;
  for (size_t i = 0; i < sizeof(w->encryption_key); i++) {
    key_p[i] = 0;
  }
  for (size_t i = 0; i < sizeof(w->encryption_salt); i++) {
    salt_p[i] = 0;
  }
#endif

  // Disable AEAD feature (only if not using compression that might need it)
  w->features &= ~BFC_FEATURE_AEAD;

  return BFC_OK;
}

uint8_t bfc_get_encryption(bfc_t* w) {
  if (!w) {
    return BFC_ENC_NONE;
  }

  return w->encryption_type;
}