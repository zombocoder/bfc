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
#include "bfc_crc32c.h"
#include "bfc_format.h"
#include "bfc_os.h"
#include "bfc_util.h"
#include <bfc.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define WRITE_BUFFER_SIZE 65536

typedef struct bfc_index_entry {
  char* path;
  uint64_t obj_offset;
  uint64_t obj_size;
  uint32_t mode;
  uint64_t mtime_ns;
  uint32_t comp;
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

  // Index entries
  bfc_array_t index;

  // Path tracking for duplicates
  bfc_array_t paths;

  // Current position
  uint64_t current_offset;
};

static int add_path_to_index(bfc_t* w, const char* path, uint64_t obj_offset, uint64_t obj_size,
                             uint32_t mode, uint64_t mtime_ns, uint32_t comp, uint64_t orig_size,
                             uint32_t crc32c) {
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
      .name_len = (uint16_t) strlen(norm_path),
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

  // Stream content and calculate CRC
  bfc_crc32c_ctx_t crc_ctx;
  bfc_crc32c_reset(&crc_ctx);

  uint8_t buffer[WRITE_BUFFER_SIZE];
  uint64_t total_bytes = 0;
  size_t bytes_read;

  while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
    if (fwrite(buffer, 1, bytes_read, w->file) != bytes_read) {
      bfc_path_free(norm_path);
      return BFC_E_IO;
    }

    bfc_crc32c_update(&crc_ctx, buffer, bytes_read);
    total_bytes += bytes_read;
  }

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
  obj_hdr.enc_size = total_bytes;
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
                             BFC_COMP_NONE, total_bytes, crc);

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
                             BFC_COMP_NONE, 0, 0);

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

    uint8_t entry_data[8 + 8 + 4 + 8 + 4 + 8 + 4];
    bfc_write_le64(entry_data, entry->obj_offset);
    bfc_write_le64(entry_data + 8, entry->obj_size);
    bfc_write_le32(entry_data + 16, entry->mode);
    bfc_write_le64(entry_data + 20, entry->mtime_ns);
    bfc_write_le32(entry_data + 28, entry->comp);
    bfc_write_le64(entry_data + 32, entry->orig_size);
    bfc_write_le32(entry_data + 40, entry->crc32c);

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

  bfc_free(w);
}