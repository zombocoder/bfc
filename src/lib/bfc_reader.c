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
#include "bfc_format.h"
#include "bfc_os.h"
#include "bfc_util.h"
#include <bfc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define READ_BUFFER_SIZE 65536

// Reader-specific index entry
typedef struct {
  char* path;
  uint64_t obj_offset;
  uint64_t obj_size;
  uint32_t mode;
  uint64_t mtime_ns;
  uint32_t comp;
  uint64_t orig_size;
  uint32_t crc32c;
} bfc_reader_entry_t;

// Reader context (reuse bfc_t structure)
struct bfc {
  FILE* file;
  char* filename;

  // Header info
  struct bfc_header header;

  // Index data
  bfc_reader_entry_t* entries;
  uint32_t entry_count;
  void* index_mmap;
  size_t index_size;

  // File size
  uint64_t file_size;
};

static int compare_entries_by_path(const void* a, const void* b) {
  const bfc_reader_entry_t* ea = (const bfc_reader_entry_t*) a;
  const bfc_reader_entry_t* eb = (const bfc_reader_entry_t*) b;
  return strcmp(ea->path, eb->path);
}

static bfc_reader_entry_t* find_entry(bfc_t* r, const char* path) {
  if (!r || !path || !r->entries) {
    return NULL;
  }

  bfc_reader_entry_t key = {.path = (char*) path};
  return bsearch(&key, r->entries, r->entry_count, sizeof(bfc_reader_entry_t),
                 compare_entries_by_path);
}

int bfc_open(const char* filename, bfc_t** out) {
  if (!filename || !out) {
    return BFC_E_INVAL;
  }

  bfc_t* r = bfc_calloc(1, sizeof(bfc_t));
  if (!r) {
    return BFC_E_IO;
  }

  r->filename = bfc_strdup(filename);
  if (!r->filename) {
    bfc_free(r);
    return BFC_E_IO;
  }

  // Open file for reading
  int result = bfc_os_open_read(filename, &r->file);
  if (result != BFC_OK) {
    bfc_free(r->filename);
    bfc_free(r);
    return result;
  }

  // Get file size
  result = bfc_os_get_size(r->file, &r->file_size);
  if (result != BFC_OK) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return result;
  }

  if (r->file_size < BFC_HEADER_SIZE + BFC_FOOTER_SIZE) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_BADMAGIC;
  }

  // Read and validate footer
  struct bfc_footer footer;
  if (bfc_os_seek(r->file, -(int64_t) BFC_FOOTER_SIZE, SEEK_END) != BFC_OK) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_IO;
  }

  uint8_t footer_buf[BFC_FOOTER_SIZE];
  if (fread(footer_buf, 1, BFC_FOOTER_SIZE, r->file) != BFC_FOOTER_SIZE) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_IO;
  }

  result = bfc_footer_deserialize(footer_buf, &footer);
  if (result != BFC_OK) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return result;
  }

  // Validate footer fields
  if (footer.index_offset >= r->file_size || footer.index_size == 0 ||
      footer.index_offset + footer.index_size > r->file_size - BFC_FOOTER_SIZE) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_BADMAGIC;
  }

  // Read index
  if (bfc_os_seek(r->file, (int64_t) footer.index_offset, SEEK_SET) != BFC_OK) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_IO;
  }

  uint8_t* index_data = bfc_malloc(footer.index_size);
  if (!index_data) {
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_IO;
  }

  if (fread(index_data, 1, footer.index_size, r->file) != footer.index_size) {
    bfc_free(index_data);
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_IO;
  }

  // Verify index CRC
  uint32_t calculated_crc = bfc_crc32c_compute(index_data, footer.index_size);
  if (calculated_crc != footer.index_crc32) {
    bfc_free(index_data);
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_CRC;
  }

  // Parse index
  const uint8_t* ptr = index_data;
  const uint8_t* end = index_data + footer.index_size;

  if (ptr + sizeof(struct bfc_index_hdr) > end) {
    bfc_free(index_data);
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_BADMAGIC;
  }

  struct bfc_index_hdr idx_hdr;
  idx_hdr.version = bfc_read_le32(ptr);
  idx_hdr.count = bfc_read_le32(ptr + 4);
  ptr += sizeof(struct bfc_index_hdr);

  if (idx_hdr.version != 1) {
    bfc_free(index_data);
    bfc_os_close(r->file);
    bfc_free(r->filename);
    bfc_free(r);
    return BFC_E_BADMAGIC;
  }

  r->entry_count = idx_hdr.count;
  if (r->entry_count > 0) {
    r->entries = bfc_calloc(r->entry_count, sizeof(bfc_reader_entry_t));
    if (!r->entries) {
      bfc_free(index_data);
      bfc_os_close(r->file);
      bfc_free(r->filename);
      bfc_free(r);
      return BFC_E_IO;
    }

    for (uint32_t i = 0; i < r->entry_count; i++) {
      if (ptr + 4 > end) {
        goto parse_error;
      }

      uint32_t path_len = bfc_read_le32(ptr);
      ptr += 4;

      if (ptr + path_len > end || path_len == 0) {
        goto parse_error;
      }

      r->entries[i].path = bfc_malloc(path_len + 1);
      if (!r->entries[i].path) {
        goto parse_error;
      }

      memcpy(r->entries[i].path, ptr, path_len);
      r->entries[i].path[path_len] = '\0';
      ptr += path_len;

      if (ptr + 44 > end) { // 8+8+4+8+4+8+4 = 44 bytes
        goto parse_error;
      }

      r->entries[i].obj_offset = bfc_read_le64(ptr);
      r->entries[i].obj_size = bfc_read_le64(ptr + 8);
      r->entries[i].mode = bfc_read_le32(ptr + 16);
      r->entries[i].mtime_ns = bfc_read_le64(ptr + 20);
      r->entries[i].comp = bfc_read_le32(ptr + 28);
      r->entries[i].orig_size = bfc_read_le64(ptr + 32);
      r->entries[i].crc32c = bfc_read_le32(ptr + 40);
      ptr += 44;
    }

    // Sort entries by path for binary search
    qsort(r->entries, r->entry_count, sizeof(bfc_reader_entry_t), compare_entries_by_path);
  }

  bfc_free(index_data);

  // Read header for metadata
  if (bfc_os_seek(r->file, 0, SEEK_SET) != BFC_OK) {
    bfc_close_read(r);
    return BFC_E_IO;
  }

  uint8_t header_buf[BFC_HEADER_SIZE];
  if (fread(header_buf, 1, BFC_HEADER_SIZE, r->file) != BFC_HEADER_SIZE) {
    bfc_close_read(r);
    return BFC_E_IO;
  }

  result = bfc_header_deserialize(header_buf, &r->header);
  if (result != BFC_OK) {
    bfc_close_read(r);
    return result;
  }

  *out = r;
  return BFC_OK;

parse_error:
  // Cleanup on parse error
  if (r->entries) {
    for (uint32_t j = 0; j < r->entry_count; j++) {
      if (r->entries[j].path) {
        bfc_free(r->entries[j].path);
      }
    }
    bfc_free(r->entries);
  }
  bfc_free(index_data);
  bfc_os_close(r->file);
  bfc_free(r->filename);
  bfc_free(r);
  return BFC_E_BADMAGIC;
}

void bfc_close_read(bfc_t* r) {
  if (!r) {
    return;
  }

  if (r->file) {
    bfc_os_close(r->file);
  }

  if (r->entries) {
    for (uint32_t i = 0; i < r->entry_count; i++) {
      if (r->entries[i].path) {
        bfc_free(r->entries[i].path);
      }
    }
    bfc_free(r->entries);
  }

  if (r->index_mmap) {
    bfc_os_munmap(r->index_mmap, r->index_size);
  }

  if (r->filename) {
    bfc_free(r->filename);
  }

  bfc_free(r);
}

int bfc_stat(bfc_t* r, const char* container_path, bfc_entry_t* out) {
  if (!r || !container_path || !out) {
    return BFC_E_INVAL;
  }

  char* norm_path;
  int result = bfc_path_normalize(container_path, &norm_path);
  if (result != BFC_OK) {
    return result;
  }

  bfc_reader_entry_t* entry = find_entry(r, norm_path);
  bfc_path_free(norm_path);

  if (!entry) {
    return BFC_E_NOTFOUND;
  }

  out->path = entry->path;
  out->mode = entry->mode;
  out->mtime_ns = entry->mtime_ns;
  out->comp = entry->comp;
  out->size = entry->orig_size;
  out->crc32c = entry->crc32c;
  out->obj_offset = entry->obj_offset;
  out->obj_size = entry->obj_size;

  return BFC_OK;
}

int bfc_list(bfc_t* r, const char* prefix_dir, bfc_list_cb cb, void* user) {
  if (!r || !cb) {
    return BFC_E_INVAL;
  }

  char* norm_prefix = NULL;
  if (prefix_dir && strlen(prefix_dir) > 0) {
    int result = bfc_path_normalize(prefix_dir, &norm_prefix);
    if (result != BFC_OK) {
      return result;
    }
  }

  size_t prefix_len = norm_prefix ? strlen(norm_prefix) : 0;

  for (uint32_t i = 0; i < r->entry_count; i++) {
    const char* entry_path = r->entries[i].path;

    // Check if this entry matches the prefix
    if (norm_prefix) {
      if (strncmp(entry_path, norm_prefix, prefix_len) != 0) {
        continue;
      }
      // Make sure it's a proper directory match
      if (entry_path[prefix_len] != '\0' && entry_path[prefix_len] != '/') {
        continue;
      }
    }

    // Create bfc_entry_t for callback
    bfc_entry_t entry = {.path = r->entries[i].path,
                         .mode = r->entries[i].mode,
                         .mtime_ns = r->entries[i].mtime_ns,
                         .comp = r->entries[i].comp,
                         .size = r->entries[i].orig_size,
                         .crc32c = r->entries[i].crc32c,
                         .obj_offset = r->entries[i].obj_offset,
                         .obj_size = r->entries[i].obj_size};

    int result = cb(&entry, user);
    if (result != 0) {
      break;
    }
  }

  if (norm_prefix) {
    bfc_path_free(norm_prefix);
  }

  return BFC_OK;
}

// Helper function to read and decompress a compressed file
static size_t read_compressed_file(bfc_t* r, bfc_reader_entry_t* entry, uint64_t offset, void* buf,
                                   size_t len) {
  // Calculate content start position
  if (bfc_os_seek(r->file, (int64_t) entry->obj_offset, SEEK_SET) != BFC_OK) {
    return 0;
  }

  struct bfc_obj_hdr obj_hdr;
  if (fread(&obj_hdr, 1, sizeof(obj_hdr), r->file) != sizeof(obj_hdr)) {
    return 0;
  }

  // Skip name and padding to get to content
  uint16_t name_len = obj_hdr.name_len;
  if (fseek(r->file, name_len, SEEK_CUR) != 0) {
    return 0;
  }

  // Align to 16-byte boundary
  size_t hdr_name_size = sizeof(obj_hdr) + name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);
  if (padding > 0 && fseek(r->file, (long) padding, SEEK_CUR) != 0) {
    return 0;
  }

  // Read compressed data
  void* compressed_data = malloc(obj_hdr.enc_size);
  if (!compressed_data) {
    return 0;
  }

  size_t compressed_read = fread(compressed_data, 1, obj_hdr.enc_size, r->file);
  if (compressed_read != obj_hdr.enc_size) {
    free(compressed_data);
    return 0;
  }

  // Decompress the data
  bfc_decompress_result_t decomp_result =
      bfc_decompress_data(entry->comp, compressed_data, obj_hdr.enc_size, obj_hdr.orig_size);

  free(compressed_data);

  if (decomp_result.error != BFC_OK || !decomp_result.data) {
    return 0;
  }

  // Validate decompressed size
  if (decomp_result.decompressed_size != obj_hdr.orig_size) {
    free(decomp_result.data);
    return 0;
  }

  // Validate CRC of decompressed data
  bfc_crc32c_ctx_t crc_ctx;
  bfc_crc32c_reset(&crc_ctx);
  bfc_crc32c_update(&crc_ctx, decomp_result.data, decomp_result.decompressed_size);
  uint32_t calculated_crc = bfc_crc32c_final(&crc_ctx);

  if (calculated_crc != obj_hdr.crc32c) {
    free(decomp_result.data);
    return 0;
  }

  // Copy requested portion to output buffer
  size_t copy_size = len;
  if (offset + copy_size > decomp_result.decompressed_size) {
    copy_size = decomp_result.decompressed_size - offset;
  }

  memcpy(buf, (uint8_t*) decomp_result.data + offset, copy_size);
  free(decomp_result.data);

  return copy_size;
}

size_t bfc_read(bfc_t* r, const char* container_path, uint64_t offset, void* buf, size_t len) {
  if (!r || !container_path || !buf || len == 0) {
    return 0;
  }

  char* norm_path;
  if (bfc_path_normalize(container_path, &norm_path) != BFC_OK) {
    return 0;
  }

  bfc_reader_entry_t* entry = find_entry(r, norm_path);
  bfc_path_free(norm_path);

  if (!entry) {
    return 0;
  }

  // Only read from files, not directories
  if ((entry->mode & S_IFMT) == S_IFDIR) {
    return 0;
  }

  // Check bounds
  if (offset >= entry->orig_size) {
    return 0;
  }

  size_t to_read = len;
  if (offset + to_read > entry->orig_size) {
    to_read = entry->orig_size - offset;
  }

  // Handle compressed files
  if (entry->comp != BFC_COMP_NONE) {
    if (!bfc_compress_is_supported(entry->comp)) {
      return 0; // Unsupported compression type
    }

    // For compressed files, we need to decompress the entire file
    // and then return the requested portion
    return read_compressed_file(r, entry, offset, buf, to_read);
  }

  // Calculate file position
  // Find content start by parsing object header
  if (bfc_os_seek(r->file, (int64_t) entry->obj_offset, SEEK_SET) != BFC_OK) {
    return 0;
  }

  struct bfc_obj_hdr obj_hdr;
  if (fread(&obj_hdr, 1, sizeof(obj_hdr), r->file) != sizeof(obj_hdr)) {
    return 0;
  }

  // Skip name and padding
  uint16_t name_len = obj_hdr.name_len;
  size_t hdr_name_size = sizeof(obj_hdr) + name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);

  uint64_t content_offset = entry->obj_offset + hdr_name_size + padding + offset;

  if (bfc_os_seek(r->file, (int64_t) content_offset, SEEK_SET) != BFC_OK) {
    return 0;
  }

  return fread(buf, 1, to_read, r->file);
}

int bfc_extract_to_fd(bfc_t* r, const char* container_path, int out_fd) {
  if (!r || !container_path || out_fd < 0) {
    return BFC_E_INVAL;
  }

  char* norm_path;
  int result = bfc_path_normalize(container_path, &norm_path);
  if (result != BFC_OK) {
    return result;
  }

  bfc_reader_entry_t* entry = find_entry(r, norm_path);
  bfc_path_free(norm_path);

  if (!entry) {
    return BFC_E_NOTFOUND;
  }

  // Only extract files
  if ((entry->mode & S_IFMT) != S_IFREG) {
    return BFC_E_INVAL;
  }

  // Calculate content start
  if (bfc_os_seek(r->file, (int64_t) entry->obj_offset, SEEK_SET) != BFC_OK) {
    return BFC_E_IO;
  }

  struct bfc_obj_hdr obj_hdr;
  if (fread(&obj_hdr, 1, sizeof(obj_hdr), r->file) != sizeof(obj_hdr)) {
    return BFC_E_IO;
  }

  // Skip name and padding to get to content
  uint16_t name_len = obj_hdr.name_len;
  size_t hdr_name_size = sizeof(obj_hdr) + name_len;
  size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);

  if (fseek(r->file, name_len + padding, SEEK_CUR) != 0) {
    return BFC_E_IO;
  }

  // Handle compressed vs uncompressed files
  if (entry->comp != BFC_COMP_NONE) {
    // Compressed file - decompress and write
    if (!bfc_compress_is_supported(entry->comp)) {
      return BFC_E_INVAL;
    }

    // Read all compressed data
    void* compressed_data = malloc(obj_hdr.enc_size);
    if (!compressed_data) {
      return BFC_E_IO;
    }

    size_t compressed_read = fread(compressed_data, 1, obj_hdr.enc_size, r->file);
    if (compressed_read != obj_hdr.enc_size) {
      free(compressed_data);
      return BFC_E_IO;
    }

    // Decompress
    bfc_decompress_result_t decomp_result =
        bfc_decompress_data(entry->comp, compressed_data, obj_hdr.enc_size, obj_hdr.orig_size);
    free(compressed_data);

    if (decomp_result.error != BFC_OK || !decomp_result.data) {
      return BFC_E_IO;
    }

    // Validate decompressed size
    if (decomp_result.decompressed_size != obj_hdr.orig_size) {
      free(decomp_result.data);
      return BFC_E_CRC;
    }

    // Validate CRC
    bfc_crc32c_ctx_t crc_ctx;
    bfc_crc32c_reset(&crc_ctx);
    bfc_crc32c_update(&crc_ctx, decomp_result.data, decomp_result.decompressed_size);
    uint32_t calculated_crc = bfc_crc32c_final(&crc_ctx);

    if (calculated_crc != entry->crc32c) {
      free(decomp_result.data);
      return BFC_E_CRC;
    }

    // Write decompressed data to output
    ssize_t written = write(out_fd, decomp_result.data, decomp_result.decompressed_size);
    free(decomp_result.data);

    if (written != (ssize_t) decomp_result.decompressed_size) {
      return BFC_E_IO;
    }
  } else {
    // Uncompressed file - stream directly
    uint8_t buffer[READ_BUFFER_SIZE];
    uint64_t remaining = entry->orig_size;
    bfc_crc32c_ctx_t crc_ctx;
    bfc_crc32c_reset(&crc_ctx);

    while (remaining > 0) {
      size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
      size_t bytes_read = fread(buffer, 1, chunk, r->file);

      if (bytes_read == 0) {
        return BFC_E_IO;
      }

      if (write(out_fd, buffer, bytes_read) != (ssize_t) bytes_read) {
        return BFC_E_IO;
      }

      bfc_crc32c_update(&crc_ctx, buffer, bytes_read);
      remaining -= bytes_read;

      if (bytes_read < chunk) {
        break; // EOF
      }
    }

    // Verify CRC
    uint32_t calculated_crc = bfc_crc32c_final(&crc_ctx);
    if (calculated_crc != entry->crc32c) {
      return BFC_E_CRC;
    }
  }

  return BFC_OK;
}

int bfc_verify(bfc_t* r, int deep) {
  if (!r) {
    return BFC_E_INVAL;
  }

  // Basic verification - check that all entries are valid
  for (uint32_t i = 0; i < r->entry_count; i++) {
    bfc_reader_entry_t* entry = &r->entries[i];

    // Check entry bounds
    if (entry->obj_offset >= r->file_size || entry->obj_offset + entry->obj_size > r->file_size) {
      return BFC_E_BADMAGIC;
    }

    if (deep) {
      // Deep verification - read and verify CRC of each file
      if ((entry->mode & S_IFMT) == S_IFREG) {
        // Verify file content CRC
        if (bfc_os_seek(r->file, (int64_t) entry->obj_offset, SEEK_SET) != BFC_OK) {
          return BFC_E_IO;
        }

        struct bfc_obj_hdr obj_hdr;
        if (fread(&obj_hdr, 1, sizeof(obj_hdr), r->file) != sizeof(obj_hdr)) {
          return BFC_E_IO;
        }

        // Skip to content
        uint16_t name_len = obj_hdr.name_len;
        size_t hdr_name_size = sizeof(obj_hdr) + name_len;
        size_t padding = bfc_padding_size(hdr_name_size, BFC_ALIGN);

        if (fseek(r->file, name_len + padding, SEEK_CUR) != 0) {
          return BFC_E_IO;
        }

        // Read and verify content
        bfc_crc32c_ctx_t crc_ctx;
        bfc_crc32c_reset(&crc_ctx);

        uint8_t buffer[READ_BUFFER_SIZE];
        uint64_t remaining = entry->orig_size;

        while (remaining > 0) {
          size_t chunk = remaining > sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
          size_t bytes_read = fread(buffer, 1, chunk, r->file);

          if (bytes_read == 0) {
            return BFC_E_IO;
          }

          bfc_crc32c_update(&crc_ctx, buffer, bytes_read);
          remaining -= bytes_read;

          if (bytes_read < chunk) {
            break;
          }
        }

        uint32_t calculated_crc = bfc_crc32c_final(&crc_ctx);
        if (calculated_crc != entry->crc32c) {
          return BFC_E_CRC;
        }
      }
    }
  }

  return BFC_OK;
}