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

#include "bfc_format.h"
#include "bfc_crc32c.h"
#include <bfc.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#endif

int bfc_path_normalize(const char* path, char** normalized) {
  if (!path || !normalized) {
    return BFC_E_INVAL;
  }

  size_t len = strlen(path);
  if (len == 0 || len > UINT16_MAX) {
    return BFC_E_INVAL;
  }

  // Reject absolute paths
  if (path[0] == '/') {
    return BFC_E_INVAL;
  }

  char* norm = malloc(len + 1);
  if (!norm) {
    return BFC_E_IO;
  }

  const char* src = path;
  char* dst = norm;

  while (*src) {
    // Skip redundant slashes
    if (*src == '/') {
      if (dst > norm && dst[-1] != '/') {
        *dst++ = '/';
      }
      src++;
      continue;
    }

    // Check for .. components and single dot
    if (*src == '.') {
      if (src[1] == '.' && (src[2] == '/' || src[2] == '\0')) {
        // .. component
        free(norm);
        return BFC_E_INVAL;
      }
      if (src[1] == '\0' || (src[1] == '/' && src == path)) {
        // Single dot at start or standalone
        free(norm);
        return BFC_E_INVAL;
      }
    }

    *dst++ = *src++;
  }

  // Remove trailing slash
  if (dst > norm && dst[-1] == '/') {
    dst--;
  }

  *dst = '\0';

  // Reject empty result
  if (dst == norm) {
    free(norm);
    return BFC_E_INVAL;
  }

  *normalized = norm;
  return BFC_OK;
}

int bfc_path_validate(const char* path) {
  char* norm;
  int result = bfc_path_normalize(path, &norm);
  if (result == BFC_OK) {
    free(norm);
  }
  return result;
}

void bfc_path_free(char* path) { free(path); }

void bfc_uuid_generate(uint8_t uuid[16]) {
#ifdef _WIN32
  BCryptGenRandom(NULL, uuid, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#elif defined(__linux__)
  if (getrandom(uuid, 16, 0) != 16) {
    // Fallback to /dev/urandom if getrandom fails
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
      ssize_t bytes_read = read(fd, uuid, 16);
      close(fd);
      (void) bytes_read; // We don't need to handle partial reads for UUID generation
    }
  }
#else
  // Fallback for macOS and other systems
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    read(fd, uuid, 16);
    close(fd);
  } else {
    // Last resort: use time-based pseudo-random
    srand((unsigned int) time(NULL));
    for (int i = 0; i < 16; i++) {
      uuid[i] = (uint8_t) rand();
    }
  }
#endif

  // Set version 4 (random) and variant bits
  uuid[6] = (uuid[6] & 0x0F) | 0x40; // version 4
  uuid[8] = (uuid[8] & 0x3F) | 0x80; // variant 10
}

void bfc_write_le16(uint8_t* buf, uint16_t val) {
  buf[0] = (uint8_t) (val & 0xFF);
  buf[1] = (uint8_t) ((val >> 8) & 0xFF);
}

void bfc_write_le32(uint8_t* buf, uint32_t val) {
  buf[0] = (uint8_t) (val & 0xFF);
  buf[1] = (uint8_t) ((val >> 8) & 0xFF);
  buf[2] = (uint8_t) ((val >> 16) & 0xFF);
  buf[3] = (uint8_t) ((val >> 24) & 0xFF);
}

void bfc_write_le64(uint8_t* buf, uint64_t val) {
  bfc_write_le32(buf, (uint32_t) (val & 0xFFFFFFFF));
  bfc_write_le32(buf + 4, (uint32_t) ((val >> 32) & 0xFFFFFFFF));
}

uint16_t bfc_read_le16(const uint8_t* buf) { return (uint16_t) buf[0] | ((uint16_t) buf[1] << 8); }

uint32_t bfc_read_le32(const uint8_t* buf) {
  return (uint32_t) buf[0] | ((uint32_t) buf[1] << 8) | ((uint32_t) buf[2] << 16) |
         ((uint32_t) buf[3] << 24);
}

uint64_t bfc_read_le64(const uint8_t* buf) {
  uint32_t lo = bfc_read_le32(buf);
  uint32_t hi = bfc_read_le32(buf + 4);
  return (uint64_t) lo | ((uint64_t) hi << 32);
}

int bfc_header_serialize(const struct bfc_header* hdr, uint8_t buf[BFC_HEADER_SIZE]) {
  if (!hdr || !buf) {
    return BFC_E_INVAL;
  }

  memset(buf, 0, BFC_HEADER_SIZE);

  // Magic
  memcpy(buf, hdr->magic, 8);

  // Skip header_crc32 for now
  bfc_write_le32(buf + 12, hdr->block_size);
  bfc_write_le64(buf + 16, hdr->features);
  memcpy(buf + 24, hdr->uuid, 16);
  memcpy(buf + 40, hdr->enc_salt, 32);

  // Calculate CRC32 of everything after magic
  uint32_t crc = bfc_crc32c_compute(buf + 12, BFC_HEADER_SIZE - 12);
  bfc_write_le32(buf + 8, crc);

  return BFC_OK;
}

int bfc_header_deserialize(const uint8_t buf[BFC_HEADER_SIZE], struct bfc_header* hdr) {
  if (!buf || !hdr) {
    return BFC_E_INVAL;
  }

  // Check magic
  if (memcmp(buf, BFC_MAGIC, BFC_MAGIC_SIZE) != 0) {
    return BFC_E_BADMAGIC;
  }

  memcpy(hdr->magic, buf, 8);
  hdr->header_crc32 = bfc_read_le32(buf + 8);
  hdr->block_size = bfc_read_le32(buf + 12);
  hdr->features = bfc_read_le64(buf + 16);
  memcpy(hdr->uuid, buf + 24, 16);
  memcpy(hdr->enc_salt, buf + 40, 32);
  memset(hdr->reserved, 0, sizeof(hdr->reserved));

  // Verify CRC
  uint32_t expected_crc = bfc_crc32c_compute(buf + 12, BFC_HEADER_SIZE - 12);
  if (hdr->header_crc32 != expected_crc) {
    return BFC_E_CRC;
  }

  return BFC_OK;
}

int bfc_footer_serialize(const struct bfc_footer* footer, uint8_t buf[BFC_FOOTER_SIZE]) {
  if (!footer || !buf) {
    return BFC_E_INVAL;
  }

  memset(buf, 0, BFC_FOOTER_SIZE);

  memcpy(buf, footer->tag, 8);
  bfc_write_le64(buf + 8, footer->index_size);
  bfc_write_le32(buf + 16, footer->index_crc32);
  bfc_write_le64(buf + 20, footer->index_offset);
  bfc_write_le32(buf + 28, footer->container_crc);
  // reserved[16] already zeroed
  memcpy(buf + 48, footer->end, 8);

  return BFC_OK;
}

int bfc_footer_deserialize(const uint8_t buf[BFC_FOOTER_SIZE], struct bfc_footer* footer) {
  if (!buf || !footer) {
    return BFC_E_INVAL;
  }

  // Check tags
  if (memcmp(buf, BFC_IDX_TAG, 8) != 0 || memcmp(buf + 48, BFC_END_TAG, 8) != 0) {
    return BFC_E_BADMAGIC;
  }

  memcpy(footer->tag, buf, 8);
  footer->index_size = bfc_read_le64(buf + 8);
  footer->index_crc32 = bfc_read_le32(buf + 16);
  footer->index_offset = bfc_read_le64(buf + 20);
  footer->container_crc = bfc_read_le32(buf + 28);
  memset(footer->reserved, 0, sizeof(footer->reserved));
  memcpy(footer->end, buf + 48, 8);

  return BFC_OK;
}

size_t bfc_align_up(size_t size, size_t align) { return (size + align - 1) & ~(align - 1); }

size_t bfc_padding_size(size_t size, size_t align) { return bfc_align_up(size, align) - size; }