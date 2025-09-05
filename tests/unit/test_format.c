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
#include <assert.h>
#include <bfc.h>
#include <stdio.h>
#include <string.h>

static int test_endian_conversion(void) {
  uint8_t buf[8];

  // Test 16-bit
  bfc_write_le16(buf, 0x1234);
  assert(buf[0] == 0x34 && buf[1] == 0x12);
  assert(bfc_read_le16(buf) == 0x1234);

  // Test 32-bit
  bfc_write_le32(buf, 0x12345678);
  assert(buf[0] == 0x78 && buf[1] == 0x56 && buf[2] == 0x34 && buf[3] == 0x12);
  assert(bfc_read_le32(buf) == 0x12345678);

  // Test 64-bit
  bfc_write_le64(buf, 0x123456789ABCDEF0ULL);
  assert(buf[0] == 0xF0 && buf[1] == 0xDE && buf[2] == 0xBC && buf[3] == 0x9A);
  assert(buf[4] == 0x78 && buf[5] == 0x56 && buf[6] == 0x34 && buf[7] == 0x12);
  assert(bfc_read_le64(buf) == 0x123456789ABCDEF0ULL);

  return 0;
}

static int test_alignment(void) {
  assert(bfc_align_up(0, 16) == 0);
  assert(bfc_align_up(1, 16) == 16);
  assert(bfc_align_up(15, 16) == 16);
  assert(bfc_align_up(16, 16) == 16);
  assert(bfc_align_up(17, 16) == 32);

  assert(bfc_padding_size(0, 16) == 0);
  assert(bfc_padding_size(1, 16) == 15);
  assert(bfc_padding_size(15, 16) == 1);
  assert(bfc_padding_size(16, 16) == 0);
  assert(bfc_padding_size(17, 16) == 15);

  return 0;
}

static int test_header_serialization(void) {
  struct bfc_header hdr = {0};
  memcpy(hdr.magic, BFC_MAGIC, BFC_MAGIC_SIZE);
  hdr.block_size = 4096;
  hdr.features = BFC_FEATURE_ZSTD;

  // Generate a test UUID
  for (int i = 0; i < 16; i++) {
    hdr.uuid[i] = (uint8_t) i;
  }

  uint8_t buf[BFC_HEADER_SIZE];
  assert(bfc_header_serialize(&hdr, buf) == BFC_OK);

  // Check magic
  assert(memcmp(buf, BFC_MAGIC, BFC_MAGIC_SIZE) == 0);

  // Deserialize and verify
  struct bfc_header hdr2;
  assert(bfc_header_deserialize(buf, &hdr2) == BFC_OK);

  assert(memcmp(hdr2.magic, BFC_MAGIC, BFC_MAGIC_SIZE) == 0);
  assert(hdr2.block_size == 4096);
  assert(hdr2.features == BFC_FEATURE_ZSTD);
  assert(memcmp(hdr2.uuid, hdr.uuid, 16) == 0);

  return 0;
}

static int test_footer_serialization(void) {
  struct bfc_footer footer = {0};
  memcpy(footer.tag, BFC_IDX_TAG, 8);
  footer.index_size = 1234;
  footer.index_crc32 = 0xDEADBEEF;
  footer.index_offset = 5678;
  footer.container_crc = 0;
  memcpy(footer.end, BFC_END_TAG, 8);

  uint8_t buf[BFC_FOOTER_SIZE];
  assert(bfc_footer_serialize(&footer, buf) == BFC_OK);

  // Check tags
  assert(memcmp(buf, BFC_IDX_TAG, 8) == 0);
  assert(memcmp(buf + 48, BFC_END_TAG, 8) == 0);

  // Deserialize and verify
  struct bfc_footer footer2;
  assert(bfc_footer_deserialize(buf, &footer2) == BFC_OK);

  assert(memcmp(footer2.tag, BFC_IDX_TAG, 8) == 0);
  assert(footer2.index_size == 1234);
  assert(footer2.index_crc32 == 0xDEADBEEF);
  assert(footer2.index_offset == 5678);
  assert(footer2.container_crc == 0);
  assert(memcmp(footer2.end, BFC_END_TAG, 8) == 0);

  return 0;
}

static int test_bad_magic(void) {
  uint8_t buf[BFC_HEADER_SIZE] = {0};
  memcpy(buf, "BADMAGIC", 8);

  struct bfc_header hdr;
  assert(bfc_header_deserialize(buf, &hdr) == BFC_E_BADMAGIC);

  return 0;
}

int test_format(void) {
  if (test_endian_conversion() != 0)
    return 1;
  if (test_alignment() != 0)
    return 1;
  if (test_header_serialization() != 0)
    return 1;
  if (test_footer_serialization() != 0)
    return 1;
  if (test_bad_magic() != 0)
    return 1;

  return 0;
}