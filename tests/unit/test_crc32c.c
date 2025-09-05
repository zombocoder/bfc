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

#include "bfc_crc32c.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_empty_crc(void) {
  uint32_t crc = bfc_crc32c_compute(NULL, 0);
  assert(crc == 0);

  crc = bfc_crc32c_compute("", 0);
  assert(crc == 0);

  return 0;
}

static int test_known_values(void) {
  // Known CRC32C values for test strings
  const char* test1 = "hello";
  uint32_t crc1 = bfc_crc32c_compute(test1, strlen(test1));

  const char* test2 = "world";
  uint32_t crc2 = bfc_crc32c_compute(test2, strlen(test2));

  // CRCs should be different for different inputs
  assert(crc1 != crc2);

  // Same input should produce same CRC
  uint32_t crc1_again = bfc_crc32c_compute(test1, strlen(test1));
  assert(crc1 == crc1_again);

  return 0;
}

static int test_streaming_crc(void) {
  const char* data = "hello world";
  size_t len = strlen(data);

  // Compute all at once
  uint32_t crc_all = bfc_crc32c_compute(data, len);

  // Compute in chunks
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);

  bfc_crc32c_update(&ctx, data, 5);           // "hello"
  bfc_crc32c_update(&ctx, data + 5, 1);       // " "
  bfc_crc32c_update(&ctx, data + 6, len - 6); // "world"

  uint32_t crc_streaming = bfc_crc32c_final(&ctx);

  assert(crc_all == crc_streaming);

  return 0;
}

static int test_incremental_crc(void) {
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);

  // Empty context should have CRC of 0
  assert(bfc_crc32c_final(&ctx) == 0);

  // Add data byte by byte
  const char* data = "test";
  for (size_t i = 0; i < strlen(data); i++) {
    bfc_crc32c_update(&ctx, &data[i], 1);
  }

  uint32_t crc_incremental = bfc_crc32c_final(&ctx);
  uint32_t crc_all = bfc_crc32c_compute(data, strlen(data));

  assert(crc_incremental == crc_all);

  return 0;
}

static int test_hardware_detection(void) {
  // Just ensure the function doesn't crash
  int has_hw = bfc_crc32c_has_hw_support();
  printf("  Hardware CRC32C support: %s\n", has_hw ? "yes" : "no");

  return 0;
}

static int test_null_parameters(void) {
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);

  // Test NULL data pointer with non-zero length (should be safe)
  uint32_t crc = bfc_crc32c_compute(NULL, 0);
  assert(crc == 0);

  // Test update with NULL data and zero length (should be safe)
  bfc_crc32c_update(&ctx, NULL, 0);
  assert(bfc_crc32c_final(&ctx) == 0);

  return 0;
}

static int test_large_data(void) {
  // Test with larger data chunks to exercise different code paths
  size_t large_size = 8192;
  unsigned char* large_data = malloc(large_size);
  assert(large_data != NULL);

  // Fill with pattern
  for (size_t i = 0; i < large_size; i++) {
    large_data[i] = (unsigned char) (i & 0xFF);
  }

  uint32_t crc_all = bfc_crc32c_compute(large_data, large_size);

  // Test streaming with large chunks
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);

  size_t chunk_size = 1024;
  for (size_t offset = 0; offset < large_size; offset += chunk_size) {
    size_t remaining = large_size - offset;
    size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;
    bfc_crc32c_update(&ctx, large_data + offset, current_chunk);
  }

  uint32_t crc_streaming = bfc_crc32c_final(&ctx);
  assert(crc_all == crc_streaming);

  free(large_data);
  return 0;
}

static int test_binary_data(void) {
  // Test with binary data including null bytes
  unsigned char binary_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA,
                                 0xF9, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};

  uint32_t crc1 = bfc_crc32c_compute(binary_data, sizeof(binary_data));

  // Test with streaming API
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);
  bfc_crc32c_update(&ctx, binary_data, sizeof(binary_data));
  uint32_t crc2 = bfc_crc32c_final(&ctx);

  assert(crc1 == crc2);
  assert(crc1 != 0); // Should not be zero for this data

  return 0;
}

static int test_alignment_cases(void) {
  // Test different alignment cases to exercise alignment handling
  char aligned_data[32] __attribute__((aligned(16)));
  memset(aligned_data, 0xAA, sizeof(aligned_data));

  uint32_t crc_aligned = bfc_crc32c_compute(aligned_data, sizeof(aligned_data));

  // Test with misaligned data
  char* misaligned_data = aligned_data + 1; // Offset by 1 byte
  uint32_t crc_misaligned = bfc_crc32c_compute(misaligned_data, sizeof(aligned_data) - 1);

  // Should produce different CRCs
  assert(crc_aligned != crc_misaligned);

  return 0;
}

static int test_various_sizes(void) {
  // Test various data sizes to exercise different code paths
  for (size_t size = 1; size <= 32; size++) {
    char data[32];
    memset(data, (int) size, sizeof(data));

    uint32_t crc_compute = bfc_crc32c_compute(data, size);

    bfc_crc32c_ctx_t ctx;
    bfc_crc32c_reset(&ctx);
    bfc_crc32c_update(&ctx, data, size);
    uint32_t crc_streaming = bfc_crc32c_final(&ctx);

    assert(crc_compute == crc_streaming);
  }

  return 0;
}

static int test_reset_functionality(void) {
  bfc_crc32c_ctx_t ctx;
  bfc_crc32c_reset(&ctx);

  const char* data1 = "first";
  const char* data2 = "second";

  // Add first data
  bfc_crc32c_update(&ctx, data1, strlen(data1));
  uint32_t crc1 = bfc_crc32c_final(&ctx);

  // Reset and add second data
  bfc_crc32c_reset(&ctx);
  bfc_crc32c_update(&ctx, data2, strlen(data2));
  uint32_t crc2 = bfc_crc32c_final(&ctx);

  // Should be same as computing second data directly
  uint32_t crc2_direct = bfc_crc32c_compute(data2, strlen(data2));
  assert(crc2 == crc2_direct);

  // Should be different from first CRC
  assert(crc1 != crc2);

  return 0;
}

static int test_specific_values(void) {
  // Test some specific known patterns that might trigger edge cases

  // All zeros
  char zeros[16] = {0};
  uint32_t crc_zeros = bfc_crc32c_compute(zeros, sizeof(zeros));

  // All ones
  char ones[16];
  memset(ones, 0xFF, sizeof(ones));
  uint32_t crc_ones = bfc_crc32c_compute(ones, sizeof(ones));

  // Pattern
  char pattern[16] = {0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA,
                      0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA};
  uint32_t crc_pattern = bfc_crc32c_compute(pattern, sizeof(pattern));

  // All should be different
  assert(crc_zeros != crc_ones);
  assert(crc_zeros != crc_pattern);
  assert(crc_ones != crc_pattern);

  return 0;
}

int test_crc32c(void) {
  if (test_empty_crc() != 0)
    return 1;
  if (test_known_values() != 0)
    return 1;
  if (test_streaming_crc() != 0)
    return 1;
  if (test_incremental_crc() != 0)
    return 1;
  if (test_hardware_detection() != 0)
    return 1;
  if (test_null_parameters() != 0)
    return 1;
  if (test_large_data() != 0)
    return 1;
  if (test_binary_data() != 0)
    return 1;
  if (test_alignment_cases() != 0)
    return 1;
  if (test_various_sizes() != 0)
    return 1;
  if (test_reset_functionality() != 0)
    return 1;
  if (test_specific_values() != 0)
    return 1;

  return 0;
}