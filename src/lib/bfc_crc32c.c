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
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#include <immintrin.h>
#define HAS_X86_64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#include <arm_acle.h>
#define HAS_ARM64 1
#endif

// CRC32C polynomial: 0x1EDC6F41 (Castagnoli)
#define CRC32C_POLY 0x82F63B78U

// Software lookup table for CRC32C
static uint32_t crc32c_table[256];
static int hw_support = 0;
static int initialized = 0;

static void init_crc32c_table(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t crc = i;
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ CRC32C_POLY;
      } else {
        crc >>= 1;
      }
    }
    crc32c_table[i] = crc;
  }
}

#ifdef HAS_X86_64
static int detect_sse42_support(void) {
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & bit_SSE4_2) != 0;
  }
  return 0;
}

static uint32_t crc32c_hw_x86(uint32_t crc, const void* data, size_t len) {
  const uint8_t* ptr = (const uint8_t*) data;

  // Process aligned 8-byte chunks
  while (len >= 8 && ((uintptr_t) ptr % 8) == 0) {
    uint64_t val;
    memcpy(&val, ptr, 8);
    crc = _mm_crc32_u64(crc, val);
    ptr += 8;
    len -= 8;
  }

  // Process aligned 4-byte chunks
  while (len >= 4 && ((uintptr_t) ptr % 4) == 0) {
    uint32_t val;
    memcpy(&val, ptr, 4);
    crc = _mm_crc32_u32(crc, val);
    ptr += 4;
    len -= 4;
  }

  // Handle unaligned start - process bytes until aligned
  while (len > 0 && ((uintptr_t) ptr % 4) != 0) {
    crc = _mm_crc32_u8(crc, *ptr);
    ptr++;
    len--;
  }

  // Now process remaining 4-byte aligned chunks
  while (len >= 4) {
    uint32_t val;
    memcpy(&val, ptr, 4);
    crc = _mm_crc32_u32(crc, val);
    ptr += 4;
    len -= 4;
  }

  // Process remaining bytes
  while (len > 0) {
    crc = _mm_crc32_u8(crc, *ptr);
    ptr++;
    len--;
  }

  return crc;
}
#endif

#ifdef HAS_ARM64
static int detect_arm_crc_support(void) {
  // On ARM64, CRC instructions are mandatory in ARMv8.1+
  // For simplicity, assume support is available
  return 1;
}

static uint32_t crc32c_hw_arm(uint32_t crc, const void* data, size_t len) {
  const uint8_t* ptr = (const uint8_t*) data;

  // Process 8-byte chunks with proper alignment
  while (len >= 8 && ((uintptr_t) ptr % 8) == 0) {
    uint64_t val;
    memcpy(&val, ptr, 8);
    crc = __crc32cd(crc, val);
    ptr += 8;
    len -= 8;
  }

  // Process 4-byte chunks with proper alignment
  while (len >= 4 && ((uintptr_t) ptr % 4) == 0) {
    uint32_t val;
    memcpy(&val, ptr, 4);
    crc = __crc32cw(crc, val);
    ptr += 4;
    len -= 4;
  }

  // Process 2-byte chunks with proper alignment
  while (len >= 2 && ((uintptr_t) ptr % 2) == 0) {
    uint16_t val;
    memcpy(&val, ptr, 2);
    crc = __crc32ch(crc, val);
    ptr += 2;
    len -= 2;
  }

  // Process remaining bytes
  while (len > 0) {
    crc = __crc32cb(crc, *ptr);
    ptr++;
    len--;
  }

  return crc;
}
#endif

static uint32_t crc32c_sw(uint32_t crc, const void* data, size_t len) {
  const uint8_t* ptr = (const uint8_t*) data;

  crc = ~crc;
  for (size_t i = 0; i < len; i++) {
    crc = crc32c_table[(crc ^ ptr[i]) & 0xFF] ^ (crc >> 8);
  }
  return ~crc;
}

void bfc_crc32c_init(void) {
  if (initialized) {
    return;
  }

  init_crc32c_table();

#ifdef HAS_X86_64
  hw_support = detect_sse42_support();
#elif defined(HAS_ARM64)
  hw_support = detect_arm_crc_support();
#else
  hw_support = 0;
#endif

  initialized = 1;
}

uint32_t bfc_crc32c_compute(const void* data, size_t len) {
  if (!initialized) {
    bfc_crc32c_init();
  }

  if (!data || len == 0) {
    return 0;
  }

  uint32_t crc = 0;

#ifdef HAS_X86_64
  if (hw_support) {
    return crc32c_hw_x86(crc, data, len);
  }
#elif defined(HAS_ARM64)
  if (hw_support) {
    return crc32c_hw_arm(crc, data, len);
  }
#endif

  return crc32c_sw(crc, data, len);
}

void bfc_crc32c_reset(bfc_crc32c_ctx_t* ctx) {
  if (ctx) {
    ctx->crc = 0;
  }
}

void bfc_crc32c_update(bfc_crc32c_ctx_t* ctx, const void* data, size_t len) {
  if (!ctx || !data || len == 0) {
    return;
  }

  if (!initialized) {
    bfc_crc32c_init();
  }

#ifdef HAS_X86_64
  if (hw_support) {
    ctx->crc = crc32c_hw_x86(ctx->crc, data, len);
    return;
  }
#elif defined(HAS_ARM64)
  if (hw_support) {
    ctx->crc = crc32c_hw_arm(ctx->crc, data, len);
    return;
  }
#endif

  ctx->crc = crc32c_sw(ctx->crc, data, len);
}

uint32_t bfc_crc32c_final(bfc_crc32c_ctx_t* ctx) { return ctx ? ctx->crc : 0; }

int bfc_crc32c_has_hw_support(void) {
  if (!initialized) {
    bfc_crc32c_init();
  }
  return hw_support;
}