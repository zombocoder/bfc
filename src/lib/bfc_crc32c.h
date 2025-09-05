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

// CRC32C (Castagnoli) implementation with hardware acceleration support

// Initialize CRC32C module, detects hardware support
void bfc_crc32c_init(void);

// Compute CRC32C of data buffer
uint32_t bfc_crc32c_compute(const void* data, size_t len);

// Streaming CRC32C computation
typedef struct {
  uint32_t crc;
} bfc_crc32c_ctx_t;

void bfc_crc32c_reset(bfc_crc32c_ctx_t* ctx);
void bfc_crc32c_update(bfc_crc32c_ctx_t* ctx, const void* data, size_t len);
uint32_t bfc_crc32c_final(bfc_crc32c_ctx_t* ctx);

// Check if hardware acceleration is available
int bfc_crc32c_has_hw_support(void);