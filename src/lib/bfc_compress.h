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

#include "bfc_format.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compression context for streaming operations
typedef struct bfc_compress_ctx bfc_compress_ctx_t;

// Compression result structure
typedef struct {
  void* data; // Compressed data (caller must free)
  size_t compressed_size;
  size_t original_size;
  int error; // BFC_OK on success
} bfc_compress_result_t;

// Decompression result structure
typedef struct {
  void* data; // Decompressed data (caller must free)
  size_t decompressed_size;
  int error; // BFC_OK on success
} bfc_decompress_result_t;

/**
 * Check if compression type is supported
 * @param comp_type Compression type (BFC_COMP_*)
 * @return 1 if supported, 0 if not
 */
int bfc_compress_is_supported(uint8_t comp_type);

/**
 * Get recommended compression type based on file size and content
 * @param size File size in bytes
 * @param sample Sample of file content (optional, can be NULL)
 * @param sample_size Size of sample
 * @return Recommended compression type
 */
uint8_t bfc_compress_recommend(size_t size, const void* sample, size_t sample_size);

/**
 * Compress data using specified algorithm
 * @param comp_type Compression type (BFC_COMP_*)
 * @param input Input data
 * @param input_size Input data size
 * @param level Compression level (0=default, 1-22 for ZSTD)
 * @return Compression result (caller must free result.data)
 */
bfc_compress_result_t bfc_compress_data(uint8_t comp_type, const void* input, size_t input_size,
                                        int level);

/**
 * Decompress data using specified algorithm
 * @param comp_type Compression type (BFC_COMP_*)
 * @param input Compressed data
 * @param input_size Compressed data size
 * @param expected_size Expected decompressed size (for validation)
 * @return Decompression result (caller must free result.data)
 */
bfc_decompress_result_t bfc_decompress_data(uint8_t comp_type, const void* input, size_t input_size,
                                            size_t expected_size);

/**
 * Create streaming compression context
 * @param comp_type Compression type
 * @param level Compression level
 * @return Context pointer or NULL on error
 */
bfc_compress_ctx_t* bfc_compress_ctx_create(uint8_t comp_type, int level);

/**
 * Process data through streaming compression
 * @param ctx Compression context
 * @param input Input data
 * @param input_size Input size
 * @param output Output buffer
 * @param output_size Output buffer size
 * @param bytes_consumed Bytes consumed from input
 * @param bytes_produced Bytes written to output
 * @param flush_mode 0=continue, 1=flush, 2=finish
 * @return BFC_OK on success
 */
int bfc_compress_ctx_process(bfc_compress_ctx_t* ctx, const void* input, size_t input_size,
                             void* output, size_t output_size, size_t* bytes_consumed,
                             size_t* bytes_produced, int flush_mode);

/**
 * Destroy compression context
 * @param ctx Context to destroy
 */
void bfc_compress_ctx_destroy(bfc_compress_ctx_t* ctx);

/**
 * Get compression algorithm name
 * @param comp_type Compression type
 * @return Algorithm name or "unknown"
 */
const char* bfc_compress_name(uint8_t comp_type);

/**
 * Get compression statistics
 * @param comp_type Compression type
 * @param original_size Original data size
 * @param compressed_size Compressed data size
 * @return Compression ratio as percentage (0-100)
 */
double bfc_compress_ratio(size_t original_size, size_t compressed_size);

#ifdef __cplusplus
}
#endif