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

#include "bfc_compress.h"
#include "bfc.h"
#include <stdlib.h>
#include <string.h>

#ifdef BFC_WITH_ZSTD
#include <zstd.h>
#endif

// Default compression level
#define BFC_COMPRESS_DEFAULT_LEVEL 3

// Minimum file size to consider compression (bytes)
#define BFC_COMPRESS_MIN_SIZE 64

// Compression context structure
struct bfc_compress_ctx {
  uint8_t type;
  int level;
#ifdef BFC_WITH_ZSTD
  ZSTD_CStream* zstd_ctx;
#endif
};

int bfc_compress_is_supported(uint8_t comp_type) {
  switch (comp_type) {
  case BFC_COMP_NONE:
    return 1;
#ifdef BFC_WITH_ZSTD
  case BFC_COMP_ZSTD:
    return 1;
#endif
  default:
    return 0;
  }
}

uint8_t bfc_compress_recommend(size_t size, const void* sample, size_t sample_size) {
  // Don't compress very small files
  if (size < BFC_COMPRESS_MIN_SIZE) {
    return BFC_COMP_NONE;
  }

#ifndef BFC_WITH_ZSTD
  (void) sample;      // Suppress unused parameter warning
  (void) sample_size; // Suppress unused parameter warning
#endif

#ifdef BFC_WITH_ZSTD
  // Analyze sample content if provided
  if (sample && sample_size > 0) {
    const uint8_t* data = (const uint8_t*) sample;
    size_t zero_count = 0;
    size_t repeat_count = 0;

    // Count zeros and repeated bytes
    for (size_t i = 0; i < sample_size; i++) {
      if (data[i] == 0)
        zero_count++;
      if (i > 0 && data[i] == data[i - 1])
        repeat_count++;
    }

    // If file has lots of zeros or repeated patterns, compression will help
    double zero_ratio = (double) zero_count / sample_size;
    double repeat_ratio = (double) repeat_count / sample_size;

    if (zero_ratio > 0.1 || repeat_ratio > 0.2) {
      return BFC_COMP_ZSTD;
    }

    // For text-like content (printable ASCII), compression usually helps
    size_t printable_count = 0;
    for (size_t i = 0; i < sample_size; i++) {
      if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\r' ||
          data[i] == '\t') {
        printable_count++;
      }
    }

    if ((double) printable_count / sample_size > 0.8) {
      return BFC_COMP_ZSTD;
    }
  }

  // For larger files, default to compression
  if (size > 1024) {
    return BFC_COMP_ZSTD;
  }
#endif

  return BFC_COMP_NONE;
}

bfc_compress_result_t bfc_compress_data(uint8_t comp_type, const void* input, size_t input_size,
                                        int level) {
  bfc_compress_result_t result = {0};

  if (!input || input_size == 0) {
    result.error = BFC_E_INVAL;
    return result;
  }

  if (!bfc_compress_is_supported(comp_type)) {
    result.error = BFC_E_INVAL;
    return result;
  }

#ifndef BFC_WITH_ZSTD
  (void) level; // Suppress unused parameter warning when ZSTD not available
#endif

  switch (comp_type) {
  case BFC_COMP_NONE:
    // No compression - just copy data
    result.data = malloc(input_size);
    if (!result.data) {
      result.error = BFC_E_IO;
      return result;
    }
    memcpy(result.data, input, input_size);
    result.compressed_size = input_size;
    result.original_size = input_size;
    result.error = BFC_OK;
    break;

#ifdef BFC_WITH_ZSTD
  case BFC_COMP_ZSTD: {
    if (level <= 0)
      level = BFC_COMPRESS_DEFAULT_LEVEL;
    if (level > ZSTD_maxCLevel())
      level = ZSTD_maxCLevel();

    size_t max_compressed_size = ZSTD_compressBound(input_size);
    result.data = malloc(max_compressed_size);
    if (!result.data) {
      result.error = BFC_E_IO;
      return result;
    }

    size_t compressed_size =
        ZSTD_compress(result.data, max_compressed_size, input, input_size, level);

    if (ZSTD_isError(compressed_size)) {
      free(result.data);
      result.data = NULL;
      result.error = BFC_E_IO;
      return result;
    }

    // Shrink buffer to actual size
    void* new_data = realloc(result.data, compressed_size);
    if (new_data || compressed_size == 0) {
      result.data = new_data;
    }

    result.compressed_size = compressed_size;
    result.original_size = input_size;
    result.error = BFC_OK;
  } break;
#endif

  default:
    result.error = BFC_E_INVAL;
    break;
  }

  return result;
}

bfc_decompress_result_t bfc_decompress_data(uint8_t comp_type, const void* input, size_t input_size,
                                            size_t expected_size) {
  bfc_decompress_result_t result = {0};

  if (!input || input_size == 0) {
    result.error = BFC_E_INVAL;
    return result;
  }

  if (!bfc_compress_is_supported(comp_type)) {
    result.error = BFC_E_INVAL;
    return result;
  }

#ifndef BFC_WITH_ZSTD
  (void) expected_size; // Suppress unused parameter warning when ZSTD not available
#endif

  switch (comp_type) {
  case BFC_COMP_NONE:
    // No decompression - just copy data
    result.data = malloc(input_size);
    if (!result.data) {
      result.error = BFC_E_IO;
      return result;
    }
    memcpy(result.data, input, input_size);
    result.decompressed_size = input_size;
    result.error = BFC_OK;
    break;

#ifdef BFC_WITH_ZSTD
  case BFC_COMP_ZSTD: {
    // Use expected size if provided, otherwise get from compressed data
    size_t decompressed_size = expected_size;
    if (decompressed_size == 0) {
      decompressed_size = ZSTD_getFrameContentSize(input, input_size);
      if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
          decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        result.error = BFC_E_CRC;
        return result;
      }
    }

    result.data = malloc(decompressed_size);
    if (!result.data) {
      result.error = BFC_E_IO;
      return result;
    }

    size_t actual_size = ZSTD_decompress(result.data, decompressed_size, input, input_size);

    if (ZSTD_isError(actual_size)) {
      free(result.data);
      result.data = NULL;
      result.error = BFC_E_CRC;
      return result;
    }

    // Verify size matches expectation
    if (expected_size > 0 && actual_size != expected_size) {
      free(result.data);
      result.data = NULL;
      result.error = BFC_E_CRC;
      return result;
    }

    result.decompressed_size = actual_size;
    result.error = BFC_OK;
  } break;
#endif

  default:
    result.error = BFC_E_INVAL;
    break;
  }

  return result;
}

bfc_compress_ctx_t* bfc_compress_ctx_create(uint8_t comp_type, int level) {
  if (!bfc_compress_is_supported(comp_type)) {
    return NULL;
  }

  bfc_compress_ctx_t* ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;

  ctx->type = comp_type;
  ctx->level = level > 0 ? level : BFC_COMPRESS_DEFAULT_LEVEL;

#ifdef BFC_WITH_ZSTD
  if (comp_type == BFC_COMP_ZSTD) {
    ctx->zstd_ctx = ZSTD_createCStream();
    if (!ctx->zstd_ctx) {
      free(ctx);
      return NULL;
    }

    size_t ret = ZSTD_initCStream(ctx->zstd_ctx, ctx->level);
    if (ZSTD_isError(ret)) {
      ZSTD_freeCStream(ctx->zstd_ctx);
      free(ctx);
      return NULL;
    }
  }
#endif

  return ctx;
}

int bfc_compress_ctx_process(bfc_compress_ctx_t* ctx, const void* input, size_t input_size,
                             void* output, size_t output_size, size_t* bytes_consumed,
                             size_t* bytes_produced, int flush_mode) {
  if (!ctx || !bytes_consumed || !bytes_produced) {
    return BFC_E_INVAL;
  }

  *bytes_consumed = 0;
  *bytes_produced = 0;

#ifndef BFC_WITH_ZSTD
  (void) flush_mode; // Suppress unused parameter warning when ZSTD not available
#endif

  switch (ctx->type) {
  case BFC_COMP_NONE:
    // No compression - just copy data
    {
      size_t copy_size = input_size < output_size ? input_size : output_size;
      if (copy_size > 0 && input && output) {
        memcpy(output, input, copy_size);
      }
      *bytes_consumed = copy_size;
      *bytes_produced = copy_size;
      return BFC_OK;
    }

#ifdef BFC_WITH_ZSTD
  case BFC_COMP_ZSTD: {
    ZSTD_inBuffer inbuf = {input, input_size, 0};
    ZSTD_outBuffer outbuf = {output, output_size, 0};

    ZSTD_EndDirective directive;
    switch (flush_mode) {
    case 0:
      directive = ZSTD_e_continue;
      break;
    case 1:
      directive = ZSTD_e_flush;
      break;
    case 2:
      directive = ZSTD_e_end;
      break;
    default:
      return BFC_E_INVAL;
    }

    size_t ret = ZSTD_compressStream2(ctx->zstd_ctx, &outbuf, &inbuf, directive);
    if (ZSTD_isError(ret)) {
      return BFC_E_IO;
    }

    *bytes_consumed = inbuf.pos;
    *bytes_produced = outbuf.pos;
    return BFC_OK;
  }
#endif

  default:
    return BFC_E_INVAL;
  }
}

void bfc_compress_ctx_destroy(bfc_compress_ctx_t* ctx) {
  if (!ctx)
    return;

#ifdef BFC_WITH_ZSTD
  if (ctx->zstd_ctx) {
    ZSTD_freeCStream(ctx->zstd_ctx);
  }
#endif

  free(ctx);
}

const char* bfc_compress_name(uint8_t comp_type) {
  switch (comp_type) {
  case BFC_COMP_NONE:
    return "none";
  case BFC_COMP_ZSTD:
    return "zstd";
  default:
    return "unknown";
  }
}

double bfc_compress_ratio(size_t original_size, size_t compressed_size) {
  if (original_size == 0)
    return 0.0;
  return (double) compressed_size * 100.0 / original_size;
}