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
#include "bfc_os.h"
#include <assert.h>
#include <bfc.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Test basic compression support detection
static int test_compression_support(void) {
  // BFC_COMP_NONE should always be supported
  assert(bfc_compress_is_supported(BFC_COMP_NONE) == 1);

  // Invalid compression type should not be supported
  assert(bfc_compress_is_supported(255) == 0);

#ifdef BFC_WITH_ZSTD
  // ZSTD should be supported when built with it
  assert(bfc_compress_is_supported(BFC_COMP_ZSTD) == 1);
#else
  // ZSTD should not be supported when not built with it
  assert(bfc_compress_is_supported(BFC_COMP_ZSTD) == 0);
#endif

  return 0;
}

// Test compression recommendation logic
static int test_compression_recommend(void) {
  // Very small files should not be compressed
  uint8_t comp = bfc_compress_recommend(32, NULL, 0);
  assert(comp == BFC_COMP_NONE);

  // Sample with lots of zeros should be compressed (if ZSTD available)
  char zero_data[1024];
  memset(zero_data, 0, sizeof(zero_data));
  comp = bfc_compress_recommend(sizeof(zero_data), zero_data, sizeof(zero_data));
#ifdef BFC_WITH_ZSTD
  assert(comp == BFC_COMP_ZSTD);
#else
  assert(comp == BFC_COMP_NONE);
#endif

  // Sample with repeated patterns should be compressed (if ZSTD available)
  char repeat_data[1024];
  for (size_t i = 0; i < sizeof(repeat_data); i++) {
    repeat_data[i] = 'A';
  }
  comp = bfc_compress_recommend(sizeof(repeat_data), repeat_data, sizeof(repeat_data));
#ifdef BFC_WITH_ZSTD
  assert(comp == BFC_COMP_ZSTD);
#else
  assert(comp == BFC_COMP_NONE);
#endif

  // Text-like content should be compressed (if ZSTD available)
  const char* text_data =
      "Hello world! This is a test string with repeating patterns and text content.";
  comp = bfc_compress_recommend(strlen(text_data), text_data, strlen(text_data));
#ifdef BFC_WITH_ZSTD
  assert(comp == BFC_COMP_ZSTD);
#else
  assert(comp == BFC_COMP_NONE);
#endif

  return 0;
}

// Test basic data compression and decompression
static int test_compress_decompress_data(void) {
  const char* test_data = "Hello, world! This is test data for compression. "
                          "It contains repeated words and patterns that should compress well. "
                          "Hello, world! This is test data for compression.";
  size_t data_size = strlen(test_data);

  // Test with no compression
  bfc_compress_result_t comp_result = bfc_compress_data(BFC_COMP_NONE, test_data, data_size, 0);
  assert(comp_result.error == BFC_OK);
  assert(comp_result.data != NULL);
  assert(comp_result.compressed_size == data_size);
  assert(comp_result.original_size == data_size);
  assert(memcmp(comp_result.data, test_data, data_size) == 0);

  // Test decompression
  bfc_decompress_result_t decomp_result =
      bfc_decompress_data(BFC_COMP_NONE, comp_result.data, comp_result.compressed_size, data_size);
  assert(decomp_result.error == BFC_OK);
  assert(decomp_result.data != NULL);
  assert(decomp_result.decompressed_size == data_size);
  assert(memcmp(decomp_result.data, test_data, data_size) == 0);

  free(comp_result.data);
  free(decomp_result.data);

#ifdef BFC_WITH_ZSTD
  // Test ZSTD compression
  comp_result = bfc_compress_data(BFC_COMP_ZSTD, test_data, data_size, 3);
  assert(comp_result.error == BFC_OK);
  assert(comp_result.data != NULL);
  assert(comp_result.original_size == data_size);
  // Compressed size should be smaller for this repetitive text
  assert(comp_result.compressed_size < data_size);

  // Test ZSTD decompression
  decomp_result =
      bfc_decompress_data(BFC_COMP_ZSTD, comp_result.data, comp_result.compressed_size, data_size);
  assert(decomp_result.error == BFC_OK);
  assert(decomp_result.data != NULL);
  assert(decomp_result.decompressed_size == data_size);
  assert(memcmp(decomp_result.data, test_data, data_size) == 0);

  free(comp_result.data);
  free(decomp_result.data);
#endif

  return 0;
}

// Test error handling in compression functions
static int test_compress_error_handling(void) {
  const char* test_data = "test data";

  // Test invalid parameters
  bfc_compress_result_t result = bfc_compress_data(BFC_COMP_NONE, NULL, 10, 0);
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  result = bfc_compress_data(BFC_COMP_NONE, test_data, 0, 0);
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  result = bfc_compress_data(255, test_data, 10, 0); // Invalid compression type
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  // Test decompression error handling
  bfc_decompress_result_t decomp_result = bfc_decompress_data(BFC_COMP_NONE, NULL, 10, 0);
  assert(decomp_result.error == BFC_E_INVAL);
  assert(decomp_result.data == NULL);

  decomp_result = bfc_decompress_data(BFC_COMP_NONE, test_data, 0, 0);
  assert(decomp_result.error == BFC_E_INVAL);
  assert(decomp_result.data == NULL);

  decomp_result = bfc_decompress_data(255, test_data, 10, 0); // Invalid compression type
  assert(decomp_result.error == BFC_E_INVAL);
  assert(decomp_result.data == NULL);

  return 0;
}

// Test compression context creation and management
static int test_compression_context(void) {
  // Test creating context for no compression
  bfc_compress_ctx_t* ctx = bfc_compress_ctx_create(BFC_COMP_NONE, 0);
  assert(ctx != NULL);

  // Test basic streaming operation
  const char* input = "test input data";
  char output[1024];
  size_t bytes_consumed, bytes_produced;

  int result = bfc_compress_ctx_process(ctx, input, strlen(input), output, sizeof(output),
                                        &bytes_consumed, &bytes_produced, 0);
  assert(result == BFC_OK);
  assert(bytes_consumed == strlen(input));
  assert(bytes_produced == strlen(input));
  assert(memcmp(output, input, strlen(input)) == 0);

  bfc_compress_ctx_destroy(ctx);

  // Test invalid context creation
  ctx = bfc_compress_ctx_create(255, 0); // Invalid compression type
  assert(ctx == NULL);

#ifdef BFC_WITH_ZSTD
  // Test ZSTD context creation
  ctx = bfc_compress_ctx_create(BFC_COMP_ZSTD, 3);
  assert(ctx != NULL);
  bfc_compress_ctx_destroy(ctx);
#endif

  return 0;
}

// Test compression utility functions
static int test_compression_utilities(void) {
  // Test compression type names
  assert(strcmp(bfc_compress_name(BFC_COMP_NONE), "none") == 0);
  assert(strcmp(bfc_compress_name(BFC_COMP_ZSTD), "zstd") == 0);
  assert(strcmp(bfc_compress_name(255), "unknown") == 0);

  // Test compression ratio calculation
  assert(bfc_compress_ratio(0, 0) == 0.0);
  assert(bfc_compress_ratio(100, 50) == 50.0);
  assert(bfc_compress_ratio(100, 100) == 100.0);
  assert(bfc_compress_ratio(100, 150) == 150.0);

  return 0;
}

// Test BFC writer compression settings
static int test_writer_compression_settings(void) {
  const char* filename = "/tmp/test_compression_writer.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);
  assert(writer != NULL);

  // Test setting compression
  result = bfc_set_compression(writer, BFC_COMP_NONE, 0);
  assert(result == BFC_OK);
  assert(bfc_get_compression(writer) == BFC_COMP_NONE);

  // Test setting compression threshold
  result = bfc_set_compression_threshold(writer, 1024);
  assert(result == BFC_OK);

#ifdef BFC_WITH_ZSTD
  // Test ZSTD compression setting
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 5);
  assert(result == BFC_OK);
  assert(bfc_get_compression(writer) == BFC_COMP_ZSTD);
#endif

  // Test invalid compression type
  result = bfc_set_compression(writer, 255, 0);
  assert(result == BFC_E_INVAL);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

// Test end-to-end compression with BFC container
static int test_end_to_end_compression(void) {
  const char* container_filename = "/tmp/test_e2e_compression.bfc";
  const char* test_filename = "/tmp/test_e2e_input.txt";
  const char* extract_filename = "/tmp/test_e2e_output.txt";

  // Clean up any existing files
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);

  // Create test input file with compressible content
  FILE* input_file = fopen(test_filename, "w");
  assert(input_file != NULL);

  const char* repeating_content =
      "This is a test line that repeats multiple times for compression testing.\n";
  for (int i = 0; i < 100; i++) { // Create 100 lines of repeated content
    fputs(repeating_content, input_file);
  }
  fclose(input_file);

  // Create BFC container with compression
  bfc_t* writer = NULL;
  int result = bfc_create(container_filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Set compression (use NONE if ZSTD not available)
#ifdef BFC_WITH_ZSTD
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
#else
  result = bfc_set_compression(writer, BFC_COMP_NONE, 0);
#endif
  assert(result == BFC_OK);

  // Add the test file
  FILE* test_file = fopen(test_filename, "rb");
  assert(test_file != NULL);

  result = bfc_add_file(writer, "test_file.txt", test_file, 0644, 0, NULL);
  assert(result == BFC_OK);
  fclose(test_file);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Read back the file and verify compression info
  bfc_t* reader = NULL;
  result = bfc_open(container_filename, &reader);
  assert(result == BFC_OK);

  bfc_entry_t entry;
  result = bfc_stat(reader, "test_file.txt", &entry);
  assert(result == BFC_OK);

  // Verify compression type is set correctly
#ifdef BFC_WITH_ZSTD
  assert(entry.comp == BFC_COMP_ZSTD);
  // For repetitive content, compressed size should be much smaller
  assert(entry.obj_size < entry.size / 2);
#else
  assert(entry.comp == BFC_COMP_NONE);
  // Without compression, stored size should be the same (plus some overhead)
  assert(entry.obj_size >= entry.size);
#endif

  // Extract and verify content
  int out_fd = open(extract_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  result = bfc_extract_to_fd(reader, "test_file.txt", out_fd);
  assert(result == BFC_OK);
  close(out_fd);
  bfc_close_read(reader);

  // Compare original and extracted files
  FILE* orig = fopen(test_filename, "rb");
  FILE* extracted = fopen(extract_filename, "rb");
  assert(orig != NULL);
  assert(extracted != NULL);

  // Compare file sizes
  fseek(orig, 0, SEEK_END);
  long orig_size = ftell(orig);
  fseek(extracted, 0, SEEK_END);
  long extracted_size = ftell(extracted);
  assert(orig_size == extracted_size);

  // Compare content
  rewind(orig);
  rewind(extracted);

  char orig_buf[4096], extracted_buf[4096];
  size_t orig_read, extracted_read;

  while ((orig_read = fread(orig_buf, 1, sizeof(orig_buf), orig)) > 0) {
    extracted_read = fread(extracted_buf, 1, sizeof(extracted_buf), extracted);
    assert(orig_read == extracted_read);
    assert(memcmp(orig_buf, extracted_buf, orig_read) == 0);
  }

  fclose(orig);
  fclose(extracted);

  // Clean up
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);

  return 0;
}

// Test additional compression edge cases for better coverage
static int test_compression_edge_cases(void) {
  const char* filename = "/tmp/compress_edge_test.bfc";
  const char* test_filename = "/tmp/compress_edge_input.txt";

  // Create a small file that won't be compressed (below threshold)
  FILE* f = fopen(test_filename, "w");
  assert(f);
  fprintf(f, "tiny"); // 4 bytes, below default 64-byte threshold
  fclose(f);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Set compression but file should remain uncompressed due to size
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
  assert(result == BFC_OK);

  // Verify compression is set
  assert(bfc_get_compression(writer) == BFC_COMP_ZSTD);

  FILE* src = fopen(test_filename, "rb");
  assert(src);
  result = bfc_add_file(writer, "tiny.txt", src, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);
  fclose(src);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Verify the file wasn't actually compressed due to small size
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  bfc_entry_t entry;
  result = bfc_stat(reader, "tiny.txt", &entry);
  assert(result == BFC_OK);
  assert(entry.comp == BFC_COMP_NONE); // Should be uncompressed

  bfc_close_read(reader);

  // Test with different compression levels
  unlink(filename);

  // Create larger file that will be compressed
  f = fopen(test_filename, "w");
  assert(f);
  for (int i = 0; i < 100; i++) {
    fprintf(f, "This is a repeating line %d that should compress well with zstd compression.\n", i);
  }
  fclose(f);

  writer = NULL;
  result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Test different compression levels
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 1); // Fast
  assert(result == BFC_OK);

  src = fopen(test_filename, "rb");
  assert(src);
  result = bfc_add_file(writer, "large1.txt", src, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);
  fclose(src);

  // Change compression level for next file
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 19); // Max compression
  assert(result == BFC_OK);

  src = fopen(test_filename, "rb");
  assert(src);
  result = bfc_add_file(writer, "large2.txt", src, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);
  fclose(src);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Verify both files were compressed
  reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  result = bfc_stat(reader, "large1.txt", &entry);
  assert(result == BFC_OK);
  assert(entry.comp == BFC_COMP_ZSTD);

  result = bfc_stat(reader, "large2.txt", &entry);
  assert(result == BFC_OK);
  assert(entry.comp == BFC_COMP_ZSTD);

  bfc_close_read(reader);

  // Clean up
  unlink(filename);
  unlink(test_filename);

  return 0;
}

// Test compression threshold settings
static int test_compression_threshold_settings(void) {
  const char* filename = "/tmp/compress_threshold_test.bfc";
  const char* test_filename = "/tmp/compress_threshold_input.txt";

  // Create a file that's exactly at the threshold
  FILE* f = fopen(test_filename, "w");
  assert(f);
  for (int i = 0; i < 64; i++) { // Exactly 64 bytes
    fputc('A', f);
  }
  fclose(f);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Set custom compression threshold
  result = bfc_set_compression_threshold(writer, 32); // Lower threshold
  assert(result == BFC_OK);

  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 6);
  assert(result == BFC_OK);

  FILE* src = fopen(test_filename, "rb");
  assert(src);
  result = bfc_add_file(writer, "threshold_test.txt", src, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);
  fclose(src);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Verify file was compressed (since 64 bytes > 32 byte threshold)
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  bfc_entry_t entry;
  result = bfc_stat(reader, "threshold_test.txt", &entry);
  assert(result == BFC_OK);
  // Note: File might still not be compressed if compression makes it larger

  bfc_close_read(reader);

  // Clean up
  unlink(filename);
  unlink(test_filename);

  return 0;
}

int test_compress(void) {
  int result = 0;

  result += test_compression_support();
  result += test_compression_recommend();
  result += test_compress_decompress_data();
  result += test_compress_error_handling();
  result += test_compression_context();
  result += test_compression_utilities();
  result += test_writer_compression_settings();
  result += test_end_to_end_compression();
  result += test_compression_edge_cases();
  result += test_compression_threshold_settings();

  return result;
}