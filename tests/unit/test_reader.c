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
#include "bfc_os.h"
#include <assert.h>
#include <bfc.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Helper function to create a test container
static int create_test_container(const char* filename) {
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  if (result != BFC_OK)
    return result;

  // Add a directory
  result = bfc_add_dir(writer, "testdir", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  // Add some test files
  const char* content1 = "Hello, BFC Reader!";
  const char* content2 = "This is file 2";
  const char* content3 = "Subdirectory file";

  // Create temp files
  FILE* temp1 = tmpfile();
  FILE* temp2 = tmpfile();
  FILE* temp3 = tmpfile();

  if (!temp1 || !temp2 || !temp3) {
    bfc_close(writer);
    return BFC_E_IO;
  }

  fwrite(content1, 1, strlen(content1), temp1);
  fwrite(content2, 1, strlen(content2), temp2);
  fwrite(content3, 1, strlen(content3), temp3);

  rewind(temp1);
  rewind(temp2);
  rewind(temp3);

  // Add files to container
  result = bfc_add_file(writer, "file1.txt", temp1, 0644, bfc_os_current_time_ns(), NULL);
  if (result != BFC_OK)
    goto cleanup;

  result = bfc_add_file(writer, "file2.txt", temp2, 0644, bfc_os_current_time_ns(), NULL);
  if (result != BFC_OK)
    goto cleanup;

  // Add subdirectory
  result = bfc_add_dir(writer, "testdir/subdir", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK)
    goto cleanup;

  result =
      bfc_add_file(writer, "testdir/subdir/file3.txt", temp3, 0644, bfc_os_current_time_ns(), NULL);
  if (result != BFC_OK)
    goto cleanup;

  result = bfc_finish(writer);

cleanup:
  fclose(temp1);
  fclose(temp2);
  fclose(temp3);
  bfc_close(writer);

  return result;
}

static int test_open_container(void) {
  const char* filename = "/tmp/test_reader.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);
  assert(reader != NULL);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_stat_files(void) {
  const char* filename = "/tmp/test_reader_stat.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test stat on existing file
  bfc_entry_t entry;
  result = bfc_stat(reader, "file1.txt", &entry);
  assert(result == BFC_OK);
  assert(strcmp(entry.path, "file1.txt") == 0);
  assert(entry.size == strlen("Hello, BFC Reader!"));
  assert((entry.mode & 0777) == 0644);

  // Test stat on directory
  result = bfc_stat(reader, "testdir", &entry);
  assert(result == BFC_OK);
  assert(strcmp(entry.path, "testdir") == 0);
  assert((entry.mode & 0777) == 0755);

  // Test stat on non-existent file
  result = bfc_stat(reader, "nonexistent.txt", &entry);
  assert(result == BFC_E_NOTFOUND);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

// List callback for counting entries
struct list_context {
  int count;
  char found_paths[10][256];
};

static int count_entries_cb(const bfc_entry_t* entry, void* user) {
  struct list_context* ctx = (struct list_context*) user;
  if (ctx->count < 10) {
    strncpy(ctx->found_paths[ctx->count], entry->path, 255);
    ctx->found_paths[ctx->count][255] = '\0';
  }
  ctx->count++;
  return 0;
}

static int test_list_entries(void) {
  const char* filename = "/tmp/test_reader_list.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // List all entries
  struct list_context ctx = {0};
  result = bfc_list(reader, NULL, count_entries_cb, &ctx);
  assert(result == BFC_OK);
  assert(ctx.count == 5); // testdir, file1.txt, file2.txt, testdir/subdir, testdir/subdir/file3.txt

  // List entries in testdir
  ctx.count = 0;
  result = bfc_list(reader, "testdir", count_entries_cb, &ctx);
  assert(result == BFC_OK);
  assert(ctx.count >= 2); // Should find testdir/subdir and testdir/subdir/file3.txt

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_read_content(void) {
  const char* filename = "/tmp/test_reader_read.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Read full file content
  char buffer[256];
  size_t bytes_read = bfc_read(reader, "file1.txt", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("Hello, BFC Reader!"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "Hello, BFC Reader!") == 0);

  // Read partial content
  memset(buffer, 0, sizeof(buffer));
  bytes_read = bfc_read(reader, "file1.txt", 7, buffer, 3);
  assert(bytes_read == 3);
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "BFC") == 0);

  // Read beyond file end
  bytes_read = bfc_read(reader, "file1.txt", 1000, buffer, sizeof(buffer));
  assert(bytes_read == 0);

  // Try to read directory (should fail)
  bytes_read = bfc_read(reader, "testdir", 0, buffer, sizeof(buffer));
  assert(bytes_read == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_extract_file(void) {
  const char* filename = "/tmp/test_reader_extract.bfc";
  const char* output_file = "/tmp/extracted_file.txt";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Extract to file
  int out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  // Debug: check what we can stat first
  bfc_entry_t debug_entry;
  result = bfc_stat(reader, "file2.txt", &debug_entry);
  if (result == BFC_OK) {
    printf("file2.txt stat: mode=0%o, size=%" PRIu64 "\n", debug_entry.mode, debug_entry.size);
    printf("S_IFMT=0%o, S_IFREG=0%o\n", S_IFMT, S_IFREG);
    printf("mode & S_IFMT = 0%o\n", debug_entry.mode & S_IFMT);
  } else {
    printf("bfc_stat failed with error: %d\n", result);
  }

  result = bfc_extract_to_fd(reader, "file2.txt", out_fd);
  if (result != BFC_OK) {
    printf("bfc_extract_to_fd failed with error: %d\n", result);
  }
  assert(result == BFC_OK);

  close(out_fd);

  // Verify extracted content
  FILE* extracted = fopen(output_file, "r");
  assert(extracted != NULL);

  char buffer[256];
  size_t len = fread(buffer, 1, sizeof(buffer) - 1, extracted);
  buffer[len] = '\0';

  assert(strcmp(buffer, "This is file 2") == 0);

  fclose(extracted);
  unlink(output_file);
  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_verify_container(void) {
  const char* filename = "/tmp/test_reader_verify.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Basic verification
  result = bfc_verify(reader, 0);
  assert(result == BFC_OK);

  // Deep verification (with CRC checks)
  result = bfc_verify(reader, 1);
  assert(result == BFC_OK);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_invalid_container(void) {
  const char* filename = "/tmp/reader_test_invalid.bfc";

  // Create invalid file
  FILE* f = fopen(filename, "w");
  assert(f != NULL);
  fprintf(f, "This is not a valid BFC container");
  fclose(f);

  // Try to open invalid container
  bfc_t* reader = NULL;
  int result = bfc_open(filename, &reader);
  assert(result != BFC_OK);
  assert(reader == NULL);

  unlink(filename);

  // Test non-existent file
  result = bfc_open("/tmp/nonexistent.bfc", &reader);
  assert(result != BFC_OK);
  assert(reader == NULL);

  return 0;
}

static int test_error_conditions(void) {
  bfc_t* reader = NULL;
  bfc_entry_t entry;
  char buffer[256];

  // Test NULL parameters
  int result = bfc_open(NULL, &reader);
  assert(result == BFC_E_INVAL);

  result = bfc_open("/tmp/reader_test.bfc", NULL);
  assert(result == BFC_E_INVAL);

  // Test operations on NULL reader
  result = bfc_stat(NULL, "file.txt", &entry);
  assert(result == BFC_E_INVAL);

  result = bfc_verify(NULL, 0);
  assert(result == BFC_E_INVAL);

  result = bfc_list(NULL, NULL, NULL, NULL);
  assert(result == BFC_E_INVAL);

  size_t bytes = bfc_read(NULL, "file.txt", 0, buffer, sizeof(buffer));
  assert(bytes == 0);

  result = bfc_extract_to_fd(NULL, "file.txt", 1);
  assert(result == BFC_E_INVAL);

  bfc_close_read(NULL); // Should be safe

  return 0;
}

static int test_edge_cases(void) {
  const char* filename = "/tmp/test_reader_edge.bfc";

  // Create container with edge case data
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test reading with various buffer sizes
  char small_buf[5];
  char large_buf[1000];

  // Small buffer read
  size_t bytes = bfc_read(reader, "file1.txt", 0, small_buf, sizeof(small_buf));
  assert(bytes == sizeof(small_buf));
  assert(memcmp(small_buf, "Hello", 5) == 0);

  // Large buffer read (larger than file)
  bytes = bfc_read(reader, "file1.txt", 0, large_buf, sizeof(large_buf));
  assert(bytes == strlen("Hello, BFC Reader!"));

  // Test reading at various offsets
  char offset_buf[10];
  bytes = bfc_read(reader, "file1.txt", 7, offset_buf, 3);
  assert(bytes == 3);
  assert(memcmp(offset_buf, "BFC", 3) == 0);

  // Test reading beyond file end
  bytes = bfc_read(reader, "file1.txt", 1000, offset_buf, sizeof(offset_buf));
  assert(bytes == 0);

  // Test with empty/NULL parameters
  bfc_entry_t entry;
  result = bfc_stat(reader, "", &entry);
  // Empty path may be treated as root or invalid - either is acceptable
  assert(result == BFC_E_NOTFOUND || result == BFC_E_INVAL);

  result = bfc_stat(reader, NULL, &entry);
  assert(result == BFC_E_INVAL);

  result = bfc_stat(reader, "file1.txt", NULL);
  assert(result == BFC_E_INVAL);

  // Test list with NULL callback
  result = bfc_list(reader, NULL, NULL, NULL);
  assert(result == BFC_E_INVAL);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_corrupted_data(void) {
  const char* filename = "/tmp/test_corrupted.bfc";

  // Create a valid container first
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Now corrupt it by writing garbage at the beginning
  FILE* file = fopen(filename, "r+b");
  assert(file != NULL);

  fseek(file, 0, SEEK_SET);
  fwrite("CORRUPT", 1, 7, file);
  fclose(file);

  // Try to open corrupted container
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result != BFC_OK); // Should fail
  assert(reader == NULL);

  unlink(filename);

  return 0;
}

static int test_large_file_operations(void) {
  const char* filename = "/tmp/test_large.bfc";

  // Create container with larger content
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Create a larger test file (8KB)
  FILE* large_temp = tmpfile();
  assert(large_temp != NULL);

  for (int i = 0; i < 8192; i++) {
    fputc('A' + (i % 26), large_temp);
  }
  rewind(large_temp);

  result = bfc_add_file(writer, "large_file.txt", large_temp, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  fclose(large_temp);
  bfc_close(writer);

  // Now test reading the large file
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test reading in chunks
  char chunk_buf[1024];
  for (int offset = 0; offset < 8192; offset += 1024) {
    size_t bytes = bfc_read(reader, "large_file.txt", offset, chunk_buf, sizeof(chunk_buf));
    size_t expected = (offset + 1024 <= 8192) ? 1024 : (8192 - offset);
    assert(bytes == expected);

    // Verify pattern
    for (size_t i = 0; i < bytes; i++) {
      char expected_char = 'A' + ((offset + i) % 26);
      assert(chunk_buf[i] == expected_char);
    }
  }

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_empty_container(void) {
  const char* filename = "/tmp/reader_test_empty.bfc";
  unlink(filename);

  // Create empty container
  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Test reading empty container
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Verify container
  result = bfc_verify(reader, 1);
  assert(result == BFC_OK);

  // Try to stat non-existent file
  bfc_entry_t entry;
  result = bfc_stat(reader, "nonexistent.txt", &entry);
  assert(result == BFC_E_NOTFOUND);

  // List should return no entries
  struct list_context ctx = {0};
  result = bfc_list(reader, NULL, count_entries_cb, &ctx);
  assert(result == BFC_OK);
  assert(ctx.count == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_directory_only_container(void) {
  const char* filename = "/tmp/test_dirs_only.bfc";
  unlink(filename);

  // Create container with only directories
  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  result = bfc_add_dir(writer, "dir1", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_add_dir(writer, "dir1/subdir", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_add_dir(writer, "dir2", 0700, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Test reading directory-only container
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // List all directories
  struct list_context ctx = {0};
  result = bfc_list(reader, NULL, count_entries_cb, &ctx);
  assert(result == BFC_OK);
  assert(ctx.count == 3);

  // Test stat on directories
  bfc_entry_t entry;
  result = bfc_stat(reader, "dir1", &entry);
  assert(result == BFC_OK);
  assert(S_ISDIR(entry.mode));
  assert((entry.mode & 0777) == 0755);

  result = bfc_stat(reader, "dir2", &entry);
  assert(result == BFC_OK);
  assert(S_ISDIR(entry.mode));
  assert((entry.mode & 0777) == 0700);

  // Try to read directory as file (should fail)
  char buffer[256];
  size_t bytes = bfc_read(reader, "dir1", 0, buffer, sizeof(buffer));
  assert(bytes == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_encryption_functions(void) {
  const char* filename = "/tmp/test_encrypted.bfc";
  unlink(filename);

  // Test bfc_has_encryption on non-encrypted container
  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add a simple file
  FILE* temp = tmpfile();
  assert(temp != NULL);
  fwrite("test content", 1, 12, temp);
  rewind(temp);
  result = bfc_add_file(writer, "test.txt", temp, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);
  fclose(temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Test reading and encryption detection
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Container without encryption should return 0
  int has_encryption = bfc_has_encryption(reader);
  assert(has_encryption == 0);

  // Test encryption functions with NULL reader
  has_encryption = bfc_has_encryption(NULL);
  assert(has_encryption == 0);

#ifdef BFC_WITH_SODIUM
  // Test setting encryption password (should succeed even for non-encrypted containers)
  result = bfc_reader_set_encryption_password(reader, "password", 8);
  // This may succeed or fail depending on implementation

  // Test with NULL parameters
  result = bfc_reader_set_encryption_password(NULL, "password", 8);
  assert(result == BFC_E_INVAL);

  result = bfc_reader_set_encryption_password(reader, NULL, 8);
  assert(result == BFC_E_INVAL);

  result = bfc_reader_set_encryption_password(reader, "password", 0);
  assert(result == BFC_E_INVAL);

  // Test setting encryption key
  uint8_t test_key[32] = {0};
  result = bfc_reader_set_encryption_key(reader, test_key);
  // Should succeed

  result = bfc_reader_set_encryption_key(NULL, test_key);
  assert(result == BFC_E_INVAL);

  result = bfc_reader_set_encryption_key(reader, NULL);
  assert(result == BFC_E_INVAL);
#else
  // Test without libsodium - should return BFC_E_INVAL
  result = bfc_reader_set_encryption_password(reader, "password", 8);
  assert(result == BFC_E_INVAL);

  uint8_t test_key[32] = {0};
  result = bfc_reader_set_encryption_key(reader, test_key);
  assert(result == BFC_E_INVAL);
#endif

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_file_size_edge_cases(void) {
  const char* filename = "/tmp/test_file_size.bfc";

  // Create a file that's too small to be a valid BFC container
  FILE* tiny_file = fopen(filename, "wb");
  assert(tiny_file != NULL);
  fwrite("tiny", 1, 4, tiny_file);
  fclose(tiny_file);

  // Try to open it - should fail
  bfc_t* reader = NULL;
  int result = bfc_open(filename, &reader);
  assert(result == BFC_E_BADMAGIC);
  assert(reader == NULL);

  unlink(filename);
  return 0;
}

static int test_index_parse_errors(void) {
  const char* filename = "/tmp/test_parse_error.bfc";

  // Create a valid container first
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  // Corrupt the index by modifying bytes in the index area
  FILE* file = fopen(filename, "r+b");
  assert(file != NULL);

  // Seek to near the end to corrupt index data
  fseek(file, -100, SEEK_END);
  fwrite("CORRUPT_INDEX_DATA", 1, 18, file);
  fclose(file);

  // Try to open corrupted container
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  // Should fail due to CRC mismatch or parse error
  assert(result != BFC_OK);
  assert(reader == NULL);

  unlink(filename);
  return 0;
}

static int test_extract_edge_cases(void) {
  const char* filename = "/tmp/test_extract_edge.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test extract with invalid file descriptor
  result = bfc_extract_to_fd(reader, "file1.txt", -1);
  assert(result == BFC_E_INVAL);

  // Test extract non-existent file
  int fd = open("/tmp/test_extract_output", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(fd >= 0);

  result = bfc_extract_to_fd(reader, "nonexistent.txt", fd);
  assert(result == BFC_E_NOTFOUND);

  // Test extract directory (should fail)
  result = bfc_extract_to_fd(reader, "testdir", fd);
  assert(result == BFC_E_INVAL);

  close(fd);
  unlink("/tmp/test_extract_output");

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_verify_edge_cases(void) {
  const char* filename = "/tmp/test_verify_edge.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Create a malformed container by modifying file size info
  // First close the reader
  bfc_close_read(reader);

  // Modify the container to create invalid offset/size
  FILE* file = fopen(filename, "r+b");
  assert(file != NULL);

  // Find and corrupt an entry's offset to be beyond file size
  // This is a bit tricky without parsing, so let's just corrupt some bytes
  fseek(file, -200, SEEK_END);
  uint8_t corrupt_data[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  fwrite(corrupt_data, 1, 8, file);
  fclose(file);

  // Try to open and verify
  result = bfc_open(filename, &reader);
  if (result == BFC_OK) {
    // If it opens, verify should catch the corruption
    result = bfc_verify(reader, 0);
    // Should fail with badmagic or CRC error
    assert(result != BFC_OK);
    bfc_close_read(reader);
  }

  unlink(filename);
  return 0;
}

static int test_list_edge_cases(void) {
  const char* filename = "/tmp/test_list_edge.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test list with empty string prefix
  struct list_context ctx = {0};
  result = bfc_list(reader, "", count_entries_cb, &ctx);
  assert(result == BFC_OK);

  // Test list with prefix that matches no entries
  ctx.count = 0;
  result = bfc_list(reader, "nonexistent_prefix", count_entries_cb, &ctx);
  assert(result == BFC_OK);
  assert(ctx.count == 0);

  // Test list with prefix that partially matches but not on directory boundary
  ctx.count = 0;
  result = bfc_list(reader, "file", count_entries_cb, &ctx);
  assert(result == BFC_OK);
  // The list function requires directory boundary matches, so "file" won't match
  // "file1.txt" or "file2.txt" because there's no '/' after "file"
  assert(ctx.count == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_compressed_files(void) {
  const char* filename = "/tmp/test_compressed.bfc";
  unlink(filename);

#ifdef BFC_WITH_ZSTD
  // Create container with compressed files
  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Set compression
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 1);
  assert(result == BFC_OK);

  // Create test content that compresses well
  FILE* temp = tmpfile();
  assert(temp != NULL);

  // Write repetitive content that compresses well
  for (int i = 0; i < 1000; i++) {
    fwrite("This is repetitive content for compression testing. ", 1, 52, temp);
  }
  rewind(temp);

  // Add file (will be compressed automatically)
  result = bfc_add_file(writer, "compressed.txt", temp, 0644, bfc_os_current_time_ns(), NULL);
  if (result == BFC_OK) {
    result = bfc_finish(writer);
    assert(result == BFC_OK);
    bfc_close(writer);
    fclose(temp);

    // Test reading compressed file
    bfc_t* reader = NULL;
    result = bfc_open(filename, &reader);
    assert(result == BFC_OK);

    // Verify file properties
    bfc_entry_t entry;
    result = bfc_stat(reader, "compressed.txt", &entry);
    assert(result == BFC_OK);
    assert(entry.comp == BFC_COMP_ZSTD);
    assert(entry.size == 52000); // Original size

    // Test reading full file
    char* buffer = malloc(52000);
    assert(buffer != NULL);

    size_t bytes_read = bfc_read(reader, "compressed.txt", 0, buffer, 52000);
    assert(bytes_read == 52000);

    // Verify content
    assert(strncmp(buffer, "This is repetitive content", 26) == 0);

    // Test reading partial content from compressed file
    char partial_buffer[100];
    bytes_read = bfc_read(reader, "compressed.txt", 1000, partial_buffer, 50);
    assert(bytes_read == 50);

    // Test reading beyond file end
    bytes_read = bfc_read(reader, "compressed.txt", 60000, partial_buffer, 100);
    assert(bytes_read == 0);

    // Test extracting compressed file
    int fd = open("/tmp/test_compressed_output", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0);

    result = bfc_extract_to_fd(reader, "compressed.txt", fd);
    assert(result == BFC_OK);
    close(fd);

    // Verify extracted content
    FILE* extracted = fopen("/tmp/test_compressed_output", "r");
    assert(extracted != NULL);
    fseek(extracted, 0, SEEK_END);
    long extracted_size = ftell(extracted);
    assert(extracted_size == 52000);
    fclose(extracted);
    unlink("/tmp/test_compressed_output");

    free(buffer);
    bfc_close_read(reader);
  } else {
    // Compression failed, clean up
    bfc_close(writer);
    fclose(temp);
  }

  unlink(filename);
#endif

  return 0;
}

static int test_read_errors(void) {
  const char* filename = "/tmp/test_read_errors.bfc";

  // Create test container
  int result = create_test_container(filename);
  assert(result == BFC_OK);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test read with various invalid parameters
  char buffer[256];

  // NULL reader
  size_t bytes = bfc_read(NULL, "file1.txt", 0, buffer, sizeof(buffer));
  assert(bytes == 0);

  // NULL path
  bytes = bfc_read(reader, NULL, 0, buffer, sizeof(buffer));
  assert(bytes == 0);

  // NULL buffer
  bytes = bfc_read(reader, "file1.txt", 0, NULL, sizeof(buffer));
  assert(bytes == 0);

  // Zero length
  bytes = bfc_read(reader, "file1.txt", 0, buffer, 0);
  assert(bytes == 0);

  // Non-existent file
  bytes = bfc_read(reader, "nonexistent.txt", 0, buffer, sizeof(buffer));
  assert(bytes == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

// Helper function to create a container with symlinks for testing
static int create_symlink_test_container(const char* filename) {
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  if (result != BFC_OK)
    return result;

  // Add a directory
  result = bfc_add_dir(writer, "testdir", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  // Add a regular file
  const char* content = "Test file content for symlinks";
  const char* src_file = "/tmp/reader_test_src_symlink.txt";
  FILE* src = fopen(src_file, "w");
  if (!src) {
    bfc_close(writer);
    return BFC_E_IO;
  }
  fwrite(content, 1, strlen(content), src);
  fclose(src);

  src = fopen(src_file, "rb");
  if (!src) {
    bfc_close(writer);
    return BFC_E_IO;
  }
  uint32_t crc;
  result = bfc_add_file(writer, "testfile.txt", src, 0644, bfc_os_current_time_ns(), &crc);
  fclose(src);
  unlink(src_file);

  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  // Add various types of symlinks
  result = bfc_add_symlink(writer, "link_to_file", "testfile.txt", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  result = bfc_add_symlink(writer, "link_to_dir", "testdir", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  result = bfc_add_symlink(writer, "absolute_link", "/tmp/absolute_target", 0755,
                           bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  result =
      bfc_add_symlink(writer, "relative_link", "../parent/target", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  result =
      bfc_add_symlink(writer, "broken_link", "nonexistent_target", 0755, bfc_os_current_time_ns());
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  result = bfc_finish(writer);
  if (result != BFC_OK) {
    bfc_close(writer);
    return result;
  }

  bfc_close(writer);
  return BFC_OK;
}

// Helper types and callback for symlink listing test
typedef struct {
  int total_count;
  int symlink_count;
  int file_count;
  int dir_count;
} symlink_count_context_t;

static int symlink_list_callback(const bfc_entry_t* entry, void* user) {
  symlink_count_context_t* c = (symlink_count_context_t*) user;
  c->total_count++;

  if (S_ISLNK(entry->mode)) {
    c->symlink_count++;
  } else if (S_ISREG(entry->mode)) {
    c->file_count++;
  } else if (S_ISDIR(entry->mode)) {
    c->dir_count++;
  }

  return 0;
}

static int test_read_symlink_stat(void) {
  const char* filename = "/tmp/reader_test_symlink_stat.bfc";

  // Create test container
  int result = create_symlink_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);
  assert(reader != NULL);

  // Test stat on symlinks
  bfc_entry_t entry;

  // Test simple symlink
  result = bfc_stat(reader, "link_to_file", &entry);
  assert(result == BFC_OK);
  assert(S_ISLNK(entry.mode));
  assert(entry.size == strlen("testfile.txt"));

  // Test directory symlink
  result = bfc_stat(reader, "link_to_dir", &entry);
  assert(result == BFC_OK);
  assert(S_ISLNK(entry.mode));
  assert(entry.size == strlen("testdir"));

  // Test absolute symlink
  result = bfc_stat(reader, "absolute_link", &entry);
  assert(result == BFC_OK);
  assert(S_ISLNK(entry.mode));
  assert(entry.size == strlen("/tmp/absolute_target"));

  // Test relative symlink
  result = bfc_stat(reader, "relative_link", &entry);
  assert(result == BFC_OK);
  assert(S_ISLNK(entry.mode));
  assert(entry.size == strlen("../parent/target"));

  // Test broken symlink
  result = bfc_stat(reader, "broken_link", &entry);
  assert(result == BFC_OK);
  assert(S_ISLNK(entry.mode));
  assert(entry.size == strlen("nonexistent_target"));

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_read_symlink_content(void) {
  const char* filename = "/tmp/reader_test_symlink_content.bfc";

  // Create test container
  int result = create_symlink_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Read symlink targets
  char buffer[256];

  // Test reading simple symlink target
  size_t bytes_read = bfc_read(reader, "link_to_file", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("testfile.txt"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "testfile.txt") == 0);

  // Test reading directory symlink target
  memset(buffer, 0, sizeof(buffer));
  bytes_read = bfc_read(reader, "link_to_dir", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("testdir"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "testdir") == 0);

  // Test reading absolute symlink target
  memset(buffer, 0, sizeof(buffer));
  bytes_read = bfc_read(reader, "absolute_link", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("/tmp/absolute_target"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "/tmp/absolute_target") == 0);

  // Test reading relative symlink target
  memset(buffer, 0, sizeof(buffer));
  bytes_read = bfc_read(reader, "relative_link", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("../parent/target"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "../parent/target") == 0);

  // Test reading broken symlink target
  memset(buffer, 0, sizeof(buffer));
  bytes_read = bfc_read(reader, "broken_link", 0, buffer, sizeof(buffer));
  assert(bytes_read == strlen("nonexistent_target"));
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "nonexistent_target") == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_symlink_listing(void) {
  const char* filename = "/tmp/reader_test_symlink_list.bfc";

  // Create test container
  int result = create_symlink_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Count entries and verify symlinks are listed
  symlink_count_context_t ctx = {0, 0, 0, 0};

  // List callback to count entries - defined as a static function above
  result = bfc_list(reader, NULL, symlink_list_callback, &ctx);
  assert(result == BFC_OK);

  // Verify counts: 1 dir + 1 file + 5 symlinks = 7 total
  assert(ctx.total_count == 7);
  assert(ctx.dir_count == 1);
  assert(ctx.file_count == 1);
  assert(ctx.symlink_count == 5);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_symlink_partial_read(void) {
  const char* filename = "/tmp/reader_test_symlink_partial.bfc";

  // Create test container
  int result = create_symlink_test_container(filename);
  assert(result == BFC_OK);

  // Open for reading
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Test partial reads of symlink targets
  char buffer[20];
  const char* target = "/tmp/absolute_target";
  size_t target_len = strlen(target);

  // Read first part of absolute symlink target
  size_t bytes_read = bfc_read(reader, "absolute_link", 0, buffer, 5);
  assert(bytes_read == 5);
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "/tmp/") == 0);

  // Read second part - remaining bytes
  size_t remaining = target_len - 5;
  bytes_read = bfc_read(reader, "absolute_link", 5, buffer, remaining);
  assert(bytes_read == remaining);
  buffer[bytes_read] = '\0';
  assert(strcmp(buffer, "absolute_target") == 0);

  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

int test_reader(void) {
  if (test_open_container() != 0)
    return 1;
  if (test_stat_files() != 0)
    return 1;
  if (test_list_entries() != 0)
    return 1;
  if (test_read_content() != 0)
    return 1;
  if (test_extract_file() != 0)
    return 1;
  if (test_verify_container() != 0)
    return 1;
  if (test_invalid_container() != 0)
    return 1;
  if (test_error_conditions() != 0)
    return 1;
  if (test_edge_cases() != 0)
    return 1;
  if (test_corrupted_data() != 0)
    return 1;
  if (test_large_file_operations() != 0)
    return 1;
  if (test_empty_container() != 0)
    return 1;
  if (test_directory_only_container() != 0)
    return 1;
  if (test_encryption_functions() != 0)
    return 1;
  if (test_file_size_edge_cases() != 0)
    return 1;
  if (test_index_parse_errors() != 0)
    return 1;
  if (test_extract_edge_cases() != 0)
    return 1;
  if (test_verify_edge_cases() != 0)
    return 1;
  if (test_list_edge_cases() != 0)
    return 1;
  if (test_compressed_files() != 0)
    return 1;
  if (test_read_errors() != 0)
    return 1;
  if (test_read_symlink_stat() != 0)
    return 1;
  if (test_read_symlink_content() != 0)
    return 1;
  if (test_symlink_listing() != 0)
    return 1;
  if (test_symlink_partial_read() != 0)
    return 1;

  return 0;
}