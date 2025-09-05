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

#include "bfc_os.h"
#include <assert.h>
#include <bfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_create_empty_container(void) {
  const char* filename = "/tmp/test_empty.bfc";

  // Clean up any existing file
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);
  assert(writer != NULL);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  // Verify file exists and has reasonable size
  FILE* file = fopen(filename, "rb");
  assert(file != NULL);

  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  fclose(file);

  // Should have header + minimal index + footer
  assert(size >= 4096 + 8 + 56);

  unlink(filename);
  return 0;
}

static int test_add_single_file(void) {
  const char* filename = "/tmp/test_single.bfc";
  const char* content = "Hello, BFC!";

  // Clean up
  unlink(filename);

  // Create temporary source file
  const char* src_file = "/tmp/test_src.txt";
  FILE* src = fopen(src_file, "w");
  assert(src != NULL);
  fwrite(content, 1, strlen(content), src);
  fclose(src);

  // Create container
  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add file
  src = fopen(src_file, "rb");
  assert(src != NULL);

  uint32_t crc = 0;
  result = bfc_add_file(writer, "hello.txt", src, 0644, bfc_os_current_time_ns(), &crc);
  assert(result == BFC_OK);
  assert(crc != 0);

  fclose(src);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  // Clean up
  unlink(src_file);
  unlink(filename);

  return 0;
}

static int test_add_directory(void) {
  const char* filename = "/tmp/test_dir.bfc";

  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add directory
  result = bfc_add_dir(writer, "testdir", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  unlink(filename);
  return 0;
}

static int test_duplicate_paths(void) {
  const char* filename = "/tmp/test_dup.bfc";

  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add first directory
  result = bfc_add_dir(writer, "samedir", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  // Try to add same path again - should fail
  result = bfc_add_dir(writer, "samedir", 0755, bfc_os_current_time_ns());
  assert(result == BFC_E_EXISTS);

  bfc_close(writer);

  unlink(filename);
  return 0;
}

static int test_invalid_paths(void) {
  const char* filename = "/tmp/test_invalid.bfc";

  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Try invalid paths
  result = bfc_add_dir(writer, "/absolute", 0755, bfc_os_current_time_ns());
  assert(result != BFC_OK);

  result = bfc_add_dir(writer, "../relative", 0755, bfc_os_current_time_ns());
  assert(result != BFC_OK);

  result = bfc_add_dir(writer, "", 0755, bfc_os_current_time_ns());
  assert(result != BFC_OK);

  bfc_close(writer);

  unlink(filename);
  return 0;
}

static int test_multiple_files(void) {
  const char* filename = "/tmp/test_multi.bfc";

  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Create some test files
  const char* files[] = {"file1.txt", "file2.txt", "dir/file3.txt"};
  const char* contents[] = {"Content 1", "Content 2", "Content 3"};
  const int num_files = 3;

  // Add directory first
  result = bfc_add_dir(writer, "dir", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  for (int i = 0; i < num_files; i++) {
    // Create temp source file
    char src_name[64];
    snprintf(src_name, sizeof(src_name), "/tmp/test_src_%d.txt", i);

    FILE* src = fopen(src_name, "w");
    assert(src != NULL);
    fwrite(contents[i], 1, strlen(contents[i]), src);
    fclose(src);

    // Add to container
    src = fopen(src_name, "rb");
    assert(src != NULL);

    result = bfc_add_file(writer, files[i], src, 0644, bfc_os_current_time_ns(), NULL);
    assert(result == BFC_OK);

    fclose(src);
    unlink(src_name);
  }

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  unlink(filename);
  return 0;
}

static int test_error_conditions(void) {
  bfc_t* writer = NULL;

  // Test NULL parameters
  int result = bfc_create(NULL, 4096, 0, &writer);
  assert(result == BFC_E_INVAL);

  result = bfc_create("/tmp/test.bfc", 4096, 0, NULL);
  assert(result == BFC_E_INVAL);

  // Test block size of 0 (should default to header size)
  result = bfc_create("/tmp/test.bfc", 0, 0, &writer);
  assert(result == BFC_OK);
  bfc_close(writer);
  unlink("/tmp/test.bfc");

  // Note: Small block size may be accepted and rounded up
  result = bfc_create("/tmp/test.bfc", 100, 0, &writer);
  if (result == BFC_OK) {
    bfc_close(writer);
    unlink("/tmp/test.bfc");
  } else {
    assert(result == BFC_E_INVAL);
  }

  // Test operations on NULL writer
  FILE* temp = tmpfile();
  assert(temp != NULL);

  result = bfc_add_file(NULL, "test.txt", temp, 0644, 0, NULL);
  assert(result == BFC_E_INVAL);

  result = bfc_add_dir(NULL, "dir", 0755, 0);
  assert(result == BFC_E_INVAL);

  result = bfc_finish(NULL);
  assert(result == BFC_E_INVAL);

  bfc_close(NULL); // Should be safe

  fclose(temp);

  return 0;
}

static int test_file_parameter_validation(void) {
  const char* filename = "/tmp/test_validation.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  FILE* temp = tmpfile();
  assert(temp != NULL);
  fwrite("test", 1, 4, temp);
  rewind(temp);

  // Test NULL path
  result = bfc_add_file(writer, NULL, temp, 0644, 0, NULL);
  assert(result == BFC_E_INVAL);

  // Test empty path
  result = bfc_add_file(writer, "", temp, 0644, 0, NULL);
  assert(result == BFC_E_INVAL);

  // Test NULL file
  result = bfc_add_file(writer, "test.txt", NULL, 0644, 0, NULL);
  assert(result == BFC_E_INVAL);

  // Test directory with NULL path
  result = bfc_add_dir(writer, NULL, 0755, 0);
  assert(result == BFC_E_INVAL);

  // Test directory with empty path
  result = bfc_add_dir(writer, "", 0755, 0);
  assert(result == BFC_E_INVAL);

  fclose(temp);
  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_large_file_handling(void) {
  const char* filename = "/tmp/test_large_writer.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Create a larger file (16KB)
  FILE* large_temp = tmpfile();
  assert(large_temp != NULL);

  for (int i = 0; i < 16384; i++) {
    fputc('X', large_temp);
  }
  rewind(large_temp);

  uint32_t crc;
  result = bfc_add_file(writer, "large.dat", large_temp, 0644, bfc_os_current_time_ns(), &crc);
  assert(result == BFC_OK);
  assert(crc != 0);

  fclose(large_temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_binary_file_handling(void) {
  const char* filename = "/tmp/test_binary.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Create binary data with null bytes
  FILE* binary_temp = tmpfile();
  assert(binary_temp != NULL);

  unsigned char binary_data[256];
  for (int i = 0; i < 256; i++) {
    binary_data[i] = (unsigned char) i;
  }
  fwrite(binary_data, 1, sizeof(binary_data), binary_temp);
  rewind(binary_temp);

  result = bfc_add_file(writer, "binary.dat", binary_temp, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);

  fclose(binary_temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_many_files(void) {
  const char* filename = "/tmp/test_many.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add many small files
  for (int i = 0; i < 50; i++) {
    FILE* temp = tmpfile();
    assert(temp != NULL);

    char content[64];
    snprintf(content, sizeof(content), "File number %d content", i);
    fwrite(content, 1, strlen(content), temp);
    rewind(temp);

    char path[64];
    snprintf(path, sizeof(path), "file_%03d.txt", i);

    result = bfc_add_file(writer, path, temp, 0644, bfc_os_current_time_ns(), NULL);
    assert(result == BFC_OK);

    fclose(temp);
  }

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_deep_directory_structure(void) {
  const char* filename = "/tmp/test_deep.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Create deep directory structure
  const char* dirs[] = {"a", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e", "a/b/c/d/e/f"};

  for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    result = bfc_add_dir(writer, dirs[i], 0755, bfc_os_current_time_ns());
    assert(result == BFC_OK);
  }

  // Add a file in the deepest directory
  FILE* temp = tmpfile();
  assert(temp != NULL);
  fwrite("deep file", 1, 9, temp);
  rewind(temp);

  result = bfc_add_file(writer, "a/b/c/d/e/f/deep.txt", temp, 0644, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);

  fclose(temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_various_permissions(void) {
  const char* filename = "/tmp/test_perms.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Test different directory permissions
  result = bfc_add_dir(writer, "private", 0700, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_add_dir(writer, "public", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  result = bfc_add_dir(writer, "readonly", 0555, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  // Test different file permissions
  FILE* temp = tmpfile();
  assert(temp != NULL);
  fwrite("executable", 1, 10, temp);
  rewind(temp);

  result = bfc_add_file(writer, "script.sh", temp, 0755, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);

  fclose(temp);

  temp = tmpfile();
  assert(temp != NULL);
  fwrite("readonly", 1, 8, temp);
  rewind(temp);

  result = bfc_add_file(writer, "readonly.txt", temp, 0444, bfc_os_current_time_ns(), NULL);
  assert(result == BFC_OK);

  fclose(temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_empty_file(void) {
  const char* filename = "/tmp/test_empty_file.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add empty file
  FILE* empty_temp = tmpfile();
  assert(empty_temp != NULL);
  // Don't write anything - file is empty

  uint32_t crc;
  result = bfc_add_file(writer, "empty.txt", empty_temp, 0644, bfc_os_current_time_ns(), &crc);
  assert(result == BFC_OK);
  // CRC of empty file should be 0
  assert(crc == 0);

  fclose(empty_temp);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

static int test_finish_before_close(void) {
  const char* filename = "/tmp/test_finish_close.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Add something
  result = bfc_add_dir(writer, "test", 0755, bfc_os_current_time_ns());
  assert(result == BFC_OK);

  // Finish
  result = bfc_finish(writer);
  assert(result == BFC_OK);

  // Try to add after finish (should fail)
  result = bfc_add_dir(writer, "test2", 0755, bfc_os_current_time_ns());
  assert(result == BFC_E_INVAL);

  // Try to finish again (should fail)
  result = bfc_finish(writer);
  assert(result == BFC_E_INVAL);

  bfc_close(writer);
  unlink(filename);

  return 0;
}

int test_writer(void) {
  if (test_create_empty_container() != 0)
    return 1;
  if (test_add_single_file() != 0)
    return 1;
  if (test_add_directory() != 0)
    return 1;
  if (test_duplicate_paths() != 0)
    return 1;
  if (test_invalid_paths() != 0)
    return 1;
  if (test_multiple_files() != 0)
    return 1;
  if (test_error_conditions() != 0)
    return 1;
  if (test_file_parameter_validation() != 0)
    return 1;
  if (test_large_file_handling() != 0)
    return 1;
  if (test_binary_file_handling() != 0)
    return 1;
  if (test_many_files() != 0)
    return 1;
  if (test_deep_directory_structure() != 0)
    return 1;
  if (test_various_permissions() != 0)
    return 1;
  if (test_empty_file() != 0)
    return 1;
  if (test_finish_before_close() != 0)
    return 1;

  return 0;
}