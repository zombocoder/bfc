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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int test_file_operations(void) {
  const char* test_file = "/tmp/test_bfc_os.dat";

  // Test open for writing
  FILE* file = NULL;
  int result = bfc_os_open_write(test_file, &file);
  assert(result == BFC_OK);
  assert(file != NULL);

  // Write some test data
  const char* test_data = "Hello, BFC OS test!";
  size_t data_len = strlen(test_data);
  fwrite(test_data, 1, data_len, file);

  // Test sync
  result = bfc_os_sync(file);
  assert(result == BFC_OK);

  // Test get size
  uint64_t size;
  result = bfc_os_get_size(file, &size);
  assert(result == BFC_OK);
  assert(size == data_len);

  // Test seek and tell
  result = bfc_os_seek(file, 0, SEEK_SET);
  assert(result == BFC_OK);

  int64_t pos = bfc_os_tell(file);
  assert(pos == 0);

  // Test seek to end
  result = bfc_os_seek(file, 0, SEEK_END);
  assert(result == BFC_OK);

  pos = bfc_os_tell(file);
  assert(pos == (int64_t) data_len);

  // Close file
  result = bfc_os_close(file);
  assert(result == BFC_OK);

  // Test open for reading
  result = bfc_os_open_read(test_file, &file);
  assert(result == BFC_OK);
  assert(file != NULL);

  // Test reading back the data
  char buffer[256] = {0};
  size_t read_len = fread(buffer, 1, sizeof(buffer), file);
  assert(read_len == data_len);
  assert(memcmp(buffer, test_data, data_len) == 0);

  // Test mmap functionality
  result = bfc_os_seek(file, 0, SEEK_SET);
  assert(result == BFC_OK);

  void* mapped = bfc_os_mmap(file, data_len, 0);
#ifdef _WIN32
  // Windows mmap not implemented, should return NULL
  assert(mapped == NULL);
#else
  // Unix should work
  if (mapped != NULL) {
    assert(memcmp(mapped, test_data, data_len) == 0);
    result = bfc_os_munmap(mapped, data_len);
    assert(result == BFC_OK);
  }
#endif

  // Test advisory functions
  result = bfc_os_advise_sequential(file);
  assert(result == BFC_OK);

  result = bfc_os_advise_random(file);
  assert(result == BFC_OK);

  result = bfc_os_advise_nocache(file);
  assert(result == BFC_OK);

  result = bfc_os_close(file);
  assert(result == BFC_OK);

  // Clean up
  unlink(test_file);

  return 0;
}

static int test_error_conditions(void) {
  // Test invalid parameters
  FILE* file = NULL;
  int result;

  // NULL filename
  result = bfc_os_open_read(NULL, &file);
  assert(result == BFC_E_INVAL);

  result = bfc_os_open_write(NULL, &file);
  assert(result == BFC_E_INVAL);

  // NULL output pointer
  result = bfc_os_open_read("/tmp/test", NULL);
  assert(result == BFC_E_INVAL);

  result = bfc_os_open_write("/tmp/test", NULL);
  assert(result == BFC_E_INVAL);

  // Non-existent file for reading
  result = bfc_os_open_read("/tmp/nonexistent_file_12345", &file);
  assert(result == BFC_E_IO);

  // Test invalid file operations
  uint64_t size;
  result = bfc_os_get_size(NULL, &size);
  assert(result == BFC_E_INVAL);

  result = bfc_os_get_size(stdin, NULL);
  assert(result == BFC_E_INVAL);

  result = bfc_os_sync(NULL);
  assert(result == BFC_E_INVAL);

  result = bfc_os_seek(NULL, 0, SEEK_SET);
  assert(result == BFC_E_INVAL);

  int64_t pos = bfc_os_tell(NULL);
  assert(pos == -1);

  // Test mmap with invalid params
  void* mapped = bfc_os_mmap(NULL, 100, 0);
  assert(mapped == NULL);

  mapped = bfc_os_mmap(stdin, 0, 0);
  assert(mapped == NULL);

  result = bfc_os_munmap(NULL, 100);
  assert(result == BFC_E_INVAL);

  result = bfc_os_munmap((void*) 0x1000, 0);
  assert(result == BFC_E_INVAL);

  return 0;
}

static int test_directory_operations(void) {
  const char* test_dir = "/tmp/bfc_test_dir_12345";

  // Test directory sync (should handle non-existent directory)
  int result = bfc_os_sync_dir(test_dir);
  assert(result == BFC_E_IO || result == BFC_OK); // May fail on non-existent dir

  // Test mkdir_p
  char nested_path[256];
  snprintf(nested_path, sizeof(nested_path), "%s/a/b/c", test_dir);

  result = bfc_os_mkdir_p(nested_path, 0755);
  assert(result == BFC_OK);

  // Verify directories were created
  assert(bfc_os_path_exists(test_dir));

  char partial_path[256];
  snprintf(partial_path, sizeof(partial_path), "%s/a", test_dir);
  assert(bfc_os_path_exists(partial_path));

  snprintf(partial_path, sizeof(partial_path), "%s/a/b", test_dir);
  assert(bfc_os_path_exists(partial_path));

  assert(bfc_os_path_exists(nested_path));

  // Test sync on existing directory
  result = bfc_os_sync_dir(test_dir);
  assert(result == BFC_OK);

  // Test mkdir_p with NULL
  result = bfc_os_mkdir_p(NULL, 0755);
  assert(result == BFC_E_INVAL);

  // Test path_exists with NULL
  assert(bfc_os_path_exists(NULL) == 0);

  // Clean up
  system("rm -rf /tmp/bfc_test_dir_12345");

  return 0;
}

static int test_temp_file_operations(void) {
  char* temp_path = NULL;
  FILE* temp_file = NULL;

  // Test create_temp_exec
  int result = bfc_os_create_temp_exec(&temp_path, &temp_file);
  assert(result == BFC_OK);
  assert(temp_path != NULL);
  assert(temp_file != NULL);

  // Write some data to verify it works
  const char* test_data = "temporary file test";
  fwrite(test_data, 1, strlen(test_data), temp_file);
  fflush(temp_file);

  // Verify file exists
  assert(bfc_os_path_exists(temp_path));

  fclose(temp_file);
  unlink(temp_path);
  free(temp_path);

  // Test with NULL parameters
  result = bfc_os_create_temp_exec(NULL, &temp_file);
  assert(result == BFC_E_INVAL);

  result = bfc_os_create_temp_exec(&temp_path, NULL);
  assert(result == BFC_E_INVAL);

  // Test create_memfd
  temp_file = NULL;
  result = bfc_os_create_memfd("test_memfd", &temp_file);
  assert(result == BFC_OK);
  assert(temp_file != NULL);

  // Write and read back data
  fwrite(test_data, 1, strlen(test_data), temp_file);
  rewind(temp_file);

  char buffer[256] = {0};
  size_t read_len = fread(buffer, 1, sizeof(buffer), temp_file);
  assert(read_len == strlen(test_data));
  assert(strcmp(buffer, test_data) == 0);

  fclose(temp_file);

  // Test with NULL parameters
  result = bfc_os_create_memfd(NULL, &temp_file);
  assert(result == BFC_E_INVAL);

  result = bfc_os_create_memfd("test", NULL);
  assert(result == BFC_E_INVAL);

  return 0;
}

static int test_time_operations(void) {
  // Test current time
  uint64_t time1 = bfc_os_current_time_ns();
  assert(time1 > 0);

  // Sleep a bit and test again
  usleep(10000); // 10ms

  uint64_t time2 = bfc_os_current_time_ns();
  assert(time2 > time1);
  assert(time2 - time1 >= 10000000); // At least 10ms difference

  // Test file mtime
  const char* test_file = "/tmp/test_mtime.dat";
  FILE* file = fopen(test_file, "w");
  assert(file != NULL);
  fprintf(file, "test");
  fclose(file);

  uint64_t mtime = bfc_os_file_mtime_ns(test_file);
  assert(mtime > 0);

  // Test with non-existent file
  uint64_t bad_mtime = bfc_os_file_mtime_ns("/tmp/nonexistent_file_12345");
  assert(bad_mtime == 0);

  // Test with NULL
  uint64_t null_mtime = bfc_os_file_mtime_ns(NULL);
  assert(null_mtime == 0);

  unlink(test_file);

  return 0;
}

static int test_executable_check(void) {
  // Create a test file
  const char* test_file = "/tmp/test_exec.sh";
  FILE* file = fopen(test_file, "w");
  assert(file != NULL);
  fprintf(file, "#!/bin/sh\necho test\n");
  fclose(file);

  // Initially not executable
  assert(bfc_os_is_executable(test_file) == 0);

  // Make it executable
  chmod(test_file, 0755);
  assert(bfc_os_is_executable(test_file) == 1);

  // Test with NULL
  assert(bfc_os_is_executable(NULL) == 0);

  // Test with non-existent file
  assert(bfc_os_is_executable("/tmp/nonexistent_exec_12345") == 0);

  unlink(test_file);

  return 0;
}

static int test_close_null_file(void) {
  // Test that closing NULL file is safe
  int result = bfc_os_close(NULL);
  assert(result == BFC_OK);

  return 0;
}

static int test_sync_directory_null(void) {
  // Test sync directory with NULL
  int result = bfc_os_sync_dir(NULL);
  assert(result == BFC_E_INVAL);

  return 0;
}

int test_os(void) {
  if (test_file_operations() != 0)
    return 1;
  if (test_error_conditions() != 0)
    return 1;
  if (test_directory_operations() != 0)
    return 1;
  if (test_temp_file_operations() != 0)
    return 1;
  if (test_time_operations() != 0)
    return 1;
  if (test_executable_check() != 0)
    return 1;
  if (test_close_null_file() != 0)
    return 1;
  if (test_sync_directory_null() != 0)
    return 1;

  return 0;
}