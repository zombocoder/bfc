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

static int test_valid_paths(void) {
  char* norm;

  // Simple path
  int result = bfc_path_normalize("hello.txt", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "hello.txt") == 0);
  bfc_path_free(norm);

  // Path with directory
  result = bfc_path_normalize("dir/file.txt", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "dir/file.txt") == 0);
  bfc_path_free(norm);

  // Path with multiple directories
  result = bfc_path_normalize("a/b/c/file.txt", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "a/b/c/file.txt") == 0);
  bfc_path_free(norm);

  return 0;
}

static int test_path_normalization(void) {
  char* norm;

  // Remove redundant slashes
  int result = bfc_path_normalize("dir//file.txt", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "dir/file.txt") == 0);
  bfc_path_free(norm);

  // Remove trailing slash
  result = bfc_path_normalize("dir/", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "dir") == 0);
  bfc_path_free(norm);

  // Multiple redundant slashes
  result = bfc_path_normalize("a///b//c", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "a/b/c") == 0);
  bfc_path_free(norm);

  return 0;
}

static int test_invalid_paths(void) {
  char* norm;

  // Empty path
  int result = bfc_path_normalize("", &norm);
  assert(result == BFC_E_INVAL);

  // NULL path
  result = bfc_path_normalize(NULL, &norm);
  assert(result == BFC_E_INVAL);

  // Absolute path
  result = bfc_path_normalize("/absolute", &norm);
  assert(result == BFC_E_INVAL);

  // Path with .. component
  result = bfc_path_normalize("../file.txt", &norm);
  assert(result == BFC_E_INVAL);

  result = bfc_path_normalize("dir/../file.txt", &norm);
  assert(result == BFC_E_INVAL);

  result = bfc_path_normalize("dir/..", &norm);
  assert(result == BFC_E_INVAL);

  // Path that becomes empty after normalization
  result = bfc_path_normalize("/", &norm);
  assert(result == BFC_E_INVAL);

  return 0;
}

static int test_path_validation(void) {
  // Valid paths
  assert(bfc_path_validate("file.txt") == BFC_OK);
  assert(bfc_path_validate("dir/file.txt") == BFC_OK);
  assert(bfc_path_validate("a/b/c") == BFC_OK);

  // Invalid paths
  assert(bfc_path_validate("") != BFC_OK);
  assert(bfc_path_validate("/absolute") != BFC_OK);
  assert(bfc_path_validate("../relative") != BFC_OK);
  assert(bfc_path_validate("dir/../other") != BFC_OK);

  return 0;
}

static int test_edge_cases(void) {
  char* norm;

  // Single character
  int result = bfc_path_normalize("a", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, "a") == 0);
  bfc_path_free(norm);

  // Dot file
  result = bfc_path_normalize(".hidden", &norm);
  assert(result == BFC_OK);
  assert(strcmp(norm, ".hidden") == 0);
  bfc_path_free(norm);

  // Just dot (current directory) - should be invalid
  result = bfc_path_normalize(".", &norm);
  assert(result == BFC_E_INVAL);

  return 0;
}

int test_path(void) {
  if (test_valid_paths() != 0)
    return 1;
  if (test_path_normalization() != 0)
    return 1;
  if (test_invalid_paths() != 0)
    return 1;
  if (test_path_validation() != 0)
    return 1;
  if (test_edge_cases() != 0)
    return 1;

  return 0;
}