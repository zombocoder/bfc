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

#include "bfc_util.h"
#include <assert.h>
#include <bfc.h>
#include <stdio.h>
#include <string.h>

static int test_array_operations(void) {
  bfc_array_t arr;

  // Initialize
  int result = bfc_array_init(&arr, sizeof(int));
  assert(result == BFC_OK);
  assert(bfc_array_size(&arr) == 0);

  // Push elements
  int value1 = 42;
  result = bfc_array_push(&arr, &value1);
  assert(result == BFC_OK);
  assert(bfc_array_size(&arr) == 1);

  int value2 = 84;
  result = bfc_array_push(&arr, &value2);
  assert(result == BFC_OK);
  assert(bfc_array_size(&arr) == 2);

  // Get elements
  int* retrieved1 = (int*) bfc_array_get(&arr, 0);
  assert(retrieved1 != NULL);
  assert(*retrieved1 == 42);

  int* retrieved2 = (int*) bfc_array_get(&arr, 1);
  assert(retrieved2 != NULL);
  assert(*retrieved2 == 84);

  // Invalid access
  int* invalid = (int*) bfc_array_get(&arr, 2);
  assert(invalid == NULL);

  bfc_array_destroy(&arr);

  return 0;
}

static int test_array_growth(void) {
  bfc_array_t arr;
  int result = bfc_array_init(&arr, sizeof(int));
  assert(result == BFC_OK);

  // Push many elements to test growth
  for (int i = 0; i < 100; i++) {
    result = bfc_array_push(&arr, &i);
    assert(result == BFC_OK);
    assert(bfc_array_size(&arr) == (size_t) (i + 1));
  }

  // Verify all elements
  for (int i = 0; i < 100; i++) {
    int* value = (int*) bfc_array_get(&arr, i);
    assert(value != NULL);
    assert(*value == i);
  }

  bfc_array_destroy(&arr);

  return 0;
}

static int test_string_operations(void) {
  // Test strdup
  char* dup = bfc_strdup("hello");
  assert(dup != NULL);
  assert(strcmp(dup, "hello") == 0);
  bfc_free(dup);

  // Test strdup with NULL
  dup = bfc_strdup(NULL);
  assert(dup == NULL);

  // Test strcmp
  assert(bfc_strcmp("a", "a") == 0);
  assert(bfc_strcmp("a", "b") < 0);
  assert(bfc_strcmp("b", "a") > 0);
  assert(bfc_strcmp(NULL, NULL) == 0);
  assert(bfc_strcmp(NULL, "a") < 0);
  assert(bfc_strcmp("a", NULL) > 0);

  return 0;
}

static int test_memory_operations(void) {
  // Test malloc
  void* ptr = bfc_malloc(100);
  assert(ptr != NULL);
  bfc_free(ptr);

  // Test calloc
  ptr = bfc_calloc(10, 10);
  assert(ptr != NULL);

  // Verify it's zeroed
  char* bytes = (char*) ptr;
  for (int i = 0; i < 100; i++) {
    assert(bytes[i] == 0);
  }

  // Test realloc
  ptr = bfc_realloc(ptr, 200);
  assert(ptr != NULL);
  bfc_free(ptr);

  // Test free with NULL (should not crash)
  bfc_free(NULL);

  return 0;
}

int test_util(void) {
  if (test_array_operations() != 0)
    return 1;
  if (test_array_growth() != 0)
    return 1;
  if (test_string_operations() != 0)
    return 1;
  if (test_memory_operations() != 0)
    return 1;

  return 0;
}