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
#include <bfc.h>
#include <stdlib.h>
#include <string.h>

int bfc_array_init(bfc_array_t* arr, size_t elem_size) {
  if (!arr || elem_size == 0) {
    return BFC_E_INVAL;
  }

  arr->data = NULL;
  arr->size = 0;
  arr->capacity = 0;
  arr->elem_size = elem_size;
  return BFC_OK;
}

void bfc_array_destroy(bfc_array_t* arr) {
  if (arr) {
    free(arr->data);
    arr->data = NULL;
    arr->size = 0;
    arr->capacity = 0;
  }
}

int bfc_array_push(bfc_array_t* arr, const void* elem) {
  if (!arr || !elem) {
    return BFC_E_INVAL;
  }

  if (arr->size >= arr->capacity) {
    size_t new_capacity = arr->capacity ? arr->capacity * 2 : 8;
    void* new_data = realloc(arr->data, new_capacity * arr->elem_size);
    if (!new_data) {
      return BFC_E_IO;
    }
    arr->data = new_data;
    arr->capacity = new_capacity;
  }

  char* ptr = (char*) arr->data + (arr->size * arr->elem_size);
  memcpy(ptr, elem, arr->elem_size);
  arr->size++;

  return BFC_OK;
}

void* bfc_array_get(bfc_array_t* arr, size_t index) {
  if (!arr || index >= arr->size) {
    return NULL;
  }

  return (char*) arr->data + (index * arr->elem_size);
}

size_t bfc_array_size(const bfc_array_t* arr) { return arr ? arr->size : 0; }

char* bfc_strdup(const char* str) {
  if (!str) {
    return NULL;
  }

  size_t len = strlen(str);
  char* copy = malloc(len + 1);
  if (copy) {
    memcpy(copy, str, len + 1);
  }
  return copy;
}

int bfc_strcmp(const char* a, const char* b) {
  if (!a && !b)
    return 0;
  if (!a)
    return -1;
  if (!b)
    return 1;
  return strcmp(a, b);
}

void* bfc_malloc(size_t size) { return malloc(size); }

void* bfc_calloc(size_t count, size_t size) { return calloc(count, size); }

void* bfc_realloc(void* ptr, size_t size) { return realloc(ptr, size); }

void bfc_free(void* ptr) { free(ptr); }