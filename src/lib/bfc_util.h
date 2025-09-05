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

// Utility functions for BFC implementation

// Dynamic array for index entries
typedef struct {
  void* data;
  size_t size;
  size_t capacity;
  size_t elem_size;
} bfc_array_t;

int bfc_array_init(bfc_array_t* arr, size_t elem_size);
void bfc_array_destroy(bfc_array_t* arr);
int bfc_array_push(bfc_array_t* arr, const void* elem);
void* bfc_array_get(bfc_array_t* arr, size_t index);
size_t bfc_array_size(const bfc_array_t* arr);

// String utilities
char* bfc_strdup(const char* str);
int bfc_strcmp(const char* a, const char* b);

// Memory utilities
void* bfc_malloc(size_t size);
void* bfc_calloc(size_t count, size_t size);
void* bfc_realloc(void* ptr, size_t size);
void bfc_free(void* ptr);

// Min/max macros
#define BFC_MIN(a, b) ((a) < (b) ? (a) : (b))
#define BFC_MAX(a, b) ((a) > (b) ? (a) : (b))