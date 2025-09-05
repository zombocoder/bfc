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
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

// Cross-platform file operations
int bfc_os_open_read(const char* filename, FILE** out);
int bfc_os_open_write(const char* filename, FILE** out);
int bfc_os_close(FILE* file);
int bfc_os_sync(FILE* file);
int bfc_os_sync_dir(const char* dirname);

// File size and seeking
int bfc_os_get_size(FILE* file, uint64_t* size);
int bfc_os_seek(FILE* file, int64_t offset, int whence);
int64_t bfc_os_tell(FILE* file);

// Memory mapping (optional, returns NULL if not available)
void* bfc_os_mmap(FILE* file, size_t size, size_t offset);
int bfc_os_munmap(void* addr, size_t size);

// Temporary file creation for exec
int bfc_os_create_temp_exec(char** path, FILE** file);
int bfc_os_create_memfd(const char* name, FILE** file);

// File advisory hints
int bfc_os_advise_sequential(FILE* file);
int bfc_os_advise_random(FILE* file);
int bfc_os_advise_nocache(FILE* file);

// Time utilities
uint64_t bfc_os_current_time_ns(void);
uint64_t bfc_os_file_mtime_ns(const char* filename);

// Path utilities
int bfc_os_mkdir_p(const char* path, uint32_t mode);
int bfc_os_path_exists(const char* path);
int bfc_os_is_executable(const char* path);