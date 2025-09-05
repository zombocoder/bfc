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
#include <bfc.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/memfd.h>
#include <sys/syscall.h>
#endif
#endif

int bfc_os_open_read(const char* filename, FILE** out) {
  if (!filename || !out) {
    return BFC_E_INVAL;
  }

  FILE* file = fopen(filename, "rb");
  if (!file) {
    return BFC_E_IO;
  }

  *out = file;
  return BFC_OK;
}

int bfc_os_open_write(const char* filename, FILE** out) {
  if (!filename || !out) {
    return BFC_E_INVAL;
  }

  // Open in read/write binary mode to allow both writing and reading back
  FILE* file = fopen(filename, "wb+");
  if (!file) {
    return BFC_E_IO;
  }

  *out = file;
  return BFC_OK;
}

int bfc_os_close(FILE* file) {
  if (!file) {
    return BFC_OK;
  }

  int result = fclose(file);
  return result == 0 ? BFC_OK : BFC_E_IO;
}

int bfc_os_sync(FILE* file) {
  if (!file) {
    return BFC_E_INVAL;
  }

  if (fflush(file) != 0) {
    return BFC_E_IO;
  }

#ifdef _WIN32
  int fd = _fileno(file);
  return _commit(fd) == 0 ? BFC_OK : BFC_E_IO;
#else
  int fd = fileno(file);
  return fdatasync(fd) == 0 ? BFC_OK : BFC_E_IO;
#endif
}

int bfc_os_sync_dir(const char* dirname) {
  if (!dirname) {
    return BFC_E_INVAL;
  }

#ifdef _WIN32
  // Windows doesn't require directory sync
  return BFC_OK;
#else
  int fd = open(dirname, O_RDONLY);
  if (fd < 0) {
    return BFC_E_IO;
  }

  int result = fsync(fd) == 0 ? BFC_OK : BFC_E_IO;
  close(fd);
  return result;
#endif
}

int bfc_os_get_size(FILE* file, uint64_t* size) {
  if (!file || !size) {
    return BFC_E_INVAL;
  }

  long pos = ftell(file);
  if (pos < 0) {
    return BFC_E_IO;
  }

  if (fseek(file, 0, SEEK_END) != 0) {
    return BFC_E_IO;
  }

  long end_pos = ftell(file);
  if (end_pos < 0) {
    return BFC_E_IO;
  }

  if (fseek(file, pos, SEEK_SET) != 0) {
    return BFC_E_IO;
  }

  *size = (uint64_t) end_pos;
  return BFC_OK;
}

int bfc_os_seek(FILE* file, int64_t offset, int whence) {
  if (!file) {
    return BFC_E_INVAL;
  }

#ifdef _WIN32
  return _fseeki64(file, offset, whence) == 0 ? BFC_OK : BFC_E_IO;
#else
  return fseeko(file, (off_t) offset, whence) == 0 ? BFC_OK : BFC_E_IO;
#endif
}

int64_t bfc_os_tell(FILE* file) {
  if (!file) {
    return -1;
  }

#ifdef _WIN32
  return _ftelli64(file);
#else
  return (int64_t) ftello(file);
#endif
}

void* bfc_os_mmap(FILE* file, size_t size, size_t offset) {
#ifdef _WIN32
  // Windows memory mapping not implemented in v1
  return NULL;
#else
  if (!file || size == 0) {
    return NULL;
  }

  int fd = fileno(file);
  void* addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, (off_t) offset);
  return (addr == MAP_FAILED) ? NULL : addr;
#endif
}

int bfc_os_munmap(void* addr, size_t size) {
#ifdef _WIN32
  return BFC_E_INVAL;
#else
  if (!addr || size == 0) {
    return BFC_E_INVAL;
  }

  return munmap(addr, size) == 0 ? BFC_OK : BFC_E_IO;
#endif
}

int bfc_os_create_temp_exec(char** path, FILE** file) {
  if (!path || !file) {
    return BFC_E_INVAL;
  }

#ifdef _WIN32
  char temp_dir[MAX_PATH];
  char temp_file[MAX_PATH];

  if (GetTempPath(sizeof(temp_dir), temp_dir) == 0) {
    return BFC_E_IO;
  }

  if (GetTempFileName(temp_dir, "bfc", 0, temp_file) == 0) {
    return BFC_E_IO;
  }

  FILE* f = fopen(temp_file, "wb+");
  if (!f) {
    return BFC_E_IO;
  }

  *path = strdup(temp_file);
  *file = f;
  return BFC_OK;
#else
  char template[] = "/tmp/bfc_exec_XXXXXX";
  int fd = mkstemp(template);
  if (fd < 0) {
    return BFC_E_IO;
  }

  FILE* f = fdopen(fd, "wb+");
  if (!f) {
    close(fd);
    unlink(template);
    return BFC_E_IO;
  }

  *path = strdup(template);
  *file = f;
  return BFC_OK;
#endif
}

int bfc_os_create_memfd(const char* name, FILE** file) {
  if (!name || !file) {
    return BFC_E_INVAL;
  }

#ifdef __linux__
  int fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);
  if (fd < 0) {
    return BFC_E_IO;
  }

  FILE* f = fdopen(fd, "wb+");
  if (!f) {
    close(fd);
    return BFC_E_IO;
  }

  *file = f;
  return BFC_OK;
#else
  // Fall back to temporary file
  char* temp_path;
  int result = bfc_os_create_temp_exec(&temp_path, file);
  if (result == BFC_OK) {
    // Unlink immediately so it gets cleaned up
#ifndef _WIN32
    unlink(temp_path);
#endif
    free(temp_path);
  }
  return result;
#endif
}

int bfc_os_advise_sequential(FILE* file) {
#if defined(__linux__) && defined(POSIX_FADV_SEQUENTIAL)
  if (!file)
    return BFC_E_INVAL;
  int fd = fileno(file);
  posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#else
  (void) file; // Suppress unused parameter warning
#endif
  return BFC_OK;
}

int bfc_os_advise_random(FILE* file) {
#if defined(__linux__) && defined(POSIX_FADV_RANDOM)
  if (!file)
    return BFC_E_INVAL;
  int fd = fileno(file);
  posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);
#else
  (void) file; // Suppress unused parameter warning
#endif
  return BFC_OK;
}

int bfc_os_advise_nocache(FILE* file) {
#if defined(__APPLE__) && defined(F_NOCACHE)
  if (!file)
    return BFC_E_INVAL;
  int fd = fileno(file);
  fcntl(fd, F_NOCACHE, 1);
#elif defined(__linux__) && defined(POSIX_FADV_DONTNEED)
  if (!file)
    return BFC_E_INVAL;
  int fd = fileno(file);
  posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
  return BFC_OK;
}

uint64_t bfc_os_current_time_ns(void) {
  struct timespec ts;
#ifdef _WIN32
  // Windows implementation would need timespec_get or similar
  timespec_get(&ts, TIME_UTC);
#else
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
  return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

uint64_t bfc_os_file_mtime_ns(const char* filename) {
  if (!filename) {
    return 0;
  }

  struct stat st;
  if (stat(filename, &st) != 0) {
    return 0;
  }

#ifdef __APPLE__
  return (uint64_t) st.st_mtimespec.tv_sec * 1000000000ULL + (uint64_t) st.st_mtimespec.tv_nsec;
#elif defined(__linux__)
  return (uint64_t) st.st_mtim.tv_sec * 1000000000ULL + (uint64_t) st.st_mtim.tv_nsec;
#else
  return (uint64_t) st.st_mtime * 1000000000ULL;
#endif
}

int bfc_os_mkdir_p(const char* path, uint32_t mode) {
  if (!path) {
    return BFC_E_INVAL;
  }

  char* path_copy = strdup(path);
  if (!path_copy) {
    return BFC_E_IO;
  }

  char* p = path_copy;
  while (*p) {
    if (*p == '/') {
      *p = '\0';
      if (strlen(path_copy) > 0) {
#ifdef _WIN32
        _mkdir(path_copy);
#else
        mkdir(path_copy, mode);
#endif
      }
      *p = '/';
    }
    p++;
  }

  // Create the final directory
#ifdef _WIN32
  int result = _mkdir(path_copy) == 0 || errno == EEXIST ? BFC_OK : BFC_E_IO;
#else
  int result = mkdir(path_copy, mode) == 0 || errno == EEXIST ? BFC_OK : BFC_E_IO;
#endif

  free(path_copy);
  return result;
}

int bfc_os_path_exists(const char* path) {
  if (!path) {
    return 0;
  }

  struct stat st;
  return stat(path, &st) == 0;
}

int bfc_os_is_executable(const char* path) {
  if (!path) {
    return 0;
  }

  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }

#ifdef _WIN32
  // On Windows, check file extension
  const char* ext = strrchr(path, '.');
  return ext && (strcmp(ext, ".exe") == 0 || strcmp(ext, ".com") == 0 || strcmp(ext, ".bat") == 0);
#else
  return (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
#endif
}