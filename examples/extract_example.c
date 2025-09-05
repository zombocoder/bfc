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
#include <bfc.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Callback to collect all file entries for extraction
struct extract_context {
  char** files;
  int count;
  int capacity;
};

static int collect_files(const bfc_entry_t* entry, void* user) {
  struct extract_context* ctx = (struct extract_context*) user;

  // Only collect regular files, skip directories
  if (!S_ISREG(entry->mode)) {
    return 0;
  }

  // Expand array if needed
  if (ctx->count >= ctx->capacity) {
    ctx->capacity = ctx->capacity ? ctx->capacity * 2 : 10;
    ctx->files = realloc(ctx->files, ctx->capacity * sizeof(char*));
    if (!ctx->files) {
      return -1;
    }
  }

  // Store a copy of the path
  ctx->files[ctx->count] = strdup(entry->path);
  if (!ctx->files[ctx->count]) {
    return -1;
  }
  ctx->count++;

  return 0;
}

static int create_directories(const char* path) {
  char* path_copy = strdup(path);
  if (!path_copy)
    return -1;

  char* dir = path_copy;
  char* slash = strchr(dir, '/');

  while (slash) {
    *slash = '\0';

    struct stat st;
    if (stat(dir, &st) != 0) {
      if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        free(path_copy);
        return -1;
      }
    }

    *slash = '/';
    slash = strchr(slash + 1, '/');
  }

  free(path_copy);
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "Usage: %s <container.bfc> [output_directory]\n", argv[0]);
    fprintf(stderr,
            "  If output_directory is not specified, files are extracted to current directory\n");
    return 1;
  }

  const char* container_path = argv[1];
  const char* output_dir = (argc == 3) ? argv[2] : ".";

  // Open the BFC container
  printf("Opening container: %s\n", container_path);

  bfc_t* reader = NULL;
  int result = bfc_open(container_path, &reader);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to open container: %d\n", result);
    return 1;
  }

  // Collect all files in the container
  struct extract_context ctx = {0};
  result = bfc_list(reader, NULL, collect_files, &ctx);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to list container contents: %d\n", result);
    bfc_close_read(reader);
    return 1;
  }

  printf("Found %d files to extract\n", ctx.count);
  if (ctx.count == 0) {
    printf("No files to extract\n");
    bfc_close_read(reader);
    return 0;
  }

  // Create output directory if it doesn't exist
  struct stat st;
  if (stat(output_dir, &st) != 0) {
    if (mkdir(output_dir, 0755) != 0) {
      fprintf(stderr, "Failed to create output directory '%s': %s\n", output_dir, strerror(errno));
      bfc_close_read(reader);
      return 1;
    }
  }

  printf("Extracting to: %s\n\n", output_dir);

  // Extract each file
  for (int i = 0; i < ctx.count; i++) {
    const char* file_path = ctx.files[i];
    printf("Extracting: %s\n", file_path);

    // Create full output path
    char output_path[1024];
    snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, file_path);

    // Create any necessary directories
    if (create_directories(output_path) != 0) {
      fprintf(stderr, "Failed to create directories for: %s\n", output_path);
      continue;
    }

    // Open output file
    int out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
      fprintf(stderr, "Failed to create output file '%s': %s\n", output_path, strerror(errno));
      continue;
    }

    // Extract file content
    result = bfc_extract_to_fd(reader, file_path, out_fd);
    close(out_fd);

    if (result != BFC_OK) {
      fprintf(stderr, "Failed to extract '%s': %d\n", file_path, result);
      unlink(output_path); // Remove partial file
    } else {
      // Get file stats for verification
      bfc_entry_t entry;
      if (bfc_stat(reader, file_path, &entry) == BFC_OK) {
        printf("  Size: %" PRIu64 " bytes, CRC32C: 0x%08x\n", entry.size, entry.crc32c);
      }
    }
  }

  // Clean up
  for (int i = 0; i < ctx.count; i++) {
    free(ctx.files[i]);
  }
  free(ctx.files);

  bfc_close_read(reader);

  printf("\nExtraction complete!\n");
  return 0;
}