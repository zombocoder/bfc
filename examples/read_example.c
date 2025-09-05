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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

// Callback function for listing entries
static int print_entry(const bfc_entry_t* entry, void* user) {
  (void) user; // Unused parameter

  // Format file mode
  char mode_str[11] = "----------";
  if (S_ISDIR(entry->mode))
    mode_str[0] = 'd';
  else if (S_ISREG(entry->mode))
    mode_str[0] = '-';

  if (entry->mode & S_IRUSR)
    mode_str[1] = 'r';
  if (entry->mode & S_IWUSR)
    mode_str[2] = 'w';
  if (entry->mode & S_IXUSR)
    mode_str[3] = 'x';
  if (entry->mode & S_IRGRP)
    mode_str[4] = 'r';
  if (entry->mode & S_IWGRP)
    mode_str[5] = 'w';
  if (entry->mode & S_IXGRP)
    mode_str[6] = 'x';
  if (entry->mode & S_IROTH)
    mode_str[7] = 'r';
  if (entry->mode & S_IWOTH)
    mode_str[8] = 'w';
  if (entry->mode & S_IXOTH)
    mode_str[9] = 'x';

  // Format timestamp
  time_t mtime = (time_t) (entry->mtime_ns / 1000000000ULL);
  struct tm* tm = localtime(&mtime);
  char time_str[20];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm);

  printf("%s %8" PRIu64 " %s %s\n", mode_str, entry->size, time_str, entry->path);
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <container.bfc>\n", argv[0]);
    return 1;
  }

  const char* container_path = argv[1];

  // Open the BFC container
  printf("Opening container: %s\n", container_path);

  bfc_t* reader = NULL;
  int result = bfc_open(container_path, &reader);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to open container: %d\n", result);
    return 1;
  }

  // Verify container integrity
  printf("Verifying container...\n");
  result = bfc_verify(reader, 1); // Deep verification with CRC checks
  if (result != BFC_OK) {
    fprintf(stderr, "Container verification failed: %d\n", result);
    bfc_close_read(reader);
    return 1;
  }
  printf("Container is valid!\n\n");

  // List all entries in the container
  printf("Container contents:\n");
  printf("Mode      Size     Modified         Path\n");
  printf("--------- -------- ---------------- ----\n");

  result = bfc_list(reader, NULL, print_entry, NULL);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to list entries: %d\n", result);
    bfc_close_read(reader);
    return 1;
  }
  printf("\n");

  // Demonstrate file statistics
  bfc_entry_t entry;
  result = bfc_stat(reader, "README.md", &entry);
  if (result == BFC_OK) {
    printf("File statistics for README.md:\n");
    printf("  Size: %" PRIu64 " bytes\n", entry.size);
    printf("  Mode: 0%o\n", entry.mode & 0777);
    printf("  Type: %s\n", S_ISREG(entry.mode) ? "Regular file" : "Other");
    printf("  CRC32C: 0x%08x\n", entry.crc32c);
    printf("\n");
  }

  // Read and display file content
  printf("Content of README.md:\n");
  printf("=====================\n");

  char buffer[4096];
  size_t bytes_read = bfc_read(reader, "README.md", 0, buffer, sizeof(buffer) - 1);
  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';
    printf("%s", buffer);
  } else {
    printf("Failed to read file content\n");
  }
  printf("\n");

  // Demonstrate partial reading
  printf("First 50 characters of README.md:\n");
  printf("==================================\n");
  bytes_read = bfc_read(reader, "README.md", 0, buffer, 50);
  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';
    printf("\"%s\"\n", buffer);
  }
  printf("\n");

  // List entries in docs directory
  printf("Contents of docs/ directory:\n");
  printf("Mode      Size     Modified         Path\n");
  printf("--------- -------- ---------------- ----\n");

  result = bfc_list(reader, "docs", print_entry, NULL);
  if (result != BFC_OK) {
    printf("No entries found in docs/ or error: %d\n", result);
  }

  // Clean up
  bfc_close_read(reader);

  printf("\nDone!\n");
  return 0;
}