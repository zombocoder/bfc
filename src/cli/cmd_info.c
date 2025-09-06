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
#include "cli.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct {
  const char* container_file;
  const char* path_filter;
  int show_detailed;
} info_options_t;

static void print_info_help(void) {
  printf("Usage: bfc info [options] <container.bfc> [path]\n\n");
  printf("Show information about a BFC container or specific entries.\n\n");
  printf("Options:\n");
  printf("  -d, --detailed         Show detailed information\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Arguments:\n");
  printf("  container.bfc          BFC container to inspect\n");
  printf("  path                   Optional path to get info about specific entry\n\n");
  printf("Examples:\n");
  printf("  bfc info archive.bfc                  # Show container summary\n");
  printf("  bfc info -d archive.bfc               # Show detailed container info\n");
  printf("  bfc info archive.bfc docs/readme.txt  # Show info about specific file\n");
}

static int parse_info_options(int argc, char* argv[], info_options_t* opts) {
  // Initialize options
  opts->container_file = NULL;
  opts->path_filter = NULL;
  opts->show_detailed = 0;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_info_help();
      return 1;
    } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--detailed") == 0) {
      opts->show_detailed = 1;
    } else if (argv[i][0] == '-') {
      print_error("Unknown option: %s", argv[i]);
      return -1;
    } else {
      // First non-option argument is the container file
      if (!opts->container_file) {
        opts->container_file = argv[i];
      } else if (!opts->path_filter) {
        opts->path_filter = argv[i];
      } else {
        print_error("Too many arguments");
        return -1;
      }
    }
  }

  if (!opts->container_file) {
    print_error("Container file not specified");
    return -1;
  }

  return 0;
}

static void format_size_human(uint64_t size, char* buffer, size_t buffer_size) {
  if (size < 1024) {
    snprintf(buffer, buffer_size, "%" PRIu64 " bytes", size);
  } else if (size < 1024 * 1024) {
    snprintf(buffer, buffer_size, "%.1f KiB (%" PRIu64 " bytes)", size / 1024.0, size);
  } else if (size < 1024 * 1024 * 1024) {
    snprintf(buffer, buffer_size, "%.1f MiB (%" PRIu64 " bytes)", size / (1024.0 * 1024.0), size);
  } else {
    snprintf(buffer, buffer_size, "%.1f GiB (%" PRIu64 " bytes)", size / (1024.0 * 1024.0 * 1024.0),
             size);
  }
}

static void format_timestamp_full(uint64_t mtime_ns, char* buffer, size_t buffer_size) {
  time_t mtime = (time_t) (mtime_ns / 1000000000ULL);
  struct tm* tm = localtime(&mtime);
  if (tm) {
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S %Z", tm);
  } else {
    strcpy(buffer, "Invalid timestamp");
  }
}

static void format_file_mode_full(uint32_t mode, char* buffer) {
  strcpy(buffer, "----------");

  if (S_ISDIR(mode))
    buffer[0] = 'd';
  else if (S_ISREG(mode))
    buffer[0] = '-';
  else if (S_ISLNK(mode))
    buffer[0] = 'l';
  else if (S_ISBLK(mode))
    buffer[0] = 'b';
  else if (S_ISCHR(mode))
    buffer[0] = 'c';
  else if (S_ISFIFO(mode))
    buffer[0] = 'p';
  else if (S_ISSOCK(mode))
    buffer[0] = 's';
  else
    buffer[0] = '?';

  if (mode & S_IRUSR)
    buffer[1] = 'r';
  if (mode & S_IWUSR)
    buffer[2] = 'w';
  if (mode & S_IXUSR)
    buffer[3] = 'x';
  if (mode & S_IRGRP)
    buffer[4] = 'r';
  if (mode & S_IWGRP)
    buffer[5] = 'w';
  if (mode & S_IXGRP)
    buffer[6] = 'x';
  if (mode & S_IROTH)
    buffer[7] = 'r';
  if (mode & S_IWOTH)
    buffer[8] = 'w';
  if (mode & S_IXOTH)
    buffer[9] = 'x';

  // Handle special bits
  if (mode & S_ISUID)
    buffer[3] = (buffer[3] == 'x') ? 's' : 'S';
  if (mode & S_ISGID)
    buffer[6] = (buffer[6] == 'x') ? 's' : 'S';
  if (mode & S_ISVTX)
    buffer[9] = (buffer[9] == 'x') ? 't' : 'T';
}

// Statistics callback structure
typedef struct {
  int total_entries;
  int total_files;
  int total_dirs;
  uint64_t total_size;
  uint64_t total_compressed_size;
  int show_detailed;
} stats_context_t;

static int stats_callback(const bfc_entry_t* entry, void* user) {
  stats_context_t* ctx = (stats_context_t*) user;

  ctx->total_entries++;

  if (S_ISREG(entry->mode)) {
    ctx->total_files++;
    ctx->total_size += entry->size;
    ctx->total_compressed_size += entry->obj_size;
  } else if (S_ISDIR(entry->mode)) {
    ctx->total_dirs++;
  }

  if (ctx->show_detailed) {
    char mode_str[11];
    char size_str[64];
    char time_str[64];

    format_file_mode_full(entry->mode, mode_str);
    format_size_human(entry->size, size_str, sizeof(size_str));
    format_timestamp_full(entry->mtime_ns, time_str, sizeof(time_str));

    if (S_ISREG(entry->mode)) {
      printf("  %s %s %s CRC32C:0x%08x %s\n", mode_str, size_str, time_str, entry->crc32c,
             entry->path);
    } else {
      printf("  %s %s %s %s\n", mode_str, size_str, time_str, entry->path);
    }
  }

  return 0;
}

static void show_container_info(bfc_t* reader, const char* container_file, int show_detailed) {
  // Get container file stats
  struct stat container_stat;
  if (stat(container_file, &container_stat) == 0) {
    char container_size_str[64];
    char container_time_str[64];

    format_size_human(container_stat.st_size, container_size_str, sizeof(container_size_str));
    format_timestamp_full((uint64_t) container_stat.st_mtime * 1000000000ULL, container_time_str,
                          sizeof(container_time_str));

    printf("Container: %s\n", container_file);
    printf("Container size: %s\n", container_size_str);
    printf("Modified: %s\n", container_time_str);
    printf("\n");
  }

  // Gather statistics
  stats_context_t ctx = {0, 0, 0, 0, 0, show_detailed};

  if (show_detailed) {
    printf("Entries:\n");
  }

  int result = bfc_list(reader, NULL, stats_callback, &ctx);
  if (result != BFC_OK) {
    print_error("Failed to list container contents: %s", bfc_error_string(result));
    return;
  }

  if (show_detailed && ctx.total_entries > 0) {
    printf("\n");
  }

  // Check for encryption
  int has_encryption = bfc_has_encryption(reader);
  
  printf("Summary:\n");
  printf("  Total entries: %d\n", ctx.total_entries);
  printf("  Files: %d\n", ctx.total_files);
  printf("  Directories: %d\n", ctx.total_dirs);
  
  if (has_encryption) {
    printf("  Encryption: ChaCha20-Poly1305\n");
  }

  if (ctx.total_size > 0) {
    char size_str[64];
    char compressed_str[64];

    format_size_human(ctx.total_size, size_str, sizeof(size_str));
    format_size_human(ctx.total_compressed_size, compressed_str, sizeof(compressed_str));

    double ratio = (ctx.total_size > 0) ? (double) ctx.total_compressed_size / ctx.total_size : 1.0;

    printf("  Uncompressed size: %s\n", size_str);
    printf("  Stored size: %s\n", compressed_str);
    printf("  Storage ratio: %.1f%%\n", ratio * 100.0);
  }
}

static void show_entry_info(bfc_t* reader, const char* path) {
  bfc_entry_t entry;
  int result = bfc_stat(reader, path, &entry);

  if (result != BFC_OK) {
    print_error("Cannot get info for '%s': %s", path, bfc_error_string(result));
    return;
  }

  char mode_str[11];
  char size_str[64];
  char time_str[64];

  format_file_mode_full(entry.mode, mode_str);
  format_size_human(entry.size, size_str, sizeof(size_str));
  format_timestamp_full(entry.mtime_ns, time_str, sizeof(time_str));

  printf("Entry: %s\n", entry.path);
  printf("Type: %s\n", S_ISDIR(entry.mode)   ? "Directory"
                       : S_ISREG(entry.mode) ? "Regular file"
                                             : "Special file");
  printf("Mode: %s (0%04o)\n", mode_str, entry.mode & 0777);
  printf("Size: %s\n", size_str);

  if (S_ISREG(entry.mode)) {
    char stored_str[64];
    format_size_human(entry.obj_size, stored_str, sizeof(stored_str));

    double ratio = (entry.size > 0) ? (double) entry.obj_size / entry.size : 1.0;

    // Show compression information
    const char* comp_name;
    switch (entry.comp) {
    case BFC_COMP_NONE:
      comp_name = "none";
      break;
    case BFC_COMP_ZSTD:
      comp_name = "zstd";
      break;
    default:
      comp_name = "unknown";
      break;
    }

    printf("Compression: %s\n", comp_name);

    // Show encryption information
    const char* enc_name;
    switch (entry.enc) {
    case BFC_ENC_NONE:
      enc_name = "none";
      break;
    case BFC_ENC_CHACHA20_POLY1305:
      enc_name = "ChaCha20-Poly1305";
      break;
    default:
      enc_name = "unknown";
      break;
    }
    printf("Encryption: %s\n", enc_name);

    printf("Stored size: %s\n", stored_str);
    printf("Storage ratio: %.1f%%\n", ratio * 100.0);
    if (entry.comp != BFC_COMP_NONE && entry.size > 0) {
      printf("Compression ratio: %.1f%%\n", (1.0 - ratio) * 100.0);
    }
    printf("CRC32C: 0x%08x\n", entry.crc32c);
    printf("Object offset: %" PRIu64 "\n", entry.obj_offset);
  }

  printf("Modified: %s\n", time_str);
}

int cmd_info(int argc, char* argv[]) {
  info_options_t opts;
  int result = parse_info_options(argc, argv, &opts);
  if (result != 0) {
    return (result > 0) ? 0 : 1;
  }

  // Open container for reading
  print_verbose("Opening container: %s", opts.container_file);

  bfc_t* reader = NULL;
  result = bfc_open(opts.container_file, &reader);
  if (result != BFC_OK) {
    print_error("Failed to open container '%s': %s", opts.container_file, bfc_error_string(result));
    return 1;
  }

  if (opts.path_filter) {
    // Show info about specific entry
    show_entry_info(reader, opts.path_filter);
  } else {
    // Show container info
    show_container_info(reader, opts.container_file, opts.show_detailed);
  }

  bfc_close_read(reader);
  return 0;
}
