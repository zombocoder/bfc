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
  int long_format;
  int show_size;
  int show_checksum;
  const char* path_filter;
  const char* container_file;
} list_options_t;

static void print_list_help(void) {
  printf("Usage: bfc list [options] <container.bfc> [path]\n\n");
  printf("List contents of a BFC container.\n\n");
  printf("Options:\n");
  printf("  -l, --long         Use long listing format (like 'ls -l')\n");
  printf("  -s, --size         Show file sizes\n");
  printf("  -c, --checksum     Show CRC32C checksums\n");
  printf("  -h, --help         Show this help message\n\n");
  printf("Arguments:\n");
  printf("  container.bfc      BFC container to list\n");
  printf("  path               Optional path to filter entries (directory or prefix)\n\n");
  printf("Examples:\n");
  printf("  bfc list archive.bfc                  # List all entries\n");
  printf("  bfc list -l archive.bfc               # Long format listing\n");
  printf("  bfc list archive.bfc docs/            # List entries in docs/ directory\n");
  printf("  bfc list -sc archive.bfc              # Show sizes and checksums\n");
}

static int parse_list_options(int argc, char* argv[], list_options_t* opts) {
  // Initialize options
  opts->long_format = 0;
  opts->show_size = 0;
  opts->show_checksum = 0;
  opts->path_filter = NULL;
  opts->container_file = NULL;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_list_help();
      return 1;
    } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--long") == 0) {
      opts->long_format = 1;
    } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--size") == 0) {
      opts->show_size = 1;
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--checksum") == 0) {
      opts->show_checksum = 1;
    } else if (argv[i][0] == '-') {
      // Handle combined short options like -lsc
      const char* opt = argv[i] + 1;
      while (*opt) {
        switch (*opt) {
        case 'l':
          opts->long_format = 1;
          break;
        case 's':
          opts->show_size = 1;
          break;
        case 'c':
          opts->show_checksum = 1;
          break;
        default:
          print_error("Unknown option: -%c", *opt);
          return -1;
        }
        opt++;
      }
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

static void format_file_mode(uint32_t mode, char* buffer) {
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
}

static void format_file_size(uint64_t size, char* buffer, size_t buffer_size) {
  if (size < 1024) {
    snprintf(buffer, buffer_size, "%" PRIu64 "B", size);
  } else if (size < 1024 * 1024) {
    snprintf(buffer, buffer_size, "%.1fK", size / 1024.0);
  } else if (size < 1024 * 1024 * 1024) {
    snprintf(buffer, buffer_size, "%.1fM", size / (1024.0 * 1024.0));
  } else {
    snprintf(buffer, buffer_size, "%.1fG", size / (1024.0 * 1024.0 * 1024.0));
  }
}

static void format_timestamp(uint64_t mtime_ns, char* buffer, size_t buffer_size) {
  time_t mtime = (time_t) (mtime_ns / 1000000000ULL);
  struct tm* tm = localtime(&mtime);
  if (tm) {
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M", tm);
  } else {
    strcpy(buffer, "----?--?-- --?--");
  }
}

// List callback structure
typedef struct {
  list_options_t* opts;
  int count;
} list_context_t;

static int list_entry_callback(const bfc_entry_t* entry, void* user) {
  list_context_t* ctx = (list_context_t*) user;
  list_options_t* opts = ctx->opts;

  ctx->count++;

  if (opts->long_format) {
    char mode_str[11];
    char size_str[16];
    char time_str[32];

    format_file_mode(entry->mode, mode_str);
    format_file_size(entry->size, size_str, sizeof(size_str));
    format_timestamp(entry->mtime_ns, time_str, sizeof(time_str));

    if (opts->show_checksum && S_ISREG(entry->mode)) {
      printf("%s %8s %s 0x%08x %s\n", mode_str, size_str, time_str, entry->crc32c, entry->path);
    } else {
      printf("%s %8s %s %s\n", mode_str, size_str, time_str, entry->path);
    }
  } else {
    // Simple format
    if (opts->show_size && opts->show_checksum && S_ISREG(entry->mode)) {
      char size_str[16];
      format_file_size(entry->size, size_str, sizeof(size_str));
      printf("%8s 0x%08x %s\n", size_str, entry->crc32c, entry->path);
    } else if (opts->show_size) {
      char size_str[16];
      format_file_size(entry->size, size_str, sizeof(size_str));
      printf("%8s %s\n", size_str, entry->path);
    } else if (opts->show_checksum && S_ISREG(entry->mode)) {
      printf("0x%08x %s\n", entry->crc32c, entry->path);
    } else {
      printf("%s\n", entry->path);
    }
  }

  return 0;
}

int cmd_list(int argc, char* argv[]) {
  list_options_t opts;
  int result = parse_list_options(argc, argv, &opts);
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

  // List entries
  list_context_t ctx = {&opts, 0};

  print_verbose("Listing entries%s%s", opts.path_filter ? " in path: " : "",
                opts.path_filter ? opts.path_filter : "");

  result = bfc_list(reader, opts.path_filter, list_entry_callback, &ctx);
  if (result != BFC_OK) {
    print_error("Failed to list container contents: %s", bfc_error_string(result));
    bfc_close_read(reader);
    return 1;
  }

  bfc_close_read(reader);

  if (ctx.count == 0 && !g_options.quiet) {
    if (opts.path_filter) {
      printf("No entries found matching '%s'\n", opts.path_filter);
    } else {
      printf("Container is empty\n");
    }
  } else if (!g_options.quiet) {
    print_verbose("Listed %d entries", ctx.count);
  }

  return 0;
}