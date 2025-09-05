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
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  int force;
  int preserve_paths;
  const char* output_dir;
  const char* container_file;
  const char** extract_paths;
  int num_paths;
} extract_options_t;

static void print_extract_help(void) {
  printf("Usage: bfc extract [options] <container.bfc> [paths...]\n\n");
  printf("Extract files and directories from a BFC container.\n\n");
  printf("Options:\n");
  printf("  -C, --directory DIR    Change to directory DIR before extracting\n");
  printf("  -f, --force            Overwrite existing files\n");
  printf("  -k, --keep-paths       Preserve full directory paths when extracting\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Arguments:\n");
  printf("  container.bfc          BFC container to extract from\n");
  printf("  paths                  Optional paths to extract (default: all)\n\n");
  printf("Examples:\n");
  printf("  bfc extract archive.bfc                   # Extract all files\n");
  printf("  bfc extract -C /tmp archive.bfc           # Extract to /tmp\n");
  printf("  bfc extract archive.bfc docs/             # Extract docs/ directory\n");
  printf("  bfc extract -k archive.bfc file.txt       # Extract preserving path\n");
}

static int parse_extract_options(int argc, char* argv[], extract_options_t* opts) {
  // Initialize options
  opts->force = 0;
  opts->preserve_paths = 0;
  opts->output_dir = NULL;
  opts->container_file = NULL;
  opts->extract_paths = NULL;
  opts->num_paths = 0;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_extract_help();
      return 1;
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
      opts->force = 1;
    } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--keep-paths") == 0) {
      opts->preserve_paths = 1;
    } else if (strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--directory") == 0) {
      if (i + 1 >= argc) {
        print_error("--directory requires an argument");
        return -1;
      }
      opts->output_dir = argv[++i];
    } else if (argv[i][0] == '-') {
      // Handle combined short options like -fk
      const char* opt = argv[i] + 1;
      while (*opt) {
        switch (*opt) {
        case 'f':
          opts->force = 1;
          break;
        case 'k':
          opts->preserve_paths = 1;
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
      } else {
        // Remaining arguments are paths to extract
        opts->extract_paths = (const char**) (argv + i);
        opts->num_paths = argc - i;
        break;
      }
    }
  }

  if (!opts->container_file) {
    print_error("Container file not specified");
    return -1;
  }

  return 0;
}

static int create_parent_directories(const char* path, int force) {
  char* path_copy = strdup(path);
  if (!path_copy) {
    return -1;
  }

  char* dir = dirname(path_copy);
  if (strcmp(dir, ".") == 0 || strcmp(dir, "/") == 0) {
    free(path_copy);
    return 0;
  }

  struct stat st;
  if (stat(dir, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      print_error("'%s' exists but is not a directory", dir);
      free(path_copy);
      return -1;
    }
    free(path_copy);
    return 0;
  }

  // Recursively create parent directories
  if (create_parent_directories(dir, force) != 0) {
    free(path_copy);
    return -1;
  }

  print_verbose("Creating directory: %s", dir);
  if (mkdir(dir, 0755) != 0) {
    print_error("Cannot create directory '%s': %s", dir, strerror(errno));
    free(path_copy);
    return -1;
  }

  free(path_copy);
  return 0;
}

static int extract_file(bfc_t* reader, const bfc_entry_t* entry, const char* output_path,
                        int force) {
  // Check if file exists
  struct stat st;
  if (stat(output_path, &st) == 0 && !force) {
    print_error("File '%s' already exists. Use -f to overwrite.", output_path);
    return -1;
  }

  // Create parent directories
  if (create_parent_directories(output_path, force) != 0) {
    return -1;
  }

  print_verbose("Extracting file: %s -> %s", entry->path, output_path);

  // Open output file
  int fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, entry->mode & 0777);
  if (fd < 0) {
    print_error("Cannot create file '%s': %s", output_path, strerror(errno));
    return -1;
  }

  // Extract file content
  int result = bfc_extract_to_fd(reader, entry->path, fd);

  if (result != BFC_OK) {
    close(fd);
    print_error("Failed to extract file '%s': %s", entry->path, bfc_error_string(result));
    unlink(output_path); // Clean up partial file
    return -1;
  }

  // Set file permissions and timestamps using file descriptor to avoid TOCTOU race conditions
  if (fchmod(fd, entry->mode & 0777) != 0) {
    print_verbose("Warning: cannot set permissions on '%s': %s", output_path, strerror(errno));
  }

  struct timespec times[2] = {
      {.tv_sec = entry->mtime_ns / 1000000000ULL,
       .tv_nsec = entry->mtime_ns % 1000000000ULL}, // atime = mtime
      {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}
      // mtime
  };

  if (futimens(fd, times) != 0) {
    print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
  }

  // Close file descriptor after setting metadata
  close(fd);

  if (!g_options.quiet) {
    printf("Extracted: %s\n", output_path);
  }

  return 0;
}

static int extract_directory(const char* output_path, const bfc_entry_t* entry, int force) {
  struct stat st;
  if (stat(output_path, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      if (!force) {
        print_error("'%s' exists but is not a directory. Use -f to overwrite.", output_path);
        return -1;
      }
      if (unlink(output_path) != 0) {
        print_error("Cannot remove file '%s': %s", output_path, strerror(errno));
        return -1;
      }
    } else {
      // Directory already exists, just update permissions and timestamps
      if (chmod(output_path, entry->mode & 0777) != 0) {
        print_verbose("Warning: cannot set permissions on '%s': %s", output_path, strerror(errno));
      }

      struct timespec times[2] = {
          {.tv_sec = entry->mtime_ns / 1000000000ULL,
           .tv_nsec = entry->mtime_ns % 1000000000ULL}, // atime = mtime
          {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}
          // mtime
      };

      if (utimensat(AT_FDCWD, output_path, times, 0) != 0) {
        print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
      }

      return 0;
    }
  }

  // Create parent directories
  if (create_parent_directories(output_path, force) != 0) {
    return -1;
  }

  print_verbose("Creating directory: %s", output_path);

  // Create directory
  if (mkdir(output_path, entry->mode & 0777) != 0) {
    print_error("Cannot create directory '%s': %s", output_path, strerror(errno));
    return -1;
  }

  // Set timestamps
  struct timespec times[2] = {
      {.tv_sec = entry->mtime_ns / 1000000000ULL,
       .tv_nsec = entry->mtime_ns % 1000000000ULL}, // atime = mtime
      {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}
      // mtime
  };

  if (utimensat(AT_FDCWD, output_path, times, 0) != 0) {
    print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
  }

  if (!g_options.quiet) {
    printf("Created: %s/\n", output_path);
  }

  return 0;
}

// Extract callback structure
typedef struct {
  extract_options_t* opts;
  bfc_t* reader;
  const char* output_dir;
  int count;
  int errors;
} extract_context_t;

static int extract_entry_callback(const bfc_entry_t* entry, void* user) {
  extract_context_t* ctx = (extract_context_t*) user;
  extract_options_t* opts = ctx->opts;

  ctx->count++;

  // Determine output path
  char output_path[1024];
  const char* extract_name;

  if (opts->preserve_paths) {
    extract_name = entry->path;
  } else {
    // Use basename only
    extract_name = strrchr(entry->path, '/');
    extract_name = extract_name ? extract_name + 1 : entry->path;

    // Skip if basename is empty (root directory)
    if (strlen(extract_name) == 0) {
      return 0;
    }
  }

  if (ctx->output_dir) {
    snprintf(output_path, sizeof(output_path), "%s/%s", ctx->output_dir, extract_name);
  } else {
    snprintf(output_path, sizeof(output_path), "%s", extract_name);
  }

  // Extract based on entry type
  int result;
  if (S_ISREG(entry->mode)) {
    result = extract_file(ctx->reader, entry, output_path, opts->force);
  } else if (S_ISDIR(entry->mode)) {
    result = extract_directory(output_path, entry, opts->force);
  } else {
    print_verbose("Skipping special file: %s", entry->path);
    return 0;
  }

  if (result != 0) {
    ctx->errors++;
  }

  return 0;
}

int cmd_extract(int argc, char* argv[]) {
  extract_options_t opts;
  int result = parse_extract_options(argc, argv, &opts);
  if (result != 0) {
    return (result > 0) ? 0 : 1;
  }

  // Change to output directory if specified
  if (opts.output_dir) {
    print_verbose("Changing to directory: %s", opts.output_dir);
    if (chdir(opts.output_dir) != 0) {
      print_error("Cannot change to directory '%s': %s", opts.output_dir, strerror(errno));
      return 1;
    }
  }

  // Open container for reading
  print_verbose("Opening container: %s", opts.container_file);

  bfc_t* reader = NULL;
  result = bfc_open(opts.container_file, &reader);
  if (result != BFC_OK) {
    print_error("Failed to open container '%s': %s", opts.container_file, bfc_error_string(result));
    return 1;
  }

  // Extract entries
  extract_context_t ctx = {&opts, reader, NULL, 0, 0};

  if (opts.num_paths == 0) {
    // Extract all entries
    print_verbose("Extracting all entries");
    result = bfc_list(reader, NULL, extract_entry_callback, &ctx);
  } else {
    // Extract specific paths
    for (int i = 0; i < opts.num_paths; i++) {
      print_verbose("Extracting entries matching: %s", opts.extract_paths[i]);
      result = bfc_list(reader, opts.extract_paths[i], extract_entry_callback, &ctx);
      if (result != BFC_OK) {
        break;
      }
    }
  }

  if (result != BFC_OK) {
    print_error("Failed to list container contents: %s", bfc_error_string(result));
    bfc_close_read(reader);
    return 1;
  }

  bfc_close_read(reader);

  if (ctx.count == 0 && !g_options.quiet) {
    if (opts.num_paths > 0) {
      printf("No entries found matching specified paths\n");
    } else {
      printf("Container is empty\n");
    }
  } else if (!g_options.quiet) {
    if (ctx.errors > 0) {
      printf("Extracted %d entries with %d errors\n", ctx.count, ctx.errors);
    } else {
      printf("Successfully extracted %d entries\n", ctx.count);
    }
  }

  return (ctx.errors > 0) ? 1 : 0;
}
