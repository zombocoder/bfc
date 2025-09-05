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

#include "cli.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
  uint32_t block_size;
  int force;
  const char* output_file;
  const char** input_paths;
  int num_inputs;
} create_options_t;

static void print_create_help(void) {
  printf("Usage: bfc create [options] <container.bfc> <input-paths...>\n\n");
  printf("Create a new BFC container from files and directories.\n\n");
  printf("Options:\n");
  printf("  -b, --block-size SIZE  Set block size (default: 4096)\n");
  printf("  -f, --force            Overwrite existing container\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Examples:\n");
  printf("  bfc create archive.bfc /path/to/files/\n");
  printf("  bfc create -f archive.bfc file1.txt file2.txt dir/\n");
  printf("  bfc create -b 8192 archive.bfc /home/user/documents/\n");
}

static int parse_create_options(int argc, char* argv[], create_options_t* opts) {
  // Initialize options
  opts->block_size = 4096;
  opts->force = 0;
  opts->output_file = NULL;
  opts->input_paths = NULL;
  opts->num_inputs = 0;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_create_help();
      return 1;
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
      opts->force = 1;
    } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--block-size") == 0) {
      if (i + 1 >= argc) {
        print_error("--block-size requires an argument");
        return -1;
      }
      opts->block_size = (uint32_t) atoi(argv[++i]);
      if (opts->block_size == 0 || opts->block_size > 1024 * 1024) {
        print_error("Block size must be between 1 and 1048576");
        return -1;
      }
    } else if (argv[i][0] == '-') {
      print_error("Unknown option: %s", argv[i]);
      return -1;
    } else {
      // First non-option argument is the output file
      if (!opts->output_file) {
        opts->output_file = argv[i];
      } else {
        // Remaining arguments are input paths
        opts->input_paths = (const char**) (argv + i);
        opts->num_inputs = argc - i;
        break;
      }
    }
  }

  if (!opts->output_file) {
    print_error("Output container file not specified");
    return -1;
  }

  if (opts->num_inputs == 0) {
    print_error("No input paths specified");
    return -1;
  }

  return 0;
}

static int add_file_to_container(bfc_t* writer, const char* file_path, const char* container_path) {
  print_verbose("Adding file: %s -> %s", file_path, container_path);

  FILE* file = fopen(file_path, "rb");
  if (!file) {
    print_error("Cannot open file '%s': %s", file_path, strerror(errno));
    return -1;
  }

  // Get file stats
  struct stat st;
  if (stat(file_path, &st) != 0) {
    print_error("Cannot stat file '%s': %s", file_path, strerror(errno));
    fclose(file);
    return -1;
  }

  // Add file to container
  uint64_t mtime_ns = (uint64_t) st.st_mtime * 1000000000ULL;
  uint32_t crc;
  int result = bfc_add_file(writer, container_path, file, st.st_mode & 0777, mtime_ns, &crc);

  fclose(file);

  if (result != BFC_OK) {
    print_error("Failed to add file '%s': %s", container_path, bfc_error_string(result));
    return -1;
  }

  if (!g_options.quiet) {
    printf("Added: %s (CRC32C: 0x%08x)\n", container_path, crc);
  }

  return 0;
}

static int add_directory_to_container(bfc_t* writer, const char* dir_path,
                                      const char* container_path);

static int process_directory_entry(bfc_t* writer, const char* base_path, const char* container_base,
                                   const char* entry_name) {
  char full_path[1024];
  char container_path[1024];

  snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry_name);

  if (strlen(container_base) > 0) {
    snprintf(container_path, sizeof(container_path), "%s/%s", container_base, entry_name);
  } else {
    snprintf(container_path, sizeof(container_path), "%s", entry_name);
  }

  struct stat st;
  if (stat(full_path, &st) != 0) {
    print_error("Cannot stat '%s': %s", full_path, strerror(errno));
    return -1;
  }

  if (S_ISREG(st.st_mode)) {
    return add_file_to_container(writer, full_path, container_path);
  } else if (S_ISDIR(st.st_mode)) {
    return add_directory_to_container(writer, full_path, container_path);
  } else {
    print_verbose("Skipping special file: %s", full_path);
    return 0;
  }
}

static int add_directory_to_container(bfc_t* writer, const char* dir_path,
                                      const char* container_path) {
  print_verbose("Adding directory: %s -> %s", dir_path, container_path);

  // Get directory stats
  struct stat st;
  if (stat(dir_path, &st) != 0) {
    print_error("Cannot stat directory '%s': %s", dir_path, strerror(errno));
    return -1;
  }

  // Add directory to container
  uint64_t mtime_ns = (uint64_t) st.st_mtime * 1000000000ULL;
  int result = bfc_add_dir(writer, container_path, st.st_mode & 0777, mtime_ns);

  if (result != BFC_OK) {
    print_error("Failed to add directory '%s': %s", container_path, bfc_error_string(result));
    return -1;
  }

  if (!g_options.quiet) {
    printf("Added: %s/\n", container_path);
  }

  // Process directory contents
  DIR* dir = opendir(dir_path);
  if (!dir) {
    print_error("Cannot open directory '%s': %s", dir_path, strerror(errno));
    return -1;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    // Skip . and ..
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    if (process_directory_entry(writer, dir_path, container_path, entry->d_name) != 0) {
      closedir(dir);
      return -1;
    }
  }

  closedir(dir);
  return 0;
}

int cmd_create(int argc, char* argv[]) {
  create_options_t opts;
  int result = parse_create_options(argc, argv, &opts);
  if (result != 0) {
    return (result > 0) ? 0 : 1;
  }

  // Check if output file exists
  if (access(opts.output_file, F_OK) == 0 && !opts.force) {
    print_error("Container '%s' already exists. Use -f to overwrite.", opts.output_file);
    return 1;
  }

  // Create container
  print_verbose("Creating container: %s (block size: %u)", opts.output_file, opts.block_size);

  bfc_t* writer = NULL;
  result = bfc_create(opts.output_file, opts.block_size, 0, &writer);
  if (result != BFC_OK) {
    print_error("Failed to create container '%s': %s", opts.output_file, bfc_error_string(result));
    return 1;
  }

  // Add input paths
  for (int i = 0; i < opts.num_inputs; i++) {
    const char* input_path = opts.input_paths[i];

    struct stat st;
    if (stat(input_path, &st) != 0) {
      print_error("Cannot access '%s': %s", input_path, strerror(errno));
      bfc_close(writer);
      return 1;
    }

    // Create a copy of input path and remove trailing slashes
    static char clean_path[1024];
    strncpy(clean_path, input_path, sizeof(clean_path) - 1);
    clean_path[sizeof(clean_path) - 1] = '\0';

    // Remove trailing slashes
    size_t len = strlen(clean_path);
    while (len > 1 && clean_path[len - 1] == '/') {
      clean_path[--len] = '\0';
    }

    // Determine container path (basename of cleaned input)
    const char* basename = strrchr(clean_path, '/');
    basename = basename ? basename + 1 : clean_path;

    if (S_ISREG(st.st_mode)) {
      if (add_file_to_container(writer, input_path, basename) != 0) {
        bfc_close(writer);
        return 1;
      }
    } else if (S_ISDIR(st.st_mode)) {
      if (add_directory_to_container(writer, input_path, basename) != 0) {
        bfc_close(writer);
        return 1;
      }
    } else {
      print_error("'%s' is not a regular file or directory", input_path);
      bfc_close(writer);
      return 1;
    }
  }

  // Finalize container
  print_verbose("Finalizing container...");
  result = bfc_finish(writer);
  if (result != BFC_OK) {
    print_error("Failed to finalize container: %s", bfc_error_string(result));
    bfc_close(writer);
    return 1;
  }

  bfc_close(writer);

  if (!g_options.quiet) {
    printf("Container '%s' created successfully.\n", opts.output_file);
  }

  return 0;
}