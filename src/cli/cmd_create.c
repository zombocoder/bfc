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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef BFC_WITH_SODIUM
// Function to read encryption key from file
static int read_key_from_file(const char* keyfile, uint8_t key[32]) {
  FILE* f = fopen(keyfile, "rb");
  if (!f) {
    print_error("Cannot open key file '%s': %s", keyfile, strerror(errno));
    return -1;
  }

  size_t bytes_read = fread(key, 1, 32, f);
  fclose(f);

  if (bytes_read != 32) {
    print_error("Key file '%s' must contain exactly 32 bytes (got %zu)", keyfile, bytes_read);
    return -1;
  }

  return 0;
}
#endif

typedef struct {
  uint32_t block_size;
  int force;
  const char* output_file;
  const char** input_paths;
  int num_inputs;
  // Compression options
  const char* compression;
  int compression_level;
  size_t compression_threshold;
  // Encryption options
  const char* encryption_password;
  const char* encryption_keyfile;
  int use_encryption;
} create_options_t;

static void print_create_help(void) {
  printf("Usage: bfc create [options] <container.bfc> <input-paths...>\n\n");
  printf("Create a new BFC container from files and directories.\n\n");
  printf("Options:\n");
  printf("  -b, --block-size SIZE       Set block size (default: 4096)\n");
  printf("  -f, --force                 Overwrite existing container\n");
  printf("  -c, --compression TYPE      Compression type: none, zstd, auto (default: none)\n");
  printf("  -l, --compression-level N   Compression level (1-22 for zstd, default: 3)\n");
  printf("  -t, --compression-threshold SIZE  Min file size to compress (default: 64)\n");
  printf("  -e, --encrypt PASSWORD      Encrypt with password\n");
  printf("  -k, --keyfile FILE          Encrypt with key from file (32 bytes)\n");
  printf("  -h, --help                  Show this help message\n\n");
  printf("Examples:\n");
  printf("  bfc create archive.bfc /path/to/files/\n");
  printf("  bfc create -f archive.bfc file1.txt file2.txt dir/\n");
  printf("  bfc create -b 8192 archive.bfc /home/user/documents/\n");
  printf("  bfc create -c zstd -l 9 archive.bfc /data/\n");
  printf("  bfc create -e mypassword archive.bfc /secure/data/\n");
  printf("  bfc create -c zstd -e secret -l 6 archive.bfc /compressed-encrypted/\n");
}

static int parse_create_options(int argc, char* argv[], create_options_t* opts) {
  // Initialize options
  opts->block_size = 4096;
  opts->force = 0;
  opts->output_file = NULL;
  opts->input_paths = NULL;
  opts->num_inputs = 0;
  // Compression defaults
  opts->compression = "none";
  opts->compression_level = 3;
  opts->compression_threshold = 64;
  // Encryption defaults
  opts->encryption_password = NULL;
  opts->encryption_keyfile = NULL;
  opts->use_encryption = 0;

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
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--compression") == 0) {
      if (i + 1 >= argc) {
        print_error("--compression requires an argument");
        return -1;
      }
      opts->compression = argv[++i];
      if (strcmp(opts->compression, "none") != 0 && strcmp(opts->compression, "zstd") != 0 &&
          strcmp(opts->compression, "auto") != 0) {
        print_error("Invalid compression type: %s (must be none, zstd, or auto)",
                    opts->compression);
        return -1;
      }
    } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--compression-level") == 0) {
      if (i + 1 >= argc) {
        print_error("--compression-level requires an argument");
        return -1;
      }
      opts->compression_level = atoi(argv[++i]);
      if (opts->compression_level < 1 || opts->compression_level > 22) {
        print_error("Compression level must be between 1 and 22");
        return -1;
      }
    } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--compression-threshold") == 0) {
      if (i + 1 >= argc) {
        print_error("--compression-threshold requires an argument");
        return -1;
      }
      opts->compression_threshold = (size_t) atol(argv[++i]);
      if (opts->compression_threshold > 1024 * 1024) {
        print_error("Compression threshold cannot exceed 1MB");
        return -1;
      }
    } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0) {
      if (i + 1 >= argc) {
        print_error("--encrypt requires a password argument");
        return -1;
      }
      opts->encryption_password = argv[++i];
      opts->use_encryption = 1;
    } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--keyfile") == 0) {
      if (i + 1 >= argc) {
        print_error("--keyfile requires a file path argument");
        return -1;
      }
      opts->encryption_keyfile = argv[++i];
      opts->use_encryption = 1;
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

  // Validate encryption options
  if (opts->encryption_password && opts->encryption_keyfile) {
    print_error("Cannot specify both --encrypt and --keyfile");
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

static int add_symlink_to_container(bfc_t* writer, const char* link_path,
                                    const char* container_path) {
  print_verbose("Adding symlink: %s -> %s", link_path, container_path);

  // Read the symlink target
  char target[1024];
  ssize_t target_len = readlink(link_path, target, sizeof(target) - 1);
  if (target_len == -1) {
    print_error("Cannot readlink '%s': %s", link_path, strerror(errno));
    return -1;
  }
  target[target_len] = '\0';

  // Get symlink stats
  struct stat st;
  if (lstat(link_path, &st) != 0) {
    print_error("Cannot lstat symlink '%s': %s", link_path, strerror(errno));
    return -1;
  }

  // Add symlink to container
  uint64_t mtime_ns = (uint64_t) st.st_mtime * 1000000000ULL;
  int result = bfc_add_symlink(writer, container_path, target, st.st_mode & 0777, mtime_ns);

  if (result != BFC_OK) {
    print_error("Failed to add symlink '%s': %s", container_path, bfc_error_string(result));
    return -1;
  }

  if (!g_options.quiet) {
    printf("Added: %s -> %s\n", container_path, target);
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
  if (lstat(full_path, &st) != 0) {
    print_error("Cannot lstat '%s': %s", full_path, strerror(errno));
    return -1;
  }

  if (S_ISREG(st.st_mode)) {
    return add_file_to_container(writer, full_path, container_path);
  } else if (S_ISDIR(st.st_mode)) {
    return add_directory_to_container(writer, full_path, container_path);
  } else if (S_ISLNK(st.st_mode)) {
    return add_symlink_to_container(writer, full_path, container_path);
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

  // Determine features based on compression setting
  uint64_t features = 0;
  uint8_t comp_type = BFC_COMP_NONE;

  if (strcmp(opts.compression, "zstd") == 0) {
    comp_type = BFC_COMP_ZSTD;
    features |= BFC_FEATURE_ZSTD;
  } else if (strcmp(opts.compression, "auto") == 0) {
    // Auto mode will be handled per-file in the writer
    comp_type = BFC_COMP_NONE; // Start with none, let writer decide
  }

  // Add encryption feature if encryption is enabled
  if (opts.use_encryption) {
    features |= BFC_FEATURE_AEAD;
  }

  bfc_t* writer = NULL;
  result = bfc_create(opts.output_file, opts.block_size, features, &writer);
  if (result != BFC_OK) {
    print_error("Failed to create container '%s': %s", opts.output_file, bfc_error_string(result));
    return 1;
  }

  // Configure compression settings
  if (strcmp(opts.compression, "none") != 0) {
    result = bfc_set_compression(writer, comp_type, opts.compression_level);
    if (result != BFC_OK) {
      print_error("Failed to set compression: %s", bfc_error_string(result));
      bfc_close(writer);
      return 1;
    }

    result = bfc_set_compression_threshold(writer, opts.compression_threshold);
    if (result != BFC_OK) {
      print_error("Failed to set compression threshold: %s", bfc_error_string(result));
      bfc_close(writer);
      return 1;
    }

    print_verbose("Compression: %s (level: %d, threshold: %zu bytes)", opts.compression,
                  opts.compression_level, opts.compression_threshold);
  }

  // Configure encryption settings
  if (opts.use_encryption) {
#ifndef BFC_WITH_SODIUM
    print_error("Encryption support not available. Rebuild with -DBFC_WITH_SODIUM=ON");
    bfc_close(writer);
    return 1;
#else
    if (opts.encryption_password) {
      // Use password-based encryption
      result = bfc_set_encryption_password(writer, opts.encryption_password,
                                           strlen(opts.encryption_password));
      if (result != BFC_OK) {
        print_error("Failed to set encryption password: %s", bfc_error_string(result));
        bfc_close(writer);
        return 1;
      }
      print_verbose("Encryption: ChaCha20-Poly1305 with password-based key derivation");
    } else if (opts.encryption_keyfile) {
      // Use key file
      uint8_t key[32];
      if (read_key_from_file(opts.encryption_keyfile, key) != 0) {
        bfc_close(writer);
        return 1;
      }

      result = bfc_set_encryption_key(writer, key);

      // Clear key from memory
      memset(key, 0, sizeof(key));

      if (result != BFC_OK) {
        print_error("Failed to set encryption key: %s", bfc_error_string(result));
        bfc_close(writer);
        return 1;
      }
      print_verbose("Encryption: ChaCha20-Poly1305 with key from file");
    }
#endif
  }

  // Add input paths
  for (int i = 0; i < opts.num_inputs; i++) {
    const char* input_path = opts.input_paths[i];

    struct stat st;
    if (lstat(input_path, &st) != 0) {
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
    } else if (S_ISLNK(st.st_mode)) {
      if (add_symlink_to_container(writer, input_path, basename) != 0) {
        bfc_close(writer);
        return 1;
      }
    } else {
      print_error("'%s' is not a regular file, directory, or symlink", input_path);
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