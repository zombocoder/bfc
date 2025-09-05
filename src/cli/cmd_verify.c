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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct {
  const char* container_file;
  int deep_verify;
  int show_progress;
} verify_options_t;

static void print_verify_help(void) {
  printf("Usage: bfc verify [options] <container.bfc>\n\n");
  printf("Verify integrity of a BFC container.\n\n");
  printf("Options:\n");
  printf("  --deep                 Perform deep verification (read and check all file contents)\n");
  printf("  -p, --progress         Show progress during verification\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Arguments:\n");
  printf("  container.bfc          BFC container to verify\n\n");
  printf("Examples:\n");
  printf("  bfc verify archive.bfc                # Quick structural verification\n");
  printf("  bfc verify --deep archive.bfc         # Full content verification\n");
  printf("  bfc verify -p --deep archive.bfc      # Deep verification with progress\n");
}

static int parse_verify_options(int argc, char* argv[], verify_options_t* opts) {
  // Initialize options
  opts->container_file = NULL;
  opts->deep_verify = 0;
  opts->show_progress = 0;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_verify_help();
      return 1;
    } else if (strcmp(argv[i], "--deep") == 0) {
      opts->deep_verify = 1;
    } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--progress") == 0) {
      opts->show_progress = 1;
    } else if (argv[i][0] == '-') {
      // Handle combined short options like -p
      const char* opt = argv[i] + 1;
      while (*opt) {
        switch (*opt) {
        case 'p':
          opts->show_progress = 1;
          break;
        default:
          print_error("Unknown option: -%c", *opt);
          return -1;
        }
        opt++;
      }
    } else {
      // Non-option argument is the container file
      if (!opts->container_file) {
        opts->container_file = argv[i];
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

// Progress callback for deep verification
typedef struct {
  int total_entries;
  int verified_entries;
  int show_progress;
  clock_t start_time;
} verify_progress_t;

static int verify_progress_callback(const bfc_entry_t* entry, void* user) {
  verify_progress_t* ctx = (verify_progress_t*) user;

  ctx->total_entries++;

  if (ctx->show_progress && S_ISREG(entry->mode)) {
    printf("Counting: %s\n", entry->path);
  }

  return 0;
}

__attribute__((unused)) static int verify_entry_callback(const bfc_entry_t* entry, void* user) {
  verify_progress_t* ctx = (verify_progress_t*) user;

  ctx->verified_entries++;

  if (ctx->show_progress) {
    if (S_ISREG(entry->mode)) {
      printf("Verifying (%d/%d): %s\n", ctx->verified_entries, ctx->total_entries, entry->path);
    } else {
      printf("Checking (%d/%d): %s\n", ctx->verified_entries, ctx->total_entries, entry->path);
    }
  }

  return 0;
}

int cmd_verify(int argc, char* argv[]) {
  verify_options_t opts;
  int result = parse_verify_options(argc, argv, &opts);
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

  if (!g_options.quiet) {
    printf("Verifying container: %s\n", opts.container_file);
    if (opts.deep_verify) {
      printf("Mode: Deep verification (checking all file contents and CRC32C checksums)\n");
    } else {
      printf("Mode: Quick verification (checking container structure and index)\n");
    }
    printf("\n");
  }

  clock_t start_time = clock();

  // Count entries for progress if needed
  verify_progress_t progress_ctx = {0, 0, opts.show_progress, start_time};

  if (opts.show_progress && opts.deep_verify) {
    if (!g_options.quiet) {
      printf("Counting entries...\n");
    }
    result = bfc_list(reader, NULL, verify_progress_callback, &progress_ctx);
    if (result != BFC_OK) {
      print_error("Failed to count entries: %s", bfc_error_string(result));
      bfc_close_read(reader);
      return 1;
    }
    if (!g_options.quiet) {
      printf("Found %d entries\n\n", progress_ctx.total_entries);
    }
    progress_ctx.verified_entries = 0;
  }

  // Perform verification
  result = bfc_verify(reader, opts.deep_verify);

  clock_t end_time = clock();
  double elapsed = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

  bfc_close_read(reader);

  if (result == BFC_OK) {
    if (!g_options.quiet) {
      if (opts.show_progress && opts.deep_verify) {
        printf("\n");
      }
      printf("✓ Verification successful\n");
      printf("Container is valid and all checksums match\n");
      printf("Verification completed in %.2f seconds\n", elapsed);
    }
    return 0;
  } else {
    print_error("✗ Verification failed: %s", bfc_error_string(result));

    // Provide more specific error information
    switch (result) {
    case BFC_E_BADMAGIC:
      print_error("The file is not a valid BFC container or is corrupted");
      break;
    case BFC_E_CRC:
      print_error("CRC32C checksum mismatch detected - data corruption");
      break;
    case BFC_E_IO:
      print_error("I/O error occurred while reading the container");
      break;
    case BFC_E_INVAL:
      print_error("Invalid container structure or format");
      break;
    default:
      break;
    }

    if (!g_options.quiet) {
      printf("Verification failed after %.2f seconds\n", elapsed);
    }
    return 1;
  }
}
