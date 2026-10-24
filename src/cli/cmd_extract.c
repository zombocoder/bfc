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

#include "bfc_format.h"
#include "cli.h"
#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct {
  int force;
  int flatten;
  const char* output_dir;
  const char* container_file;
  const char** extract_paths;
  int num_paths;
  cli_credentials_t creds;
} extract_options_t;

static void print_extract_help(void) {
  printf("Usage: bfc extract [options] <container.bfc> [paths...]\n\n");
  printf("Extract files and directories from a BFC container.\n\n");
  printf("Options:\n");
  printf("  -C, --directory DIR    Change to directory DIR before extracting\n");
  printf("  -f, --force            Overwrite existing files\n");
  printf("      --flatten          Drop directories: extract every file by its name only\n");
  printf("  -p, --password PASS    Password for encrypted container\n");
  printf("      --password-file FILE  Read the password from FILE (- for stdin)\n");
  printf("  -K, --keyfile FILE     Key file for encrypted container (32 bytes)\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Arguments:\n");
  printf("  container.bfc          BFC container to extract from\n");
  printf("  paths                  Optional paths to extract (default: all)\n\n");
  printf("Directory paths from the container are recreated under the output\n");
  printf("directory. Entries with absolute paths or '..' components, and entries\n");
  printf("that would be written through a symlink, are refused.\n\n");
  printf("Examples:\n");
  printf("  bfc extract archive.bfc                   # Extract all files\n");
  printf("  bfc extract -C /tmp archive.bfc           # Extract to /tmp\n");
  printf("  bfc extract archive.bfc docs/             # Extract docs/ directory\n");
  printf("  bfc extract --flatten archive.bfc         # All files into one directory\n");
  printf("  bfc extract -p secret archive.bfc         # Extract encrypted container\n");
  printf("  bfc extract -K key.bin archive.bfc        # Extract with key file\n");
}

static int parse_extract_options(int argc, char* argv[], extract_options_t* opts) {
  // Initialize options
  opts->force = 0;
  opts->flatten = 0;
  opts->output_dir = NULL;
  opts->container_file = NULL;
  opts->extract_paths = NULL;
  opts->num_paths = 0;
  cli_credentials_init(&opts->creds);

  int i, cred;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_extract_help();
      return 1;
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
      opts->force = 1;
    } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--keep-paths") == 0) {
      // Paths are preserved by default now; -K is the key-file option.
      fprintf(stderr,
              "Warning: %s is deprecated and has no effect: paths are preserved by "
              "default (use -K for a key file)\n",
              argv[i]);
    } else if (strcmp(argv[i], "--flatten") == 0) {
      opts->flatten = 1;
    } else if (strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--directory") == 0) {
      if (i + 1 >= argc) {
        print_error("--directory requires an argument");
        return -1;
      }
      opts->output_dir = argv[++i];
    } else if ((cred = cli_parse_credential_option(argc, argv, &i, &opts->creds)) != 0) {
      if (cred < 0) {
        return -1;
      }
    } else if (argv[i][0] == '-') {
      // Handle combined short options like -fk
      const char* opt = argv[i] + 1;
      while (*opt) {
        switch (*opt) {
        case 'f':
          opts->force = 1;
          break;
        case 'k':
          fprintf(stderr, "Warning: -k is deprecated and has no effect: paths are preserved by "
                          "default (use -K for a key file)\n");
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

  return cli_credentials_check(&opts->creds);
}

// Create every missing parent directory of path. Walks the components in
// place: dirname() returns a static buffer on some systems (macOS), which a
// recursive implementation overwrites.
static int create_parent_directories(const char* path, int force) {
  (void) force;
  char* buf = strdup(path);
  if (!buf) {
    return -1;
  }

  for (char* p = buf + 1; (p = strchr(p, '/')) != NULL; p++) {
    *p = '\0';
    print_verbose("Creating directory: %s", buf);
#ifdef _WIN32
    int rc = mkdir(buf);
#else
    int rc = mkdir(buf, 0755);
#endif
    if (rc != 0) {
      if (errno == EEXIST) {
        // Already exists - verify it is actually a directory
        struct stat st;
        if (stat(buf, &st) != 0 || !S_ISDIR(st.st_mode)) {
          print_error("'%s' exists but is not a directory", buf);
          free(buf);
          return -1;
        }
      } else {
        print_error("Cannot create directory '%s': %s", buf, strerror(errno));
        free(buf);
        return -1;
      }
    }
    *p = '/';
  }

  free(buf);
  return 0;
}

static int extract_file(bfc_t* reader, const bfc_entry_t* entry, const char* output_path,
                        int force) {
  // Create parent directories
  if (create_parent_directories(output_path, force) != 0) {
    return -1;
  }

  print_verbose("Extracting file: %s -> %s", entry->path, output_path);

  // Open output file atomically: O_EXCL rejects existing files when !force,
  // O_NOFOLLOW prevents symlink attacks (POSIX). No separate stat() needed.
#ifdef _WIN32
  int oflags = O_WRONLY | O_CREAT | O_BINARY | (force ? O_TRUNC : O_EXCL);
  int fd = open(output_path, oflags, _S_IREAD | _S_IWRITE);
#else
  int oflags = O_WRONLY | O_CREAT | O_NOFOLLOW | (force ? O_TRUNC : O_EXCL);
  int fd = open(output_path, oflags, entry->mode & 0777);
#endif
  if (fd < 0) {
    if (!force && errno == EEXIST) {
      print_error("File '%s' already exists. Use -f to overwrite.", output_path);
    } else {
      print_error("Cannot create file '%s': %s", output_path, strerror(errno));
    }
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
#ifndef _WIN32
  if (fchmod(fd, entry->mode & 0777) != 0) {
    print_verbose("Warning: cannot set permissions on '%s': %s", output_path, strerror(errno));
  }
#endif

#ifndef _WIN32
  struct timespec times[2] = {
      {.tv_sec = entry->mtime_ns / 1000000000ULL,
       .tv_nsec = entry->mtime_ns % 1000000000ULL}, // atime = mtime
      {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}
      // mtime
  };

  if (futimens(fd, times) != 0) {
    print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
  }
#endif
  // Close file descriptor after setting metadata
  close(fd);

  if (!g_options.quiet) {
    printf("Extracted: %s\n", output_path);
  }

  return 0;
}

static int extract_directory(const char* output_path, const bfc_entry_t* entry, int force) {
#ifdef _WIN32
  (void) entry; // permissions and timestamps are POSIX-only
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
      return 0;
    }
  }

  if (create_parent_directories(output_path, force) != 0) {
    return -1;
  }

  print_verbose("Creating directory: %s", output_path);

  if (mkdir(output_path) != 0) {
    print_error("Cannot create directory '%s': %s", output_path, strerror(errno));
    return -1;
  }

  if (!g_options.quiet) {
    printf("Created: %s/\n", output_path);
  }

  return 0;
#else
  // POSIX: use open() as the atomic probe — no preceding stat() to avoid TOCTOU.
  int dirfd = open(output_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
  if (dirfd >= 0) {
    // Directory exists — update permissions and timestamps via fd.
    if (fchmod(dirfd, entry->mode & 0777) != 0) {
      print_verbose("Warning: cannot set permissions on '%s': %s", output_path, strerror(errno));
    }
    struct timespec times[2] = {
        {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL},
        {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}};
    if (futimens(dirfd, times) != 0) {
      print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
    }
    close(dirfd);
    return 0;
  }

  int open_errno = errno;

  if (open_errno == ENOTDIR || open_errno == ELOOP) {
    // Path exists but is not a directory, or is a symlink (O_NOFOLLOW sets ELOOP).
    if (!force) {
      print_error("'%s' exists but is not a directory. Use -f to overwrite.", output_path);
      return -1;
    }
    if (unlink(output_path) != 0) {
      print_error("Cannot remove '%s': %s", output_path, strerror(errno));
      return -1;
    }
    // fall through to create
  } else if (open_errno != ENOENT) {
    print_error("Cannot access '%s': %s", output_path, strerror(open_errno));
    return -1;
  }

  // Create parent directories then the directory itself.
  if (create_parent_directories(output_path, force) != 0) {
    return -1;
  }

  print_verbose("Creating directory: %s", output_path);

  if (mkdir(output_path, entry->mode & 0777) != 0) {
    print_error("Cannot create directory '%s': %s", output_path, strerror(errno));
    return -1;
  }

  // Set timestamps via fd.
  {
    int dirfd_new = open(output_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dirfd_new >= 0) {
      struct timespec times[2] = {
          {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL},
          {.tv_sec = entry->mtime_ns / 1000000000ULL, .tv_nsec = entry->mtime_ns % 1000000000ULL}};
      if (futimens(dirfd_new, times) != 0) {
        print_verbose("Warning: cannot set timestamps on '%s': %s", output_path, strerror(errno));
      }
      close(dirfd_new);
    }
  }

  if (!g_options.quiet) {
    printf("Created: %s/\n", output_path);
  }

  return 0;
#endif
}

static int extract_symlink(bfc_t* reader, const bfc_entry_t* entry, const char* output_path,
                           int force) {
  // Check if file exists
  struct stat st;
  if (lstat(output_path, &st) == 0) {
    if (!S_ISLNK(st.st_mode)) {
      if (!force) {
        print_error("'%s' exists but is not a symlink. Use -f to overwrite.", output_path);
        return -1;
      }
    }
    // Remove existing file/symlink
    if (unlink(output_path) != 0) {
      print_error("Cannot remove '%s': %s", output_path, strerror(errno));
      return -1;
    }
  }

  // Read symlink target from container
  char* target = malloc(entry->size + 1);
  if (!target) {
    print_error("Out of memory");
    return -1;
  }

  size_t bytes_read = bfc_read(reader, entry->path, 0, target, entry->size);
  if (bytes_read != entry->size) {
    print_error("Failed to read symlink target for '%s'", entry->path);
    free(target);
    return -1;
  }
  target[entry->size] = '\0';

// Create symlink
#ifndef _WIN32
  if (symlink(target, output_path) != 0) {
    print_error("Cannot create symlink '%s' -> '%s': %s", output_path, target, strerror(errno));
    free(target);
    return -1;
  }

  // Set timestamps using lutimes (for symlinks)
  struct timeval times[2] = {
      {.tv_sec = entry->mtime_ns / 1000000000ULL,
       .tv_usec = (entry->mtime_ns % 1000000000ULL) / 1000}, // atime = mtime
      {.tv_sec = entry->mtime_ns / 1000000000ULL,
       .tv_usec = (entry->mtime_ns % 1000000000ULL) / 1000} // mtime
  };

  if (lutimes(output_path, times) != 0) {
    print_verbose("Warning: cannot set timestamps on symlink '%s': %s", output_path,
                  strerror(errno));
  }
#else
  print_verbose("Warning: symlinks are not supported on Windows, skipping '%s'", entry->path);
#endif

  if (!g_options.quiet) {
    printf("Extracted: %s -> %s\n", output_path, target);
  }

  free(target);
  return 0;
}

// Refuse entry paths that could land outside the output directory. The writer
// normalizes paths, but the reader takes them from the index as stored, so a
// hand-made container can hold anything.
static int entry_path_is_safe(const char* path) {
  if (bfc_path_validate(path) != BFC_OK) {
    return 0; // absolute, empty, or contains ".." components
  }
#ifdef _WIN32
  // On Windows "\\" is also a separator and "C:" a drive prefix
  if (strchr(path, '\\') || strchr(path, ':')) {
    return 0;
  }
#endif
  return 1;
}

// Return 1 if any parent component of path (relative to the current directory)
// is a symlink. Writing below one would follow it, possibly out of the output
// directory, since O_NOFOLLOW only covers the last component.
static int has_symlink_parent(const char* path) {
#ifdef _WIN32
  (void) path;
  return 0; // symlinks are never created on Windows
#else
  char buf[1024];
  size_t len = strlen(path);
  if (len >= sizeof(buf)) {
    return 1;
  }
  memcpy(buf, path, len + 1);

  for (char* p = buf; (p = strchr(p, '/')) != NULL; p++) {
    struct stat st;
    *p = '\0';
    int is_link = lstat(buf, &st) == 0 && S_ISLNK(st.st_mode);
    *p = '/';
    if (is_link) {
      return 1;
    }
  }
  return 0;
#endif
}

// Set of output names already used in --flatten mode, to catch two entries
// that would be written to the same file.
typedef struct {
  char** slots;
  size_t cap;
  size_t used;
} name_set_t;

static uint64_t name_hash(const char* s) {
  uint64_t h = 1469598103934665603ULL; // FNV-1a
  for (; *s; s++) {
    h = (h ^ (unsigned char) *s) * 1099511628211ULL;
  }
  return h;
}

// Returns 1 if added, 0 if already present, -1 on allocation failure.
static int name_set_add(name_set_t* set, const char* name) {
  if (set->used * 2 >= set->cap) {
    size_t ncap = set->cap ? set->cap * 2 : 64;
    char** nslots = calloc(ncap, sizeof(char*));
    if (!nslots) {
      return -1;
    }
    for (size_t i = 0; i < set->cap; i++) {
      if (set->slots[i]) {
        size_t j = name_hash(set->slots[i]) & (ncap - 1);
        while (nslots[j]) {
          j = (j + 1) & (ncap - 1);
        }
        nslots[j] = set->slots[i];
      }
    }
    free(set->slots);
    set->slots = nslots;
    set->cap = ncap;
  }

  size_t j = name_hash(name) & (set->cap - 1);
  while (set->slots[j]) {
    if (strcmp(set->slots[j], name) == 0) {
      return 0;
    }
    j = (j + 1) & (set->cap - 1);
  }
  set->slots[j] = strdup(name);
  if (!set->slots[j]) {
    return -1;
  }
  set->used++;
  return 1;
}

static void name_set_free(name_set_t* set) {
  for (size_t i = 0; i < set->cap; i++) {
    free(set->slots[i]);
  }
  free(set->slots);
}

// Extract callback structure
typedef struct {
  extract_options_t* opts;
  bfc_t* reader;
  const char* output_dir;
  int count;
  int errors;
  name_set_t flat_names;
} extract_context_t;

static int extract_entry_callback(const bfc_entry_t* entry, void* user) {
  extract_context_t* ctx = (extract_context_t*) user;
  extract_options_t* opts = ctx->opts;

  ctx->count++;

  if (!entry_path_is_safe(entry->path)) {
    print_error("Refusing to extract '%s': unsafe path", entry->path);
    ctx->errors++;
    return 0;
  }

  // Determine output path
  char output_path[1024];
  const char* extract_name = entry->path;

  if (opts->flatten) {
    // Directories have nothing to hold once paths are dropped
    if (S_ISDIR(entry->mode)) {
      return 0;
    }
    const char* slash = strrchr(entry->path, '/');
    extract_name = slash ? slash + 1 : entry->path;

    int added = name_set_add(&ctx->flat_names, extract_name);
    if (added <= 0) {
      if (added == 0) {
        print_error("Refusing to extract '%s': another entry was already extracted as '%s' "
                    "(drop --flatten to keep directories)",
                    entry->path, extract_name);
      } else {
        print_error("Out of memory");
      }
      ctx->errors++;
      return 0;
    }
  }

  int n;
  if (ctx->output_dir) {
    n = snprintf(output_path, sizeof(output_path), "%s/%s", ctx->output_dir, extract_name);
  } else {
    n = snprintf(output_path, sizeof(output_path), "%s", extract_name);
  }
  if (n < 0 || (size_t) n >= sizeof(output_path)) {
    print_error("Refusing to extract '%s': path too long", entry->path);
    ctx->errors++;
    return 0;
  }

  if (has_symlink_parent(output_path)) {
    print_error("Refusing to extract '%s': a parent directory is a symlink", entry->path);
    ctx->errors++;
    return 0;
  }

  // Extract based on entry type
  int result;
  if (S_ISREG(entry->mode)) {
    result = extract_file(ctx->reader, entry, output_path, opts->force);
  } else if (S_ISDIR(entry->mode)) {
    result = extract_directory(output_path, entry, opts->force);
  } else if (S_ISLNK(entry->mode)) {
    result = extract_symlink(ctx->reader, entry, output_path, opts->force);
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

  // Open container for reading BEFORE changing directories
  print_verbose("Opening container: %s", opts.container_file);

  bfc_t* reader = NULL;
  result = bfc_open(opts.container_file, &reader);
  if (result != BFC_OK) {
    print_error("Failed to open container '%s': %s", opts.container_file, bfc_error_string(result));
    return 1;
  }

  // Configure encryption before changing directory, so relative paths to
  // --password-file and --keyfile resolve against the caller's directory
  int enc_result = cli_apply_reader_credentials(reader, &opts.creds, 1);
  cli_credentials_free(&opts.creds);
  if (enc_result < 0) {
    bfc_close_read(reader);
    return 1;
  }

  // Change to output directory if specified (after opening container)
  if (opts.output_dir) {
    print_verbose("Changing to directory: %s", opts.output_dir);
    if (chdir(opts.output_dir) != 0) {
      print_error("Cannot change to directory '%s': %s", opts.output_dir, strerror(errno));
      bfc_close_read(reader);
      return 1;
    }
  }

  // Extract entries
  extract_context_t ctx = {&opts, reader, NULL, 0, 0, {NULL, 0, 0}};

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

  name_set_free(&ctx.flat_names);

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
