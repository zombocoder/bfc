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

/*
 * BFC Encryption Example
 *
 * This example demonstrates how to use BFC's encryption features to create
 * secure containers that protect file contents with strong cryptography.
 *
 * Features demonstrated:
 * - Password-based encryption
 * - Key file encryption
 * - Combining encryption with compression
 * - Secure key handling
 * - Decryption and verification
 */

#include <bfc.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Extraction context for callback
typedef struct {
  bfc_t* reader;
  const char* extract_dir;
  int count;
} extract_context_t;

// Callback for extracting files during listing
static int extract_callback(const bfc_entry_t* entry, void* user_data) {
  extract_context_t* ctx = (extract_context_t*) user_data;

  if (!S_ISREG(entry->mode)) {
    return 0; // Skip non-regular files for this example
  }

  char output_path[1024];
  snprintf(output_path, sizeof(output_path), "%s/%s", ctx->extract_dir, entry->path);

  printf("Extracting %s... ", entry->path);
  fflush(stdout);

  int fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, entry->mode & 0777);
  if (fd < 0) {
    printf("FAILED (cannot create file)\n");
    return 0;
  }

  int result = bfc_extract_to_fd(ctx->reader, entry->path, fd);
  close(fd);

  if (result == BFC_OK) {
    printf("OK (%llu bytes)\n", (unsigned long long) entry->size);
    ctx->count++;
  } else {
    printf("FAILED (%d)\n", result);
    unlink(output_path); // Remove failed extraction
  }

  return 0;
}

// Callback for showing file info during listing
static int info_callback(const bfc_entry_t* entry, void* user_data) {
  (void) user_data;

  printf("\nFile: %s\n", entry->path);
  printf("  Size: %llu bytes\n", (unsigned long long) entry->size);
  printf("  Stored: %llu bytes\n", (unsigned long long) entry->obj_size);
  printf("  Mode: 0%o\n", entry->mode & 0777);

  // Show compression info
  const char* comp_name = "unknown";
  switch (entry->comp) {
  case 0:
    comp_name = "none";
    break;
  case 1:
    comp_name = "zstd";
    break;
  }
  printf("  Compression: %s\n", comp_name);

  // Show encryption info
  const char* enc_name = "unknown";
  switch (entry->enc) {
  case 0:
    enc_name = "none";
    break;
  case 1:
    enc_name = "ChaCha20-Poly1305";
    break;
  }
  printf("  Encryption: %s\n", enc_name);

  return 0;
}

static void print_usage(const char* program) {
  printf("Usage: %s <operation> [options]\n\n", program);
  printf("Operations:\n");
  printf("  create-password <container> <password>    Create encrypted container with password\n");
  printf("  create-keyfile  <container> <keyfile>     Create encrypted container with key file\n");
  printf("  extract         <container> <password>    Extract encrypted container\n");
  printf("  info            <container>               Show container encryption info\n");
  printf("  demo                                      Run complete demo\n\n");
  printf("Examples:\n");
  printf("  %s create-password secure.bfc mypassword123\n", program);
  printf("  %s create-keyfile secure.bfc secret.key\n", program);
  printf("  %s extract secure.bfc mypassword123\n", program);
  printf("  %s info secure.bfc\n", program);
  printf("  %s demo\n", program);
}

static int create_sample_files(void) {
  // Create some sample files to demonstrate encryption

  // 1. Create a text file with sensitive data
  FILE* f = fopen("sensitive_data.txt", "w");
  if (!f) {
    perror("Failed to create sensitive_data.txt");
    return 1;
  }
  fprintf(f, "CONFIDENTIAL DOCUMENT\n");
  fprintf(f, "Account Numbers: 1234-5678-9012-3456\n");
  fprintf(f, "API Key: sk_live_abcdef123456789\n");
  fprintf(f, "Database Password: sup3r_s3cur3_p@ssw0rd\n");
  fprintf(f, "This file contains sensitive information that should be encrypted!\n");
  fprintf(f, "Even if someone gains access to the container file, the contents\n");
  fprintf(f, "should remain protected without the correct password or key.\n");
  fclose(f);

  // 2. Create a binary file
  f = fopen("config.dat", "wb");
  if (!f) {
    perror("Failed to create config.dat");
    return 1;
  }
  uint8_t config_data[] = {0x42, 0x46, 0x43, 0x01, 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF};
  fwrite(config_data, 1, sizeof(config_data), f);
  fclose(f);

  // 3. Create a larger file with repetitive content (good for compression + encryption)
  f = fopen("large_log.txt", "w");
  if (!f) {
    perror("Failed to create large_log.txt");
    return 1;
  }
  for (int i = 0; i < 1000; i++) {
    fprintf(f, "2025-01-15 12:34:%02d [INFO] System status: OK, memory: %d%%, cpu: %d%%\n", i % 60,
            75 + (i % 25), 10 + (i % 15));
  }
  fclose(f);

  printf("Created sample files:\n");
  printf("  sensitive_data.txt - Contains sensitive information\n");
  printf("  config.dat         - Binary configuration file\n");
  printf("  large_log.txt      - Large repetitive log file (good for compression)\n\n");

  return 0;
}

static int create_encrypted_container_password(const char* container_path, const char* password) {
  printf("Creating encrypted container with password authentication...\n");

  // Create the container
  bfc_t* writer = NULL;
  int result = bfc_create(container_path, 4096, 0, &writer);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to create container: %d\n", result);
    return 1;
  }

  // Enable compression (encrypt happens after compression)
#ifdef BFC_WITH_ZSTD
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
  if (result == BFC_OK) {
    printf("Enabled ZSTD compression (level 3)\n");
  } else {
    printf("ZSTD not available, using no compression\n");
  }
#endif

  // Set encryption password
#ifdef BFC_WITH_SODIUM
  result = bfc_set_encryption_password(writer, password, strlen(password));
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to set encryption password: %d\n", result);
    bfc_close(writer);
    return 1;
  }
  printf("Enabled ChaCha20-Poly1305 encryption with password\n");
#else
  printf("WARNING: Encryption not available (BFC_WITH_SODIUM not enabled)\n");
  printf("Files will be stored without encryption!\n");
#endif

  // Add the sample files
  const char* files[] = {"sensitive_data.txt", "config.dat", "large_log.txt"};
  for (int i = 0; i < 3; i++) {
    FILE* file = fopen(files[i], "rb");
    if (!file) {
      fprintf(stderr, "Failed to open %s\n", files[i]);
      continue;
    }

    uint32_t crc = 0;
    result = bfc_add_file(writer, files[i], file, 0644, 0, &crc);
    fclose(file);

    if (result != BFC_OK) {
      fprintf(stderr, "Failed to add %s: %d\n", files[i], result);
    } else {
      printf("Added %s (CRC32C: 0x%08x)\n", files[i], crc);
    }
  }

  // Finalize the container
  result = bfc_finish(writer);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to finish container: %d\n", result);
    bfc_close(writer);
    return 1;
  }

  bfc_close(writer);
  printf("Successfully created encrypted container: %s\n\n", container_path);
  return 0;
}

static int create_encrypted_container_keyfile(const char* container_path,
                                              const char* keyfile_path) {
  printf("Creating encrypted container with key file authentication...\n");

  // Generate a random 256-bit (32-byte) key
  uint8_t key[32];
  FILE* urandom = fopen("/dev/urandom", "rb");
  if (!urandom) {
    fprintf(stderr, "Failed to open /dev/urandom for key generation\n");
    return 1;
  }
  if (fread(key, 1, 32, urandom) != 32) {
    fprintf(stderr, "Failed to read random bytes\n");
    fclose(urandom);
    return 1;
  }
  fclose(urandom);

  // Write key to file
  FILE* keyfile = fopen(keyfile_path, "wb");
  if (!keyfile) {
    perror("Failed to create key file");
    return 1;
  }
  if (fwrite(key, 1, 32, keyfile) != 32) {
    fprintf(stderr, "Failed to write key to file\n");
    fclose(keyfile);
    return 1;
  }
  fclose(keyfile);
  printf("Generated 256-bit encryption key: %s\n", keyfile_path);
  printf("Key (hex): ");
  for (int i = 0; i < 32; i++) {
    printf("%02x", key[i]);
    if (i == 15)
      printf("\n           ");
  }
  printf("\n");

  // Create the container
  bfc_t* writer = NULL;
  int result = bfc_create(container_path, 4096, 0, &writer);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to create container: %d\n", result);
    return 1;
  }

  // Set encryption key
#ifdef BFC_WITH_SODIUM
  result = bfc_set_encryption_key(writer, key);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to set encryption key: %d\n", result);
    bfc_close(writer);
    return 1;
  }
  printf("Enabled ChaCha20-Poly1305 encryption with key file\n");
#else
  printf("WARNING: Encryption not available (BFC_WITH_SODIUM not enabled)\n");
#endif

  // Clear the key from memory (security best practice)
  memset(key, 0, sizeof(key));

  // Add files (same as password example)
  const char* files[] = {"sensitive_data.txt", "config.dat", "large_log.txt"};
  for (int i = 0; i < 3; i++) {
    FILE* file = fopen(files[i], "rb");
    if (!file)
      continue;

    uint32_t crc = 0;
    result = bfc_add_file(writer, files[i], file, 0644, 0, &crc);
    fclose(file);

    if (result == BFC_OK) {
      printf("Added %s (CRC32C: 0x%08x)\n", files[i], crc);
    }
  }

  result = bfc_finish(writer);
  bfc_close(writer);

  if (result == BFC_OK) {
    printf("Successfully created encrypted container: %s\n", container_path);
    printf("Keep the key file (%s) secure and separate from the container!\n\n", keyfile_path);
  }

  return (result == BFC_OK) ? 0 : 1;
}

static int extract_encrypted_container(const char* container_path, const char* password) {
  printf("Extracting encrypted container with password...\n");

  // Open the container
  bfc_t* reader = NULL;
  int result = bfc_open(container_path, &reader);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to open container: %d\n", result);
    return 1;
  }

  // Set decryption password
#ifdef BFC_WITH_SODIUM
  result = bfc_set_encryption_password(reader, password, strlen(password));
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to set decryption password: %d\n", result);
    bfc_close_read(reader);
    return 1;
  }
  printf("Set decryption password\n");
#else
  printf("WARNING: Encryption not available, extracting without decryption\n");
#endif

  // Create extraction directory
  const char* extract_dir = "extracted";
  mkdir(extract_dir, 0755);

  // List and extract all files using the callback defined above

  extract_context_t ctx = {reader, extract_dir, 0};
  result = bfc_list(reader, NULL, extract_callback, &ctx);

  bfc_close_read(reader);

  if (result == BFC_OK && ctx.count > 0) {
    printf("\nSuccessfully extracted %d files to %s/\n", ctx.count, extract_dir);
    printf("Verifying extracted content:\n");

    // Show first few lines of sensitive data to verify decryption
    FILE* f = fopen("extracted/sensitive_data.txt", "r");
    if (f) {
      char line[256];
      int line_count = 0;
      while (fgets(line, sizeof(line), f) && line_count < 3) {
        printf("  %s", line);
        line_count++;
      }
      printf("  [...]\n");
      fclose(f);
    }
    printf("\n");
  } else {
    printf("Extraction failed or no files extracted\n");
    return 1;
  }

  return 0;
}

static int show_container_info(const char* container_path) {
  printf("Container information for: %s\n", container_path);

  bfc_t* reader = NULL;
  int result = bfc_open(container_path, &reader);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to open container: %d\n", result);
    return 1;
  }

  // Check if container has encrypted content
#ifdef BFC_WITH_SODIUM
  int has_encryption = bfc_has_encryption(reader);
  printf("Encryption: %s\n", has_encryption ? "YES" : "NO");
#else
  printf("Encryption: Not supported in this build\n");
#endif

  // List files and show encryption status using the callback defined above

  result = bfc_list(reader, NULL, info_callback, NULL);
  bfc_close_read(reader);

  return (result == BFC_OK) ? 0 : 1;
}

static int run_demo(void) {
  printf("=== BFC Encryption Demo ===\n\n");

  // Clean up any existing files
  unlink("demo_encrypted.bfc");
  unlink("demo_keyfile.bfc");
  unlink("demo.key");
  unlink("sensitive_data.txt");
  unlink("config.dat");
  unlink("large_log.txt");
  system("rm -rf extracted");

  // Step 1: Create sample files
  printf("Step 1: Creating sample files with sensitive data...\n");
  if (create_sample_files() != 0) {
    return 1;
  }

  // Step 2: Create encrypted container with password
  printf("Step 2: Creating password-encrypted container...\n");
  if (create_encrypted_container_password("demo_encrypted.bfc", "demo_password_123") != 0) {
    return 1;
  }

  // Step 3: Create encrypted container with key file
  printf("Step 3: Creating key-file-encrypted container...\n");
  if (create_encrypted_container_keyfile("demo_keyfile.bfc", "demo.key") != 0) {
    return 1;
  }

  // Step 4: Show container information
  printf("Step 4: Showing container information...\n");
  show_container_info("demo_encrypted.bfc");

  // Step 5: Extract encrypted container
  printf("Step 5: Extracting password-encrypted container...\n");
  if (extract_encrypted_container("demo_encrypted.bfc", "demo_password_123") != 0) {
    return 1;
  }

  // Step 6: Test wrong password (should fail)
  printf("Step 6: Testing wrong password (should fail)...\n");
  bfc_t* reader = NULL;
  int result = bfc_open("demo_encrypted.bfc", &reader);
  if (result == BFC_OK) {
#ifdef BFC_WITH_SODIUM
    result = bfc_set_encryption_password(reader, "wrong_password", 14);
    if (result == BFC_OK) {
      // Try to extract a file - should fail during decryption
      int fd = open("/tmp/test_decrypt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        result = bfc_extract_to_fd(reader, "sensitive_data.txt", fd);
        close(fd);
        unlink("/tmp/test_decrypt");

        if (result != BFC_OK) {
          printf("✓ Correctly failed with wrong password: %d\n", result);
        } else {
          printf("✗ WARNING: Decryption succeeded with wrong password!\n");
        }
      }
    }
#endif
    bfc_close_read(reader);
  }

  printf("\n=== Demo Complete ===\n");
  printf("Files created:\n");
  printf("  demo_encrypted.bfc - Password-encrypted container\n");
  printf("  demo_keyfile.bfc   - Key-file-encrypted container\n");
  printf("  demo.key           - 256-bit encryption key file\n");
  printf("  extracted/         - Decrypted files\n\n");
  printf("Try these commands:\n");
  printf("  ./encrypt_example info demo_encrypted.bfc\n");
  printf("  ./encrypt_example extract demo_encrypted.bfc demo_password_123\n");

  return 0;
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const char* operation = argv[1];

  if (strcmp(operation, "demo") == 0) {
    return run_demo();
  } else if (strcmp(operation, "create-password") == 0) {
    if (argc != 4) {
      fprintf(stderr, "Usage: %s create-password <container> <password>\n", argv[0]);
      return 1;
    }
    if (create_sample_files() != 0)
      return 1;
    return create_encrypted_container_password(argv[2], argv[3]);
  } else if (strcmp(operation, "create-keyfile") == 0) {
    if (argc != 4) {
      fprintf(stderr, "Usage: %s create-keyfile <container> <keyfile>\n", argv[0]);
      return 1;
    }
    if (create_sample_files() != 0)
      return 1;
    return create_encrypted_container_keyfile(argv[2], argv[3]);
  } else if (strcmp(operation, "extract") == 0) {
    if (argc != 4) {
      fprintf(stderr, "Usage: %s extract <container> <password>\n", argv[0]);
      return 1;
    }
    return extract_encrypted_container(argv[2], argv[3]);
  } else if (strcmp(operation, "info") == 0) {
    if (argc != 3) {
      fprintf(stderr, "Usage: %s info <container>\n", argv[0]);
      return 1;
    }
    return show_container_info(argv[2]);
  } else {
    fprintf(stderr, "Unknown operation: %s\n", operation);
    print_usage(argv[0]);
    return 1;
  }
}