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

#include "bfc_encrypt.h"
#include <assert.h>
#include <bfc.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Test basic encryption support detection
static int test_encryption_support(void) {
  // BFC_ENC_NONE should always be supported
  assert(bfc_encrypt_is_supported(BFC_ENC_NONE) == 1);

  // Invalid encryption type should not be supported
  assert(bfc_encrypt_is_supported(255) == 0);

#ifdef BFC_WITH_SODIUM
  // ChaCha20-Poly1305 should be supported when built with libsodium
  assert(bfc_encrypt_is_supported(BFC_ENC_CHACHA20_POLY1305) == 1);
#else
  // ChaCha20-Poly1305 should not be supported when not built with libsodium
  assert(bfc_encrypt_is_supported(BFC_ENC_CHACHA20_POLY1305) == 0);
#endif

  return 0;
}

// Test encryption key creation and derivation
static int test_encryption_key_management(void) {
#ifdef BFC_WITH_SODIUM
  // Test creating key from raw bytes
  uint8_t raw_key[32];
  memset(raw_key, 0x42, sizeof(raw_key));

  bfc_encrypt_key_t key;
  int result = bfc_encrypt_key_from_bytes(raw_key, &key);
  assert(result == BFC_OK);
  bfc_encrypt_key_clear(&key);

  // Test creating key from password
  const char* password = "test_password_123";
  uint8_t salt[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  bfc_encrypt_key_t key2;
  result = bfc_encrypt_key_from_password(password, strlen(password), salt, &key2);
  assert(result == BFC_OK);
  bfc_encrypt_key_clear(&key2);

  // Test key consistency - same password and salt should produce same key
  bfc_encrypt_key_t key3, key4;
  result = bfc_encrypt_key_from_password(password, strlen(password), salt, &key3);
  assert(result == BFC_OK);
  result = bfc_encrypt_key_from_password(password, strlen(password), salt, &key4);
  assert(result == BFC_OK);

  // Keys should be the same for same password+salt
  assert(memcmp(key3.key, key4.key, 32) == 0);

  bfc_encrypt_key_clear(&key3);
  bfc_encrypt_key_clear(&key4);
#endif

  return 0;
}

// Test basic data encryption and decryption
static int test_encrypt_decrypt_data(void) {
#ifdef BFC_WITH_SODIUM
  const char* test_data = "Hello, world! This is test data for encryption.";
  size_t data_size = strlen(test_data);

  // Create encryption key
  uint8_t raw_key[32];
  memset(raw_key, 0x42, sizeof(raw_key));
  bfc_encrypt_key_t key;
  int result = bfc_encrypt_key_from_bytes(raw_key, &key);
  assert(result == BFC_OK);

  // Test encryption
  bfc_encrypt_result_t enc_result = bfc_encrypt_data(&key, test_data, data_size, NULL, 0);
  assert(enc_result.error == BFC_OK);
  assert(enc_result.data != NULL);
  assert(enc_result.original_size == data_size);
  // Encrypted size should include nonce + ciphertext + tag
  assert(enc_result.encrypted_size == data_size + BFC_ENC_NONCE_SIZE + BFC_ENC_TAG_SIZE);

  // Test decryption
  bfc_decrypt_result_t dec_result =
      bfc_decrypt_data(&key, enc_result.data, enc_result.encrypted_size, NULL, 0, data_size);
  assert(dec_result.error == BFC_OK);
  assert(dec_result.data != NULL);
  assert(dec_result.decrypted_size == data_size);
  assert(memcmp(dec_result.data, test_data, data_size) == 0);

  free(enc_result.data);
  free(dec_result.data);
  bfc_encrypt_key_clear(&key);
#endif

  return 0;
}

// Test encryption with associated data (AEAD)
static int test_encrypt_decrypt_with_associated_data(void) {
#ifdef BFC_WITH_SODIUM
  const char* test_data = "Secret message content";
  const char* associated_data = "path=/secret/file.txt,mode=0600";
  size_t data_size = strlen(test_data);
  size_t ad_size = strlen(associated_data);

  // Create encryption key
  uint8_t raw_key[32];
  memset(raw_key, 0x55, sizeof(raw_key));
  bfc_encrypt_key_t key;
  int result = bfc_encrypt_key_from_bytes(raw_key, &key);
  assert(result == BFC_OK);

  // Test encryption with associated data
  bfc_encrypt_result_t enc_result =
      bfc_encrypt_data(&key, test_data, data_size, associated_data, ad_size);
  assert(enc_result.error == BFC_OK);
  assert(enc_result.data != NULL);
  assert(enc_result.original_size == data_size);
  assert(enc_result.encrypted_size == data_size + BFC_ENC_NONCE_SIZE + BFC_ENC_TAG_SIZE);

  // Test decryption with correct associated data
  bfc_decrypt_result_t dec_result = bfc_decrypt_data(
      &key, enc_result.data, enc_result.encrypted_size, associated_data, ad_size, data_size);
  assert(dec_result.error == BFC_OK);
  assert(dec_result.data != NULL);
  assert(dec_result.decrypted_size == data_size);
  assert(memcmp(dec_result.data, test_data, data_size) == 0);

  free(dec_result.data);

  // Test decryption with wrong associated data (should fail)
  const char* wrong_ad = "path=/wrong/file.txt,mode=0644";
  dec_result = bfc_decrypt_data(&key, enc_result.data, enc_result.encrypted_size, wrong_ad,
                                strlen(wrong_ad), data_size);
  assert(dec_result.error != BFC_OK); // Should fail authentication
  assert(dec_result.data == NULL);

  // Test decryption with no associated data (should fail)
  dec_result =
      bfc_decrypt_data(&key, enc_result.data, enc_result.encrypted_size, NULL, 0, data_size);
  assert(dec_result.error != BFC_OK); // Should fail authentication
  assert(dec_result.data == NULL);

  free(enc_result.data);
  bfc_encrypt_key_clear(&key);
#endif

  return 0;
}

// Test error handling in encryption functions
static int test_encrypt_error_handling(void) {
#ifdef BFC_WITH_SODIUM
  const char* test_data = "test data";
  uint8_t raw_key[32];
  memset(raw_key, 0x42, sizeof(raw_key));
  bfc_encrypt_key_t key;
  int key_result = bfc_encrypt_key_from_bytes(raw_key, &key);
  assert(key_result == BFC_OK);

  // Test invalid parameters for encryption
  bfc_encrypt_result_t result = bfc_encrypt_data(NULL, test_data, 10, NULL, 0);
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  result = bfc_encrypt_data(&key, NULL, 10, NULL, 0);
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  // Note: Encrypting zero-length data is actually valid in AEAD schemes
  // result = bfc_encrypt_data(&key, test_data, 0, NULL, 0);
  // assert(result.error == BFC_E_INVAL);
  // assert(result.data == NULL);

  // Test invalid parameters for decryption
  bfc_decrypt_result_t dec_result = bfc_decrypt_data(NULL, test_data, 10, NULL, 0, 10);
  assert(dec_result.error == BFC_E_INVAL);
  assert(dec_result.data == NULL);

  dec_result = bfc_decrypt_data(&key, NULL, 10, NULL, 0, 10);
  assert(dec_result.error == BFC_E_INVAL);
  assert(dec_result.data == NULL);

  dec_result = bfc_decrypt_data(&key, test_data, 0, NULL, 0, 10);
  assert(dec_result.error == BFC_E_INVAL);
  assert(dec_result.data == NULL);

  // Test decryption with invalid ciphertext size (too small)
  dec_result = bfc_decrypt_data(&key, test_data, 15, NULL, 0, 10); // Less than nonce + tag size
  assert(dec_result.error != BFC_OK);
  assert(dec_result.data == NULL);

  bfc_encrypt_key_clear(&key);
#else
  // Test that functions return appropriate errors when libsodium not available
  bfc_encrypt_result_t result = bfc_encrypt_data(NULL, "data", 4, NULL, 0);
  assert(result.error == BFC_E_INVAL);
  assert(result.data == NULL);

  bfc_decrypt_result_t dec_result = bfc_decrypt_data(NULL, "data", 20, NULL, 0, 4);
  assert(dec_result.error == BFC_E_INVAL);
  assert(dec_result.data == NULL);

  // Test key derivation without sodium
  bfc_encrypt_key_t dummy_key;
  int key_result = bfc_encrypt_key_from_password("password", 8, NULL, &dummy_key);
  assert(key_result == BFC_E_INVAL);

  // Test key clearing (always available)
  bfc_encrypt_key_clear(&dummy_key);
#endif

  return 0;
}

// Test encryption utility functions
static int test_encryption_utilities(void) {
  // Test encryption type names
  assert(strcmp(bfc_encrypt_name(BFC_ENC_NONE), "none") == 0);
  assert(strcmp(bfc_encrypt_name(BFC_ENC_CHACHA20_POLY1305), "ChaCha20-Poly1305") == 0);
  assert(strcmp(bfc_encrypt_name(255), "unknown") == 0);

  // Test encryption overhead calculation
  assert(bfc_encrypt_overhead(BFC_ENC_NONE) == 0);
  assert(bfc_encrypt_overhead(BFC_ENC_CHACHA20_POLY1305) == BFC_ENC_NONCE_SIZE + BFC_ENC_TAG_SIZE);

  // Test encryption support detection
  assert(bfc_encrypt_is_supported(BFC_ENC_NONE) == 1);
#ifdef BFC_WITH_SODIUM
  assert(bfc_encrypt_is_supported(BFC_ENC_CHACHA20_POLY1305) == 1);
#else
  assert(bfc_encrypt_is_supported(BFC_ENC_CHACHA20_POLY1305) == 0);
#endif

  return 0;
}

// Test BFC writer encryption settings
static int test_writer_encryption_settings(void) {
  const char* filename = "/tmp/test_encryption_writer.bfc";
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  assert(result == BFC_OK);
  assert(writer != NULL);

#ifdef BFC_WITH_SODIUM
  // Test setting encryption password
  result = bfc_set_encryption_password(writer, "test_password", 13);
  assert(result == BFC_OK);

  // Test setting encryption key
  uint8_t key[32];
  memset(key, 0x42, sizeof(key));
  result = bfc_set_encryption_key(writer, key);
  assert(result == BFC_OK);

  // Clear key memory
  memset(key, 0, sizeof(key));
#else
  // Test that encryption functions return appropriate errors when not available
  result = bfc_set_encryption_password(writer, "test_password", 13);
  assert(result == BFC_E_INVAL);

  uint8_t key[32];
  memset(key, 0x42, sizeof(key));
  result = bfc_set_encryption_key(writer, key);
  assert(result == BFC_E_INVAL);
#endif

  bfc_close(writer);
  unlink(filename);

  return 0;
}

// Test end-to-end encryption with BFC container
static int test_end_to_end_encryption(void) {
#ifdef BFC_WITH_SODIUM
  const char* container_filename = "/tmp/encrypt_e2e_encryption.bfc";
  const char* test_filename = "/tmp/encrypt_e2e_input_enc.txt";
  const char* extract_filename = "/tmp/encrypt_e2e_output_enc.txt";

  // Clean up any existing files
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);

  // Create test input file with sensitive content
  FILE* input_file = fopen(test_filename, "w");
  assert(input_file != NULL);

  const char* sensitive_content =
      "This is sensitive data that should be encrypted in the container.\n"
      "It contains passwords, API keys, and other confidential information.\n"
      "The encryption should protect this data from unauthorized access.\n";
  fputs(sensitive_content, input_file);
  fclose(input_file);

  // Create BFC container with encryption
  bfc_t* writer = NULL;
  int result = bfc_create(container_filename, 4096, 0, &writer);
  assert(result == BFC_OK);

  // Set encryption password
  const char* password = "test_encryption_password_123";
  result = bfc_set_encryption_password(writer, password, strlen(password));
  assert(result == BFC_OK);

  // Add the test file
  FILE* test_file = fopen(test_filename, "rb");
  assert(test_file != NULL);

  result = bfc_add_file(writer, "secret_file.txt", test_file, 0600, 0, NULL);
  assert(result == BFC_OK);
  fclose(test_file);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Verify that container is encrypted (cannot read without password)
  bfc_t* reader = NULL;
  result = bfc_open(container_filename, &reader);
  assert(result == BFC_OK);

  // Try to extract without password (should fail)
  int out_fd = open(extract_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  result = bfc_extract_to_fd(reader, "secret_file.txt", out_fd);
  assert(result != BFC_OK); // Should fail without decryption key
  close(out_fd);
  unlink(extract_filename);

  // Set correct password and try again
  result = bfc_reader_set_encryption_password(reader, password, strlen(password));
  assert(result == BFC_OK);

  // Verify encryption info in entry metadata
  bfc_entry_t entry;
  result = bfc_stat(reader, "secret_file.txt", &entry);
  assert(result == BFC_OK);
  assert(entry.enc == BFC_ENC_CHACHA20_POLY1305);

  // Extract with correct password
  out_fd = open(extract_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  result = bfc_extract_to_fd(reader, "secret_file.txt", out_fd);
  assert(result == BFC_OK);
  close(out_fd);
  bfc_close_read(reader);

  // Compare original and extracted files
  FILE* orig = fopen(test_filename, "rb");
  FILE* extracted = fopen(extract_filename, "rb");
  assert(orig != NULL);
  assert(extracted != NULL);

  // Compare file sizes
  fseek(orig, 0, SEEK_END);
  long orig_size = ftell(orig);
  fseek(extracted, 0, SEEK_END);
  long extracted_size = ftell(extracted);
  assert(orig_size == extracted_size);

  // Compare content
  rewind(orig);
  rewind(extracted);

  char orig_buf[4096], extracted_buf[4096];
  size_t orig_read, extracted_read;

  while ((orig_read = fread(orig_buf, 1, sizeof(orig_buf), orig)) > 0) {
    extracted_read = fread(extracted_buf, 1, sizeof(extracted_buf), extracted);
    assert(orig_read == extracted_read);
    assert(memcmp(orig_buf, extracted_buf, orig_read) == 0);
  }

  fclose(orig);
  fclose(extracted);

  // Test with wrong password
  reader = NULL;
  result = bfc_open(container_filename, &reader);
  assert(result == BFC_OK);

  const char* wrong_password = "wrong_password";
  result = bfc_reader_set_encryption_password(reader, wrong_password, strlen(wrong_password));
  assert(result == BFC_OK); // Setting password should succeed

  out_fd = open(extract_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  result = bfc_extract_to_fd(reader, "secret_file.txt", out_fd);
  assert(result != BFC_OK); // Extraction should fail with wrong password
  close(out_fd);
  bfc_close_read(reader);

  // Clean up
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);
#endif

  return 0;
}

// Test encryption with compression
static int test_encryption_with_compression(void) {
#ifdef BFC_WITH_SODIUM
  const char* container_filename = "/tmp/encrypt_compress_test.bfc";
  const char* test_filename = "/tmp/encrypt_compress_input.txt";
  const char* extract_filename = "/tmp/encrypt_compress_output.txt";

  // Clean up any existing files
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);

  // Create test input file with compressible content
  FILE* input_file = fopen(test_filename, "w");
  assert(input_file != NULL);

  // Write highly compressible content
  for (int i = 0; i < 1000; i++) {
    fprintf(input_file, "This is line %d with repetitive content that compresses well.\n", i);
  }
  fclose(input_file);

  // Create BFC container with both compression and encryption
  bfc_t* writer = NULL;
  int result = bfc_create(container_filename, 4096, 0, &writer);
  assert(result == BFC_OK);

#ifdef BFC_WITH_ZSTD
  // Set compression first
  result = bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
  assert(result == BFC_OK);
#endif

  // Set encryption
  const char* password = "compress_encrypt_test_password";
  result = bfc_set_encryption_password(writer, password, strlen(password));
  assert(result == BFC_OK);

  // Add the test file
  FILE* test_file = fopen(test_filename, "rb");
  assert(test_file != NULL);

  result = bfc_add_file(writer, "compress_encrypt_file.txt", test_file, 0644, 0, NULL);
  assert(result == BFC_OK);
  fclose(test_file);

  result = bfc_finish(writer);
  assert(result == BFC_OK);
  bfc_close(writer);

  // Read back and verify
  bfc_t* reader = NULL;
  result = bfc_open(container_filename, &reader);
  assert(result == BFC_OK);

  result = bfc_reader_set_encryption_password(reader, password, strlen(password));
  assert(result == BFC_OK);

  // Check entry metadata
  bfc_entry_t entry;
  result = bfc_stat(reader, "compress_encrypt_file.txt", &entry);
  assert(result == BFC_OK);
  assert(entry.enc == BFC_ENC_CHACHA20_POLY1305);

#ifdef BFC_WITH_ZSTD
  assert(entry.comp == BFC_COMP_ZSTD);
  // With compression, stored size should be much smaller than original
  // (even with encryption overhead, compression should win for repetitive content)
  assert(entry.obj_size < entry.size / 2);
#else
  assert(entry.comp == BFC_COMP_NONE);
#endif

  // Extract and verify content
  int out_fd = open(extract_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  assert(out_fd >= 0);

  result = bfc_extract_to_fd(reader, "compress_encrypt_file.txt", out_fd);
  assert(result == BFC_OK);
  close(out_fd);
  bfc_close_read(reader);

  // Compare original and extracted files
  FILE* orig = fopen(test_filename, "r");
  FILE* extracted = fopen(extract_filename, "r");
  assert(orig != NULL);
  assert(extracted != NULL);

  char orig_line[256], extracted_line[256];
  while (fgets(orig_line, sizeof(orig_line), orig) != NULL) {
    assert(fgets(extracted_line, sizeof(extracted_line), extracted) != NULL);
    assert(strcmp(orig_line, extracted_line) == 0);
  }
  assert(fgets(extracted_line, sizeof(extracted_line), extracted) == NULL); // EOF

  fclose(orig);
  fclose(extracted);

  // Clean up
  unlink(container_filename);
  unlink(test_filename);
  unlink(extract_filename);
#endif

  return 0;
}

// Test additional encryption utility functions
static int test_encrypt_utility_coverage(void) {
  // Test utility functions that don't require full encryption
  const char* name_none = bfc_encrypt_name(BFC_ENC_NONE);
  assert(strcmp(name_none, "none") == 0);

  const char* name_chacha = bfc_encrypt_name(BFC_ENC_CHACHA20_POLY1305);
  assert(strcmp(name_chacha, "ChaCha20-Poly1305") == 0);

  const char* name_unknown = bfc_encrypt_name(255);
  assert(strcmp(name_unknown, "unknown") == 0);

  // Test support detection for various types
  assert(bfc_encrypt_is_supported(BFC_ENC_NONE) == 1);
  assert(bfc_encrypt_is_supported(255) == 0);

  return 0;
}

int test_encrypt(void) {
  int result = 0;

  result += test_encryption_support();
  result += test_encryption_key_management();
  result += test_encrypt_decrypt_data();
  result += test_encrypt_decrypt_with_associated_data();
  result += test_encrypt_error_handling();
  result += test_encryption_utilities();
  result += test_writer_encryption_settings();
  result += test_end_to_end_encryption();
  result += test_encryption_with_compression();
  result += test_encrypt_utility_coverage();

  return result;
}