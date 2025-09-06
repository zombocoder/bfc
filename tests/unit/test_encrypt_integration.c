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

// Integration tests that focus on code paths that require libsodium
#ifdef BFC_WITH_SODIUM

// Test encryption context lifecycle
static int test_encryption_context_lifecycle(void) {
  // Test encrypt context creation and destruction
  bfc_encrypt_ctx_t* ctx = bfc_encrypt_ctx_create();
  assert(ctx != NULL);

  // Test initialization with password
  const char* password = "integration_test_password";
  const uint8_t salt[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

  int result = bfc_encrypt_ctx_init_password(ctx, password, strlen(password), salt);
  assert(result == BFC_OK);

  // Test processing with context
  const char* plaintext = "Integration test data with encryption context";
  const char* associated = "metadata=test,format=bfc";

  uint8_t output[128];
  size_t output_len = sizeof(output);

  result = bfc_encrypt_ctx_process(ctx, plaintext, strlen(plaintext), associated,
                                   strlen(associated), output, &output_len);
  assert(result == BFC_OK);
  assert(output_len > strlen(plaintext)); // Should include tag

  // Test context reset and reinitialization
  bfc_encrypt_ctx_reset(ctx);

  result = bfc_encrypt_ctx_init_password(ctx, password, strlen(password), salt);
  assert(result == BFC_OK);

  bfc_encrypt_ctx_destroy(ctx);
  return 0;
}

// Test key derivation edge cases
static int test_key_derivation_edge_cases(void) {
  bfc_encrypt_key_t key;

  // Test minimum password length
  int result = bfc_encrypt_key_from_password("a", 1, NULL, &key);
  assert(result == BFC_OK);
  bfc_encrypt_key_clear(&key);

  // Test maximum reasonable password length
  char long_password[256];
  memset(long_password, 'A', sizeof(long_password) - 1);
  long_password[255] = '\0';

  result = bfc_encrypt_key_from_password(long_password, strlen(long_password), NULL, &key);
  assert(result == BFC_OK);
  bfc_encrypt_key_clear(&key);

  // Test with custom salt
  const uint8_t custom_salt[32] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
                                   0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                   0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

  result = bfc_encrypt_key_from_password("test", 4, custom_salt, &key);
  assert(result == BFC_OK);

  // Verify the salt was used
  assert(memcmp(key.salt, custom_salt, 32) == 0);
  bfc_encrypt_key_clear(&key);

  return 0;
}

// Test large data encryption/decryption
static int test_large_data_encryption(void) {
  // Create large test data
  size_t data_size = 64 * 1024; // 64KB
  char* large_data = malloc(data_size);
  assert(large_data != NULL);

  // Fill with pattern
  for (size_t i = 0; i < data_size; i++) {
    large_data[i] = (char) (i % 256);
  }

  // Create encryption key
  uint8_t raw_key[32];
  for (int i = 0; i < 32; i++) {
    raw_key[i] = (uint8_t) (i * 8);
  }
  bfc_encrypt_key_t* key = bfc_encrypt_key_create_from_key(raw_key);
  assert(key != NULL);

  // Test encryption
  bfc_encrypt_result_t enc_result = bfc_encrypt_data(key, large_data, data_size, NULL, 0);
  assert(enc_result.error == BFC_OK);
  assert(enc_result.data != NULL);
  assert(enc_result.encrypted_size == data_size + 16); // data + tag
  assert(enc_result.original_size == data_size);

  // Test decryption
  bfc_decrypt_result_t dec_result =
      bfc_decrypt_data(key, enc_result.data, enc_result.encrypted_size, NULL, 0, data_size);
  assert(dec_result.error == BFC_OK);
  assert(dec_result.data != NULL);
  assert(dec_result.decrypted_size == data_size);
  assert(memcmp(dec_result.data, large_data, data_size) == 0);

  free(enc_result.data);
  free(dec_result.data);
  bfc_encrypt_key_destroy(key);
  free(large_data);

  return 0;
}

// Test encryption with various data sizes
static int test_encryption_data_sizes(void) {
  uint8_t raw_key[32];
  memset(raw_key, 0x42, sizeof(raw_key));
  bfc_encrypt_key_t* key = bfc_encrypt_key_create_from_key(raw_key);
  assert(key != NULL);

  // Test sizes: 1, 15, 16, 17, 255, 256, 257, 4095, 4096, 4097
  size_t test_sizes[] = {1, 15, 16, 17, 255, 256, 257, 4095, 4096, 4097};
  size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

  for (size_t i = 0; i < num_sizes; i++) {
    size_t size = test_sizes[i];

    // Create test data
    char* test_data = malloc(size);
    assert(test_data != NULL);
    memset(test_data, 0x55 + (i % 128), size);

    // Encrypt
    bfc_encrypt_result_t enc_result = bfc_encrypt_data(key, test_data, size, NULL, 0);
    assert(enc_result.error == BFC_OK);
    assert(enc_result.encrypted_size == size + 16);

    // Decrypt
    bfc_decrypt_result_t dec_result =
        bfc_decrypt_data(key, enc_result.data, enc_result.encrypted_size, NULL, 0, size);
    assert(dec_result.error == BFC_OK);
    assert(dec_result.decrypted_size == size);
    assert(memcmp(dec_result.data, test_data, size) == 0);

    free(test_data);
    free(enc_result.data);
    free(dec_result.data);
  }

  bfc_encrypt_key_destroy(key);
  return 0;
}

// Test authenticated encryption failure cases
static int test_authentication_failures(void) {
  uint8_t raw_key[32];
  memset(raw_key, 0x33, sizeof(raw_key));
  bfc_encrypt_key_t* key = bfc_encrypt_key_create_from_key(raw_key);
  assert(key != NULL);

  const char* plaintext = "Authentication test data";
  const char* associated = "important=metadata";
  size_t data_len = strlen(plaintext);
  size_t ad_len = strlen(associated);

  // Encrypt with associated data
  bfc_encrypt_result_t enc_result = bfc_encrypt_data(key, plaintext, data_len, associated, ad_len);
  assert(enc_result.error == BFC_OK);

  // Test 1: Corrupt the encrypted data
  uint8_t* corrupted = malloc(enc_result.encrypted_size);
  memcpy(corrupted, enc_result.data, enc_result.encrypted_size);
  corrupted[5] ^= 0x01; // Flip one bit

  bfc_decrypt_result_t dec_result =
      bfc_decrypt_data(key, corrupted, enc_result.encrypted_size, associated, ad_len, data_len);
  assert(dec_result.error != BFC_OK); // Should fail authentication
  assert(dec_result.data == NULL);
  free(corrupted);

  // Test 2: Wrong associated data
  const char* wrong_ad = "wrong=metadata";
  dec_result = bfc_decrypt_data(key, enc_result.data, enc_result.encrypted_size, wrong_ad,
                                strlen(wrong_ad), data_len);
  assert(dec_result.error != BFC_OK); // Should fail authentication
  assert(dec_result.data == NULL);

  // Test 3: Truncated ciphertext
  if (enc_result.encrypted_size > 8) {
    dec_result = bfc_decrypt_data(key, enc_result.data, enc_result.encrypted_size - 8, associated,
                                  ad_len, data_len);
    assert(dec_result.error != BFC_OK); // Should fail
    assert(dec_result.data == NULL);
  }

  free(enc_result.data);
  bfc_encrypt_key_destroy(key);
  return 0;
}

// Test key management functions
static int test_key_management(void) {
  // Test key creation from bytes
  uint8_t test_key_bytes[32];
  for (int i = 0; i < 32; i++) {
    test_key_bytes[i] = (uint8_t) (i * 7);
  }

  bfc_encrypt_key_t* key1 = bfc_encrypt_key_create_from_key(test_key_bytes);
  assert(key1 != NULL);
  assert(memcmp(bfc_encrypt_key_get_data(key1), test_key_bytes, 32) == 0);

  // Test key validation
  assert(bfc_encrypt_validate_key(test_key_bytes) == BFC_OK);
  assert(bfc_encrypt_validate_key(NULL) == BFC_E_INVAL);

  // Test key comparison
  bfc_encrypt_key_t* key2 = bfc_encrypt_key_create_from_key(test_key_bytes);
  assert(key2 != NULL);
  assert(memcmp(bfc_encrypt_key_get_data(key1), bfc_encrypt_key_get_data(key2), 32) == 0);

  // Test key clearing
  bfc_encrypt_key_destroy(key1);
  bfc_encrypt_key_destroy(key2);

  return 0;
}

// Test error conditions and edge cases
static int test_encryption_error_conditions(void) {
  bfc_encrypt_key_t* key = NULL;
  uint8_t test_key[32];
  memset(test_key, 0x44, sizeof(test_key));
  key = bfc_encrypt_key_create_from_key(test_key);
  assert(key != NULL);

  const char* data = "test";
  size_t data_len = 4;

  // Test encryption with invalid parameters
  bfc_encrypt_result_t enc_result = bfc_encrypt_data(NULL, data, data_len, NULL, 0);
  assert(enc_result.error == BFC_E_INVAL);

  enc_result = bfc_encrypt_data(key, NULL, data_len, NULL, 0);
  assert(enc_result.error == BFC_E_INVAL);

  enc_result = bfc_encrypt_data(key, data, 0, NULL, 0);
  assert(enc_result.error == BFC_E_INVAL);

  // Test decryption with invalid parameters
  bfc_decrypt_result_t dec_result = bfc_decrypt_data(NULL, data, data_len, NULL, 0, data_len);
  assert(dec_result.error == BFC_E_INVAL);

  dec_result = bfc_decrypt_data(key, NULL, data_len, NULL, 0, data_len);
  assert(dec_result.error == BFC_E_INVAL);

  dec_result = bfc_decrypt_data(key, data, 0, NULL, 0, data_len);
  assert(dec_result.error == BFC_E_INVAL);

  // Test with invalid expected size
  uint8_t dummy_cipher[32];
  memset(dummy_cipher, 0, sizeof(dummy_cipher));
  dec_result = bfc_decrypt_data(key, dummy_cipher, sizeof(dummy_cipher), NULL, 0, 0);
  assert(dec_result.error == BFC_E_INVAL);

  bfc_encrypt_key_destroy(key);
  return 0;
}

int test_encrypt_integration(void) {
  int result = 0;

  result += test_encryption_context_lifecycle();
  result += test_key_derivation_edge_cases();
  result += test_large_data_encryption();
  result += test_encryption_data_sizes();
  result += test_authentication_failures();
  result += test_key_management();
  result += test_encryption_error_conditions();

  return result;
}

#else
// When libsodium is not available, just return success
int test_encrypt_integration(void) { return 0; }
#endif