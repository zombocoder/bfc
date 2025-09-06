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

#pragma once

#include "bfc_format.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encryption algorithms
#define BFC_ENC_NONE 0
#define BFC_ENC_CHACHA20_POLY1305 1

// Key derivation algorithms
#define BFC_KDF_NONE 0
#define BFC_KDF_ARGON2ID 1

// Encryption feature flags
#define BFC_FEATURE_AEAD (1ULL << 1)

// Key sizes
#define BFC_ENC_KEY_SIZE 32   // 256 bits
#define BFC_ENC_NONCE_SIZE 12 // 96 bits for ChaCha20-Poly1305
#define BFC_ENC_TAG_SIZE 16   // 128 bits authentication tag
#define BFC_ENC_SALT_SIZE 32  // 256 bits for Argon2id

// Argon2id parameters
#define BFC_KDF_MEMORY_KB 65536 // 64 MB
#define BFC_KDF_ITERATIONS 3    // 3 iterations
#define BFC_KDF_PARALLELISM 1   // Single-threaded

// Encryption context for streaming operations
typedef struct bfc_encrypt_ctx bfc_encrypt_ctx_t;

// Encryption key material
typedef struct {
  uint8_t key[BFC_ENC_KEY_SIZE];   // Derived or provided encryption key
  uint8_t salt[BFC_ENC_SALT_SIZE]; // Salt for key derivation (if using KDF)
  uint8_t enc_type;                // Encryption algorithm
  uint8_t kdf_type;                // Key derivation function
  int has_password;                // 1 if using password-based encryption
} bfc_encrypt_key_t;

// Encryption result structure
typedef struct {
  void* data;                        // Encrypted data (caller must free)
  size_t encrypted_size;             // Size including nonce + tag
  size_t original_size;              // Original plaintext size
  uint8_t nonce[BFC_ENC_NONCE_SIZE]; // Nonce used for encryption
  int error;                         // BFC_OK on success
} bfc_encrypt_result_t;

// Decryption result structure
typedef struct {
  void* data;            // Decrypted data (caller must free)
  size_t decrypted_size; // Size of decrypted data
  int error;             // BFC_OK on success
} bfc_decrypt_result_t;

/**
 * Check if encryption algorithm is supported
 * @param enc_type Encryption type (BFC_ENC_*)
 * @return 1 if supported, 0 if not
 */
int bfc_encrypt_is_supported(uint8_t enc_type);

/**
 * Initialize encryption key from password
 * @param password Password string (UTF-8)
 * @param password_len Password length in bytes
 * @param salt Optional salt (if NULL, will be generated)
 * @param key Output key structure
 * @return BFC_OK on success
 */
int bfc_encrypt_key_from_password(const char* password, size_t password_len,
                                  const uint8_t salt[BFC_ENC_SALT_SIZE], bfc_encrypt_key_t* key);

/**
 * Initialize encryption key from raw key material
 * @param raw_key 32-byte key material
 * @param key Output key structure
 * @return BFC_OK on success
 */
int bfc_encrypt_key_from_bytes(const uint8_t raw_key[BFC_ENC_KEY_SIZE], bfc_encrypt_key_t* key);

/**
 * Generate random salt for key derivation
 * @param salt Output buffer for 32-byte salt
 * @return BFC_OK on success
 */
int bfc_encrypt_generate_salt(uint8_t salt[BFC_ENC_SALT_SIZE]);

/**
 * Encrypt data using AEAD
 * @param key Encryption key
 * @param plaintext Input data
 * @param plaintext_len Input data length
 * @param associated_data Additional authenticated data (can be NULL)
 * @param associated_len Length of associated data
 * @return Encryption result (caller must free result.data)
 */
bfc_encrypt_result_t bfc_encrypt_data(const bfc_encrypt_key_t* key, const void* plaintext,
                                      size_t plaintext_len, const void* associated_data,
                                      size_t associated_len);

/**
 * Decrypt data using AEAD
 * @param key Encryption key
 * @param ciphertext Encrypted data (includes nonce + tag)
 * @param ciphertext_len Encrypted data length
 * @param associated_data Additional authenticated data (must match encryption)
 * @param associated_len Length of associated data
 * @param expected_size Expected plaintext size (for validation)
 * @return Decryption result (caller must free result.data)
 */
bfc_decrypt_result_t bfc_decrypt_data(const bfc_encrypt_key_t* key, const void* ciphertext,
                                      size_t ciphertext_len, const void* associated_data,
                                      size_t associated_len, size_t expected_size);

/**
 * Create streaming encryption context
 * @param key Encryption key
 * @param associated_data Additional authenticated data (can be NULL)
 * @param associated_len Length of associated data
 * @return Context pointer or NULL on error
 */
bfc_encrypt_ctx_t* bfc_encrypt_ctx_create(const bfc_encrypt_key_t* key, const void* associated_data,
                                          size_t associated_len);

/**
 * Process data through streaming encryption
 * @param ctx Encryption context
 * @param input Input data
 * @param input_size Input size
 * @param output Output buffer
 * @param output_size Output buffer size
 * @param bytes_consumed Bytes consumed from input
 * @param bytes_produced Bytes written to output
 * @param finish 1 if this is the final chunk, 0 otherwise
 * @return BFC_OK on success
 */
int bfc_encrypt_ctx_process(bfc_encrypt_ctx_t* ctx, const void* input, size_t input_size,
                            void* output, size_t output_size, size_t* bytes_consumed,
                            size_t* bytes_produced, int finish);

/**
 * Get nonce from encryption context (after first call to process)
 * @param ctx Encryption context
 * @param nonce Output buffer for nonce
 * @return BFC_OK on success
 */
int bfc_encrypt_ctx_get_nonce(bfc_encrypt_ctx_t* ctx, uint8_t nonce[BFC_ENC_NONCE_SIZE]);

/**
 * Destroy encryption context
 * @param ctx Context to destroy
 */
void bfc_encrypt_ctx_destroy(bfc_encrypt_ctx_t* ctx);

/**
 * Get encryption algorithm name
 * @param enc_type Encryption type
 * @return Algorithm name or "unknown"
 */
const char* bfc_encrypt_name(uint8_t enc_type);

/**
 * Calculate overhead of encryption (nonce + tag)
 * @param enc_type Encryption type
 * @return Number of additional bytes added by encryption
 */
size_t bfc_encrypt_overhead(uint8_t enc_type);

/**
 * Clear sensitive key material from memory
 * @param key Key structure to clear
 */
void bfc_encrypt_key_clear(bfc_encrypt_key_t* key);

#ifdef __cplusplus
}
#endif