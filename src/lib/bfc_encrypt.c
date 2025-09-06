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
#include "bfc.h"
#include <stdlib.h>
#include <string.h>

#ifdef BFC_WITH_SODIUM
#include <sodium.h>
#endif

// Streaming encryption context
struct bfc_encrypt_ctx {
  bfc_encrypt_key_t key;
  uint8_t nonce[BFC_ENC_NONCE_SIZE];
  uint8_t* associated_data;
  size_t associated_len;
  int initialized;
  // Note: ChaCha20-Poly1305 doesn't have streaming state in libsodium
  // We use the stateless AEAD interface instead
};

int bfc_encrypt_is_supported(uint8_t enc_type) {
  switch (enc_type) {
  case BFC_ENC_NONE:
    return 1;
#ifdef BFC_WITH_SODIUM
  case BFC_ENC_CHACHA20_POLY1305:
    return 1;
#endif
  default:
    return 0;
  }
}

#ifdef BFC_WITH_SODIUM
static int ensure_sodium_init(void) {
  static int initialized = 0;
  if (!initialized) {
    if (sodium_init() < 0) {
      return BFC_E_IO;
    }
    initialized = 1;
  }
  return BFC_OK;
}
#endif

int bfc_encrypt_key_from_password(const char* password, size_t password_len,
                                  const uint8_t salt[BFC_ENC_SALT_SIZE], bfc_encrypt_key_t* key) {
  if (!password || !key) {
    return BFC_E_INVAL;
  }

#ifndef BFC_WITH_SODIUM
  (void) password_len;
  (void) salt;
  return BFC_E_INVAL; // Encryption not supported
#else
  int result = ensure_sodium_init();
  if (result != BFC_OK) {
    return result;
  }

  // Clear key structure
  memset(key, 0, sizeof(*key));

  // Generate salt if not provided
  if (salt) {
    memcpy(key->salt, salt, BFC_ENC_SALT_SIZE);
  } else {
    randombytes_buf(key->salt, BFC_ENC_SALT_SIZE);
  }

  // Derive key using Argon2id
  if (crypto_pwhash(key->key, BFC_ENC_KEY_SIZE, password, password_len, key->salt,
                    BFC_KDF_ITERATIONS, BFC_KDF_MEMORY_KB * 1024,
                    crypto_pwhash_argon2id_ALG_ARGON2ID13) != 0) {
    bfc_encrypt_key_clear(key);
    return BFC_E_IO;
  }

  key->enc_type = BFC_ENC_CHACHA20_POLY1305;
  key->kdf_type = BFC_KDF_ARGON2ID;
  key->has_password = 1;

  return BFC_OK;
#endif
}

int bfc_encrypt_key_from_bytes(const uint8_t raw_key[BFC_ENC_KEY_SIZE], bfc_encrypt_key_t* key) {
  if (!raw_key || !key) {
    return BFC_E_INVAL;
  }

#ifndef BFC_WITH_SODIUM
  return BFC_E_INVAL; // Encryption not supported
#else
  int result = ensure_sodium_init();
  if (result != BFC_OK) {
    return result;
  }

  // Clear and set key structure
  memset(key, 0, sizeof(*key));
  memcpy(key->key, raw_key, BFC_ENC_KEY_SIZE);

  key->enc_type = BFC_ENC_CHACHA20_POLY1305;
  key->kdf_type = BFC_KDF_NONE;
  key->has_password = 0;

  return BFC_OK;
#endif
}

int bfc_encrypt_generate_salt(uint8_t salt[BFC_ENC_SALT_SIZE]) {
  if (!salt) {
    return BFC_E_INVAL;
  }

#ifndef BFC_WITH_SODIUM
  return BFC_E_INVAL; // Encryption not supported
#else
  int result = ensure_sodium_init();
  if (result != BFC_OK) {
    return result;
  }

  randombytes_buf(salt, BFC_ENC_SALT_SIZE);
  return BFC_OK;
#endif
}

bfc_encrypt_result_t bfc_encrypt_data(const bfc_encrypt_key_t* key, const void* plaintext,
                                      size_t plaintext_len, const void* associated_data,
                                      size_t associated_len) {
  bfc_encrypt_result_t result = {0};

  if (!key || !plaintext) {
    result.error = BFC_E_INVAL;
    return result;
  }

#ifndef BFC_WITH_SODIUM
  (void) plaintext;
  (void) plaintext_len;
  (void) associated_data;
  (void) associated_len;
  result.error = BFC_E_INVAL; // Encryption not supported
  return result;
#else
  int init_result = ensure_sodium_init();
  if (init_result != BFC_OK) {
    result.error = init_result;
    return result;
  }

  if (key->enc_type != BFC_ENC_CHACHA20_POLY1305) {
    result.error = BFC_E_INVAL;
    return result;
  }

  // Calculate output size (plaintext + tag)
  size_t ciphertext_len = plaintext_len + BFC_ENC_TAG_SIZE;
  result.encrypted_size = ciphertext_len + BFC_ENC_NONCE_SIZE;
  result.original_size = plaintext_len;

  // Allocate output buffer (nonce + ciphertext + tag)
  result.data = malloc(result.encrypted_size);
  if (!result.data) {
    result.error = BFC_E_IO;
    return result;
  }

  uint8_t* output = (uint8_t*) result.data;

  // Generate random nonce
  randombytes_buf(result.nonce, BFC_ENC_NONCE_SIZE);
  memcpy(output, result.nonce, BFC_ENC_NONCE_SIZE);

  // Encrypt data
  unsigned long long ciphertext_len_actual;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          output + BFC_ENC_NONCE_SIZE, &ciphertext_len_actual, (const unsigned char*) plaintext,
          plaintext_len, (const unsigned char*) associated_data, associated_len, NULL, result.nonce,
          key->key) != 0) {
    free(result.data);
    result.data = NULL;
    result.error = BFC_E_IO;
    return result;
  }

  if (ciphertext_len_actual != ciphertext_len) {
    free(result.data);
    result.data = NULL;
    result.error = BFC_E_IO;
    return result;
  }

  result.error = BFC_OK;
  return result;
#endif
}

bfc_decrypt_result_t bfc_decrypt_data(const bfc_encrypt_key_t* key, const void* ciphertext,
                                      size_t ciphertext_len, const void* associated_data,
                                      size_t associated_len, size_t expected_size) {
  bfc_decrypt_result_t result = {0};

  if (!key || !ciphertext) {
    result.error = BFC_E_INVAL;
    return result;
  }

#ifndef BFC_WITH_SODIUM
  (void) ciphertext;
  (void) ciphertext_len;
  (void) associated_data;
  (void) associated_len;
  (void) expected_size;
  result.error = BFC_E_INVAL; // Encryption not supported
  return result;
#else
  int init_result = ensure_sodium_init();
  if (init_result != BFC_OK) {
    result.error = init_result;
    return result;
  }

  if (key->enc_type != BFC_ENC_CHACHA20_POLY1305) {
    result.error = BFC_E_INVAL;
    return result;
  }

  // Validate input size
  if (ciphertext_len < BFC_ENC_NONCE_SIZE + BFC_ENC_TAG_SIZE) {
    result.error = BFC_E_INVAL;
    return result;
  }

  const uint8_t* input = (const uint8_t*) ciphertext;
  const uint8_t* nonce = input;
  const uint8_t* encrypted_data = input + BFC_ENC_NONCE_SIZE;
  size_t encrypted_data_len = ciphertext_len - BFC_ENC_NONCE_SIZE;

  // Allocate output buffer
  result.decrypted_size = encrypted_data_len - BFC_ENC_TAG_SIZE;

  // Validate expected size if provided
  if (expected_size > 0 && result.decrypted_size != expected_size) {
    result.error = BFC_E_INVAL;
    return result;
  }

  result.data = malloc(result.decrypted_size);
  if (!result.data) {
    result.error = BFC_E_IO;
    return result;
  }

  // Decrypt and authenticate
  unsigned long long decrypted_len_actual;
  if (crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char*) result.data, &decrypted_len_actual,
                                                NULL, encrypted_data, encrypted_data_len,
                                                (const unsigned char*) associated_data,
                                                associated_len, nonce, key->key) != 0) {
    free(result.data);
    result.data = NULL;
    result.error = BFC_E_CRC; // Authentication failed
    return result;
  }

  if (decrypted_len_actual != result.decrypted_size) {
    free(result.data);
    result.data = NULL;
    result.error = BFC_E_IO;
    return result;
  }

  result.error = BFC_OK;
  return result;
#endif
}

bfc_encrypt_ctx_t* bfc_encrypt_ctx_create(const bfc_encrypt_key_t* key, const void* associated_data,
                                          size_t associated_len) {
  if (!key) {
    return NULL;
  }

#ifndef BFC_WITH_SODIUM
  (void) associated_data;
  (void) associated_len;
  return NULL; // Encryption not supported
#else
  if (ensure_sodium_init() != BFC_OK) {
    return NULL;
  }

  bfc_encrypt_ctx_t* ctx = calloc(1, sizeof(*ctx));
  if (!ctx) {
    return NULL;
  }

  // Copy key
  memcpy(&ctx->key, key, sizeof(*key));

  // Copy associated data if provided
  if (associated_data && associated_len > 0) {
    ctx->associated_data = malloc(associated_len);
    if (!ctx->associated_data) {
      free(ctx);
      return NULL;
    }
    memcpy(ctx->associated_data, associated_data, associated_len);
    ctx->associated_len = associated_len;
  }

  // Generate nonce
  randombytes_buf(ctx->nonce, BFC_ENC_NONCE_SIZE);

  ctx->initialized = 0;
  return ctx;
#endif
}

int bfc_encrypt_ctx_process(bfc_encrypt_ctx_t* ctx, const void* input, size_t input_size,
                            void* output, size_t output_size, size_t* bytes_consumed,
                            size_t* bytes_produced, int finish) {
  if (!ctx || !bytes_consumed || !bytes_produced) {
    return BFC_E_INVAL;
  }

  *bytes_consumed = 0;
  *bytes_produced = 0;

#ifndef BFC_WITH_SODIUM
  (void) input;
  (void) input_size;
  (void) output;
  (void) output_size;
  (void) finish;
  return BFC_E_INVAL; // Encryption not supported
#else
  // For now, implement simple non-streaming version
  // In a full implementation, we would use the streaming AEAD interface
  if (!ctx->initialized) {
    // First call - write nonce to output
    if (output_size < BFC_ENC_NONCE_SIZE) {
      return BFC_E_INVAL;
    }
    memcpy(output, ctx->nonce, BFC_ENC_NONCE_SIZE);
    *bytes_produced = BFC_ENC_NONCE_SIZE;
    ctx->initialized = 1;
    return BFC_OK;
  }

  // For streaming, we'd need to implement proper ChaCha20-Poly1305 streaming
  // This is a simplified version for now
  if (!input || input_size == 0 || !finish) {
    return BFC_E_INVAL; // Simplified implementation requires full data
  }

  size_t required_output = input_size + BFC_ENC_TAG_SIZE;
  if (output_size < required_output) {
    return BFC_E_INVAL;
  }

  unsigned long long ciphertext_len;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          (unsigned char*) output, &ciphertext_len, (const unsigned char*) input, input_size,
          (const unsigned char*) ctx->associated_data, ctx->associated_len, NULL, ctx->nonce,
          ctx->key.key) != 0) {
    return BFC_E_IO;
  }

  *bytes_consumed = input_size;
  *bytes_produced = ciphertext_len;
  return BFC_OK;
#endif
}

int bfc_encrypt_ctx_get_nonce(bfc_encrypt_ctx_t* ctx, uint8_t nonce[BFC_ENC_NONCE_SIZE]) {
  if (!ctx || !nonce) {
    return BFC_E_INVAL;
  }

  memcpy(nonce, ctx->nonce, BFC_ENC_NONCE_SIZE);
  return BFC_OK;
}

void bfc_encrypt_ctx_destroy(bfc_encrypt_ctx_t* ctx) {
  if (!ctx) {
    return;
  }

  // Clear sensitive data
  bfc_encrypt_key_clear(&ctx->key);

#ifdef BFC_WITH_SODIUM
  sodium_memzero(ctx->nonce, BFC_ENC_NONCE_SIZE);
  if (ctx->associated_data) {
    sodium_memzero(ctx->associated_data, ctx->associated_len);
    free(ctx->associated_data);
  }
  // No state to clear for stateless ChaCha20-Poly1305
#else
  // Fallback without libsodium
  volatile uint8_t* nonce_p = (volatile uint8_t*) ctx->nonce;
  for (size_t i = 0; i < BFC_ENC_NONCE_SIZE; i++) {
    nonce_p[i] = 0;
  }
  if (ctx->associated_data) {
    volatile uint8_t* data_p = (volatile uint8_t*) ctx->associated_data;
    for (size_t i = 0; i < ctx->associated_len; i++) {
      data_p[i] = 0;
    }
    free(ctx->associated_data);
  }
#endif

  free(ctx);
}

const char* bfc_encrypt_name(uint8_t enc_type) {
  switch (enc_type) {
  case BFC_ENC_NONE:
    return "none";
  case BFC_ENC_CHACHA20_POLY1305:
    return "ChaCha20-Poly1305";
  default:
    return "unknown";
  }
}

size_t bfc_encrypt_overhead(uint8_t enc_type) {
  switch (enc_type) {
  case BFC_ENC_NONE:
    return 0;
  case BFC_ENC_CHACHA20_POLY1305:
    return BFC_ENC_NONCE_SIZE + BFC_ENC_TAG_SIZE; // 12 + 16 = 28 bytes
  default:
    return 0;
  }
}

void bfc_encrypt_key_clear(bfc_encrypt_key_t* key) {
  if (!key) {
    return;
  }

#ifdef BFC_WITH_SODIUM
  sodium_memzero(key, sizeof(*key));
#else
  // Fallback for when libsodium is not available
  volatile uint8_t* p = (volatile uint8_t*) key;
  for (size_t i = 0; i < sizeof(*key); i++) {
    p[i] = 0;
  }
#endif
}