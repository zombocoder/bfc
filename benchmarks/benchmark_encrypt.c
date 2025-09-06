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
#include <bfc.h>
#include "benchmark_common.h"
#include "bfc_encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Generate content for encryption benchmarking
static void generate_benchmark_content(char *buffer, size_t size, int pattern) {
    switch (pattern) {
    case 0: // Text-like content
        {
            const char *text = "This is sample text content for encryption benchmarking. It contains readable ASCII text with various patterns and structures that are typical in real-world documents and files. ";
            size_t text_len = strlen(text);
            for (size_t i = 0; i < size; i++) {
                buffer[i] = text[i % text_len];
            }
        }
        break;
    case 1: // Binary-like content (more random)
        srand(42); // Fixed seed for reproducible results
        for (size_t i = 0; i < size; i++) {
            buffer[i] = (char)(rand() % 256);
        }
        break;
    case 2: // Sparse content (lots of zeros)
        memset(buffer, 0, size);
        for (size_t i = 0; i < size; i += 64) {
            buffer[i] = (char)(i % 256);
        }
        break;
    }
}

// Benchmark encryption/decryption performance
static int benchmark_encryption_performance(void) {
    printf("\n=== Encryption Performance Benchmark ===\n");
    
#ifndef BFC_WITH_SODIUM
    printf("Encryption not available - BFC built without libsodium support\n");
    return 0;
#endif

    // Test different data sizes
    size_t test_sizes[] = {
        1024,           // 1 KB
        16 * 1024,      // 16 KB  
        64 * 1024,      // 64 KB
        256 * 1024,     // 256 KB
        1024 * 1024,    // 1 MB
        4 * 1024 * 1024 // 4 MB
    };
    int num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);
    
    const char *content_types[] = {"Text", "Binary", "Sparse"};
    int num_content_types = 3;
    
    printf("\n%-8s %-8s %-12s %-12s %-12s %-12s %-12s\n",
           "Content", "Size", "Encrypt MB/s", "Decrypt MB/s", "KeyDeriv ms", "Overhead", "Auth Fail");
    printf("%-8s %-8s %-12s %-12s %-12s %-12s %-12s\n",
           "--------", "--------", "------------", "------------", "------------", "------------", "------------");

    bfc_encrypt_key_t key;
    const char *password = "benchmark_password_123";
    uint8_t salt[BFC_ENC_SALT_SIZE];
    
    // Generate salt for key derivation benchmarking
    int result = bfc_encrypt_generate_salt(salt);
    if (result != BFC_OK) {
        printf("Failed to generate salt: %d\n", result);
        return 1;
    }

    for (int ct = 0; ct < num_content_types; ct++) {
        for (int sz = 0; sz < num_sizes; sz++) {
            size_t data_size = test_sizes[sz];
            char size_buf[32];
            benchmark_format_bytes(data_size, size_buf, sizeof(size_buf));
            
            // Allocate test data
            char *test_data = malloc(data_size);
            if (!test_data) {
                printf("Failed to allocate %zu bytes\n", data_size);
                continue;
            }
            
            // Generate content
            generate_benchmark_content(test_data, data_size, ct);
            
            // Benchmark key derivation (only once per content type)
            double key_deriv_time = 0.0;
            if (sz == 0) {
                struct timespec start, end;
                clock_gettime(CLOCK_MONOTONIC, &start);
                
                result = bfc_encrypt_key_from_password(password, strlen(password), salt, &key);
                
                clock_gettime(CLOCK_MONOTONIC, &end);
                key_deriv_time = benchmark_time_diff(&start, &end) * 1000.0; // Convert to ms
                
                if (result != BFC_OK) {
                    printf("Key derivation failed: %d\n", result);
                    free(test_data);
                    continue;
                }
            } else {
                // Reuse key from first iteration
                result = bfc_encrypt_key_from_password(password, strlen(password), salt, &key);
                if (result != BFC_OK) {
                    free(test_data);
                    continue;
                }
            }
            
            // Benchmark encryption
            struct timespec encrypt_start, encrypt_end;
            clock_gettime(CLOCK_MONOTONIC, &encrypt_start);
            
            bfc_encrypt_result_t encrypt_result = bfc_encrypt_data(&key, test_data, data_size, NULL, 0);
            
            clock_gettime(CLOCK_MONOTONIC, &encrypt_end);
            double encrypt_time = benchmark_time_diff(&encrypt_start, &encrypt_end);
            
            if (encrypt_result.error != BFC_OK) {
                printf("Encryption failed: %d\n", encrypt_result.error);
                free(test_data);
                continue;
            }
            
            // Calculate encryption throughput
            double encrypt_mbps = benchmark_throughput_mbps(data_size, encrypt_time);
            
            // Benchmark decryption
            struct timespec decrypt_start, decrypt_end;
            clock_gettime(CLOCK_MONOTONIC, &decrypt_start);
            
            bfc_decrypt_result_t decrypt_result = bfc_decrypt_data(&key, encrypt_result.data, 
                                                                  encrypt_result.encrypted_size, 
                                                                  NULL, 0, data_size);
            
            clock_gettime(CLOCK_MONOTONIC, &decrypt_end);
            double decrypt_time = benchmark_time_diff(&decrypt_start, &decrypt_end);
            
            if (decrypt_result.error != BFC_OK) {
                printf("Decryption failed: %d\n", decrypt_result.error);
                free(encrypt_result.data);
                free(test_data);
                continue;
            }
            
            // Calculate decryption throughput
            double decrypt_mbps = benchmark_throughput_mbps(data_size, decrypt_time);
            
            // Verify decrypted data matches original
            // int data_matches = (memcmp(test_data, decrypt_result.data, data_size) == 0) ? 1 : 0;
            
            // Calculate overhead
            size_t overhead = encrypt_result.encrypted_size - data_size;
            double overhead_pct = (overhead * 100.0) / data_size;
            
            // Test authentication failure (wrong key)
            bfc_encrypt_key_t wrong_key;
            uint8_t wrong_salt[BFC_ENC_SALT_SIZE];
            bfc_encrypt_generate_salt(wrong_salt);
            bfc_encrypt_key_from_password("wrong_password", 14, wrong_salt, &wrong_key);
            
            bfc_decrypt_result_t auth_fail_result = bfc_decrypt_data(&wrong_key, encrypt_result.data,
                                                                    encrypt_result.encrypted_size,
                                                                    NULL, 0, data_size);
            int auth_fails = (auth_fail_result.error != BFC_OK) ? 1 : 0;
            
            // Print results
            printf("%-8s %-8s %11.1f %11.1f %11.1f %10.1f%% %11s\n",
                   content_types[ct], size_buf, encrypt_mbps, decrypt_mbps,
                   (sz == 0) ? key_deriv_time : 0.0, overhead_pct,
                   auth_fails ? "PASS" : "FAIL");
            
            // Cleanup
            free(test_data);
            free(encrypt_result.data);
            free(decrypt_result.data);
            if (auth_fail_result.data) {
                free(auth_fail_result.data);
            }
            bfc_encrypt_key_clear(&wrong_key);
        }
    }
    
    bfc_encrypt_key_clear(&key);
    return 0;
}

// Benchmark container creation with encryption
static int benchmark_encrypted_containers(void) {
    printf("\n=== Encrypted Container Creation Benchmark ===\n");
    
#ifndef BFC_WITH_SODIUM
    printf("Encryption not available - BFC built without libsodium support\n");
    return 0;
#endif

    const char *container_path = "/tmp/benchmark_encrypt_container.bfc";
    const int num_files = 50;
    const size_t file_size = 32 * 1024; // 32KB files
    
    printf("Creating container with %d files (%zu KB each)\n\n", num_files, file_size / 1024);
    
    // Test different scenarios
    struct {
        const char *name;
        int use_encryption;
        int use_compression;
    } scenarios[] = {
        {"No Encryption", 0, 0},
        {"Encryption Only", 1, 0},
        {"Compression Only", 0, 1},
        {"Encrypt + Compress", 1, 1}
    };
    int num_scenarios = sizeof(scenarios) / sizeof(scenarios[0]);
    
#ifndef BFC_WITH_ZSTD
    // Skip compression scenarios if ZSTD not available
    num_scenarios = 2;
#endif
    
    printf("%-20s %-12s %-12s %-12s %-10s\n",
           "Scenario", "Write MB/s", "Read MB/s", "Container", "Ratio");
    printf("%-20s %-12s %-12s %-12s %-10s\n",
           "--------------------", "------------", "------------", "------------", "----------");
    
    // Generate test data
    char *file_content = malloc(file_size);
    if (!file_content) {
        printf("Failed to allocate file content buffer\n");
        return 1;
    }
    generate_benchmark_content(file_content, file_size, 0); // Text-like content
    
    for (int sc = 0; sc < num_scenarios; sc++) {
        unlink(container_path); // Remove previous container
        
        // Create writer
        bfc_t *writer;
        struct timespec create_start, create_end;
        clock_gettime(CLOCK_MONOTONIC, &create_start);
        
        int result = bfc_create(container_path, 4096, 0, &writer);
        if (result != BFC_OK) {
            printf("Failed to create container: %d\n", result);
            continue;
        }
        
        // Configure encryption
        if (scenarios[sc].use_encryption) {
            result = bfc_set_encryption_password(writer, "benchmark_pass", 14);
            if (result != BFC_OK) {
                printf("Failed to set encryption: %d\n", result);
                bfc_close(writer);
                continue;
            }
        }
        
        // Configure compression
        if (scenarios[sc].use_compression) {
            result = bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
            if (result != BFC_OK) {
                printf("Warning: Failed to set compression: %d\n", result);
                // Continue without compression
            }
        }
        
        // Add files
        uint64_t total_bytes = 0;
        for (int i = 0; i < num_files; i++) {
            char filename[64];
            snprintf(filename, sizeof(filename), "file_%03d.txt", i);
            
            // Create temporary file with content
            FILE *temp_file = tmpfile();
            if (!temp_file) {
                printf("Failed to create temp file\n");
                continue;
            }
            
            fwrite(file_content, 1, file_size, temp_file);
            rewind(temp_file);
            
            uint32_t crc;
            result = bfc_add_file(writer, filename, temp_file, 0644, 0, &crc);
            fclose(temp_file);
            
            if (result != BFC_OK) {
                printf("Failed to add file %s: %d\n", filename, result);
                continue;
            }
            
            total_bytes += file_size;
        }
        
        // Finalize container
        result = bfc_finish(writer);
        if (result != BFC_OK) {
            printf("Failed to finish container: %d\n", result);
            bfc_close(writer);
            continue;
        }
        
        bfc_close(writer);
        
        clock_gettime(CLOCK_MONOTONIC, &create_end);
        double create_time = benchmark_time_diff(&create_start, &create_end);
        double write_mbps = benchmark_throughput_mbps(total_bytes, create_time);
        
        // Benchmark reading
        bfc_t *reader;
        struct timespec read_start, read_end;
        clock_gettime(CLOCK_MONOTONIC, &read_start);
        
        result = bfc_open(container_path, &reader);
        if (result != BFC_OK) {
            printf("Failed to open container: %d\n", result);
            continue;
        }
        
        // Set decryption password if needed
        if (scenarios[sc].use_encryption) {
            result = bfc_set_encryption_password(reader, "benchmark_pass", 14);
            if (result != BFC_OK) {
                printf("Failed to set decryption password: %d\n", result);
                bfc_close_read(reader);
                continue;
            }
        }
        
        // Read all files
        uint64_t read_bytes = 0;
        for (int i = 0; i < num_files; i++) {
            char filename[64];
            snprintf(filename, sizeof(filename), "file_%03d.txt", i);
            
            char *read_buffer = malloc(file_size);
            if (!read_buffer) continue;
            
            size_t bytes_read = bfc_read(reader, filename, 0, read_buffer, file_size);
            if (bytes_read > 0) {
                read_bytes += bytes_read;
            }
            
            free(read_buffer);
        }
        
        bfc_close_read(reader);
        
        clock_gettime(CLOCK_MONOTONIC, &read_end);
        double read_time = benchmark_time_diff(&read_start, &read_end);
        double read_mbps = benchmark_throughput_mbps(read_bytes, read_time);
        
        // Get container size
        struct stat st;
        char container_size_buf[32] = "N/A";
        double size_ratio = 1.0;
        if (stat(container_path, &st) == 0) {
            benchmark_format_bytes(st.st_size, container_size_buf, sizeof(container_size_buf));
            size_ratio = (double)st.st_size / total_bytes;
        }
        
        printf("%-20s %11.1f %11.1f %-12s %9.1f%%\n",
               scenarios[sc].name, write_mbps, read_mbps, container_size_buf, size_ratio * 100.0);
    }
    
    free(file_content);
    unlink(container_path);
    return 0;
}

int main(void) {
    printf("BFC Encryption Performance Benchmarks\n");
    printf("=====================================\n");
    
    int result = benchmark_encryption_performance();
    if (result != 0) {
        return result;
    }
    
    result = benchmark_encrypted_containers();
    if (result != 0) {
        return result;
    }
    
    printf("\nBenchmark completed successfully.\n");
    return 0;
}