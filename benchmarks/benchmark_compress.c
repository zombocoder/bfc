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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Generate compressible content (repeated patterns)
static void generate_compressible_content(char *buffer, size_t size) {
    const char *patterns[] = {
        "This is a sample text with repeating patterns that compress well. ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
        "The quick brown fox jumps over the lazy dog. ",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    };
    const int num_patterns = sizeof(patterns) / sizeof(patterns[0]);
    
    size_t offset = 0;
    int pattern_idx = 0;
    
    while (offset < size) {
        const char *pattern = patterns[pattern_idx];
        size_t pattern_len = strlen(pattern);
        size_t copy_len = (size - offset < pattern_len) ? size - offset : pattern_len;
        
        memcpy(buffer + offset, pattern, copy_len);
        offset += copy_len;
        pattern_idx = (pattern_idx + 1) % num_patterns;
    }
}

// Generate random content (low compressibility)  
static void generate_random_content(char *buffer, size_t size) {
    srand(42); // Fixed seed for reproducible results
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (char)(rand() % 256);
    }
}

// Benchmark compression with different content types and levels
static int benchmark_compression_levels(void) {
    const char *container_base = "/tmp/benchmark_compress";
    const int num_files = 100;
    const size_t file_size = 64 * 1024; // 64KB files
    
    printf("\n=== Compression Level Benchmark ===\n");
    printf("Files: %d x %zu KB each\n\n", num_files, file_size / 1024);
    
    // Test different compression levels (if ZSTD available)
    int levels[] = {0, 1, 3, 6, 9, 12}; // 0 = no compression
    int num_levels = sizeof(levels) / sizeof(levels[0]);
    
#ifndef BFC_WITH_ZSTD
    printf("ZSTD not available - testing only no compression\n");
    levels[0] = 0;
    num_levels = 1;
#endif
    
    // Test with different content types
    struct {
        const char *name;
        void (*generator)(char *, size_t);
    } content_types[] = {
        {"Compressible Text", generate_compressible_content},
        {"Random Data", generate_random_content}
    };
    int num_content_types = sizeof(content_types) / sizeof(content_types[0]);
    
    char *content = malloc(file_size);
    if (!content) {
        printf("Failed to allocate content buffer\n");
        return 1;
    }
    
    printf("%-20s %-10s %-12s %-12s %-12s %-10s %-10s\n", 
           "Content Type", "Level", "Write MB/s", "Container", "Orig Size", "Ratio", "Space Saved");
    printf("%-20s %-10s %-12s %-12s %-12s %-10s %-10s\n", 
           "--------------------", "----------", "------------", "------------", "------------", "----------", "----------");
    
    for (int ct = 0; ct < num_content_types; ct++) {
        // Generate content for this type
        content_types[ct].generator(content, file_size);
        
        for (int lv = 0; lv < num_levels; lv++) {
            char container[256];
            snprintf(container, sizeof(container), "%s_%s_l%d.bfc", 
                    container_base, 
                    (ct == 0) ? "text" : "random", 
                    levels[lv]);
            
            unlink(container);
            
            bfc_t *writer = NULL;
            int result = bfc_create(container, 4096, 0, &writer);
            if (result != BFC_OK) continue;
            
            // Set compression
            if (levels[lv] == 0) {
                bfc_set_compression(writer, BFC_COMP_NONE, 0);
            } else {
#ifdef BFC_WITH_ZSTD
                bfc_set_compression(writer, BFC_COMP_ZSTD, levels[lv]);
#endif
            }
            
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            
            // Add files
            uint64_t total_original = 0;
            for (int i = 0; i < num_files; i++) {
                char path[64];
                snprintf(path, sizeof(path), "file_%04d.dat", i);
                
                FILE *temp = tmpfile();
                if (!temp) break;
                
                fwrite(content, 1, file_size, temp);
                rewind(temp);
                
                result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
                fclose(temp);
                
                if (result == BFC_OK) {
                    total_original += file_size;
                }
            }
            
            result = bfc_finish(writer);
            bfc_close(writer);
            
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            if (result != BFC_OK) {
                printf("%-20s L%-9d FAILED\n", content_types[ct].name, levels[lv]);
                continue;
            }
            
            // Get container size
            struct stat st;
            uint64_t container_size = 0;
            if (stat(container, &st) == 0) {
                container_size = st.st_size;
            }
            
            // Calculate metrics
            double elapsed = benchmark_time_diff(&start, &end);
            double write_mbps = benchmark_throughput_mbps(total_original, elapsed);
            double compression_ratio = (total_original > 0) ? 
                (double)container_size / total_original * 100.0 : 100.0;
            double space_saved = 100.0 - compression_ratio;
            
            char container_size_str[32], orig_size_str[32];
            benchmark_format_bytes(container_size, container_size_str, sizeof(container_size_str));
            benchmark_format_bytes(total_original, orig_size_str, sizeof(orig_size_str));
            
            printf("%-20s L%-9d %-12.1f %-12s %-12s %-9.1f%% %-9.1f%%\n",
                   content_types[ct].name,
                   levels[lv],
                   write_mbps,
                   container_size_str,
                   orig_size_str,
                   compression_ratio,
                   (space_saved > 0) ? space_saved : 0.0);
            
            unlink(container);
        }
        printf("\n");
    }
    
    free(content);
    return 0;
}

// Benchmark compression vs no compression for different file sizes
static int benchmark_compression_scaling(void) {
    const char *container_base = "/tmp/benchmark_scale";
    
    printf("\n=== Compression Scaling Benchmark ===\n");
    
    // Test different file sizes
    struct {
        int count;
        size_t size;
        const char *desc;
    } test_cases[] = {
        {10000, 1024, "Small files (1KB x 10k)"},
        {1000, 10 * 1024, "Medium files (10KB x 1k)"}, 
        {100, 100 * 1024, "Large files (100KB x 100)"},
        {10, 1024 * 1024, "Very large files (1MB x 10)"}
    };
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    char *content = malloc(1024 * 1024); // 1MB buffer
    if (!content) {
        printf("Failed to allocate content buffer\n");
        return 1;
    }
    
    // Generate compressible content
    generate_compressible_content(content, 1024 * 1024);
    
    printf("%-25s %-10s %-12s %-12s %-10s %-12s\n", 
           "Test Case", "Compress", "Write MB/s", "Files/sec", "Ratio", "Space Saved");
    printf("%-25s %-10s %-12s %-12s %-10s %-12s\n", 
           "-------------------------", "----------", "------------", "------------", "----------", "------------");
    
    for (int tc = 0; tc < num_cases; tc++) {
        const char *compression_modes[] = {"None", "ZSTD"};
        int num_modes = 1;
#ifdef BFC_WITH_ZSTD
        num_modes = 2;
#endif
        
        for (int mode = 0; mode < num_modes; mode++) {
            char container[256];
            snprintf(container, sizeof(container), "%s_s%zu_c%d_m%d.bfc", 
                    container_base, test_cases[tc].size, test_cases[tc].count, mode);
            
            unlink(container);
            
            bfc_t *writer = NULL;
            int result = bfc_create(container, 4096, 0, &writer);
            if (result != BFC_OK) continue;
            
            // Set compression mode
            if (mode == 0) {
                bfc_set_compression(writer, BFC_COMP_NONE, 0);
            } else {
#ifdef BFC_WITH_ZSTD
                bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
#endif
            }
            
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            
            // Add files
            uint64_t total_bytes = 0;
            for (int i = 0; i < test_cases[tc].count; i++) {
                char path[64];
                snprintf(path, sizeof(path), "file_%06d.dat", i);
                
                FILE *temp = tmpfile();
                if (!temp) break;
                
                fwrite(content, 1, test_cases[tc].size, temp);
                rewind(temp);
                
                result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
                fclose(temp);
                
                if (result == BFC_OK) {
                    total_bytes += test_cases[tc].size;
                }
            }
            
            result = bfc_finish(writer);
            bfc_close(writer);
            
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            if (result != BFC_OK) {
                printf("%-25s %-10s FAILED\n", test_cases[tc].desc, compression_modes[mode]);
                continue;
            }
            
            // Get container size
            struct stat st;
            uint64_t container_size = 0;
            if (stat(container, &st) == 0) {
                container_size = st.st_size;
            }
            
            // Calculate metrics
            double elapsed = benchmark_time_diff(&start, &end);
            double write_mbps = benchmark_throughput_mbps(total_bytes, elapsed);
            double files_per_sec = benchmark_ops_per_sec(test_cases[tc].count, elapsed);
            double compression_ratio = (total_bytes > 0) ? 
                (double)container_size / total_bytes * 100.0 : 100.0;
            double space_saved = 100.0 - compression_ratio;
            
            printf("%-25s %-10s %-12.1f %-12.1f %-9.1f%% %-11.1f%%\n",
                   test_cases[tc].desc,
                   compression_modes[mode],
                   write_mbps,
                   files_per_sec,
                   compression_ratio,
                   (space_saved > 0) ? space_saved : 0.0);
            
            unlink(container);
        }
        printf("\n");
    }
    
    free(content);
    return 0;
}

// Benchmark decompression performance
static int benchmark_decompression(void) {
    const char *container = "/tmp/benchmark_decomp.bfc";
    const int num_files = 1000;
    const size_t file_size = 32 * 1024; // 32KB files
    
    printf("\n=== Decompression Benchmark ===\n");
    printf("Creating test container with %d files of %zu KB each\n", num_files, file_size / 1024);
    
    // First create a container with compressed files
    char *content = malloc(file_size);
    if (!content) {
        printf("Failed to allocate content buffer\n");
        return 1;
    }
    
    generate_compressible_content(content, file_size);
    
    unlink(container);
    
    bfc_t *writer = NULL;
    int result = bfc_create(container, 4096, 0, &writer);
    if (result != BFC_OK) {
        free(content);
        return 1;
    }
    
#ifdef BFC_WITH_ZSTD
    bfc_set_compression(writer, BFC_COMP_ZSTD, 3);
#else
    bfc_set_compression(writer, BFC_COMP_NONE, 0);
#endif
    
    // Add files to container
    for (int i = 0; i < num_files; i++) {
        char path[64];
        snprintf(path, sizeof(path), "file_%05d.dat", i);
        
        FILE *temp = tmpfile();
        if (!temp) break;
        
        fwrite(content, 1, file_size, temp);
        rewind(temp);
        
        result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
        fclose(temp);
        
        if (result != BFC_OK) {
            break;
        }
    }
    
    result = bfc_finish(writer);
    bfc_close(writer);
    
    if (result != BFC_OK) {
        printf("Failed to create test container\n");
        free(content);
        return 1;
    }
    
    // Now benchmark reading/decompression
    bfc_t *reader = NULL;
    result = bfc_open(container, &reader);
    if (result != BFC_OK) {
        printf("Failed to open test container\n");
        free(content);
        unlink(container);
        return 1;
    }
    
    printf("Running decompression benchmark...\n");
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Read all files
    char *read_buffer = malloc(file_size);
    uint64_t total_read = 0;
    int files_read = 0;
    
    for (int i = 0; i < num_files; i++) {
        char path[64];
        snprintf(path, sizeof(path), "file_%05d.dat", i);
        
        size_t bytes_read = bfc_read(reader, path, 0, read_buffer, file_size);
        
        if (bytes_read == file_size) {
            total_read += bytes_read;
            files_read++;
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    bfc_close_read(reader);
    free(read_buffer);
    
    // Calculate metrics
    double elapsed = benchmark_time_diff(&start, &end);
    double read_mbps = benchmark_throughput_mbps(total_read, elapsed);
    double files_per_sec = benchmark_ops_per_sec(files_read, elapsed);
    
    printf("Decompression Results:\n");
    printf("  Files read: %d/%d\n", files_read, num_files);
    printf("  Total data: "); 
    
    char data_str[32];
    benchmark_format_bytes(total_read, data_str, sizeof(data_str));
    printf("%s\n", data_str);
    
    printf("  Read throughput: %.1f MB/s\n", read_mbps);
    printf("  Files per second: %.1f files/s\n", files_per_sec);
    
    free(content);
    unlink(container);
    return 0;
}

int main(void) {
    printf("BFC Compression Benchmark Suite\n");
    printf("===============================\n");
    
#ifdef BFC_WITH_ZSTD
    printf("ZSTD compression: ENABLED\n");
#else
    printf("ZSTD compression: DISABLED\n");
#endif
    
    int result = 0;
    
    result += benchmark_compression_levels();
    result += benchmark_compression_scaling(); 
    result += benchmark_decompression();
    
    printf("\nBenchmark completed %s\n", result == 0 ? "successfully" : "with errors");
    return result;
}