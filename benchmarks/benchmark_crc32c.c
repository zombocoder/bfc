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
#include "bfc_crc32c.h"
#include "benchmark_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int benchmark_crc32c_small_chunks(void)
{
    const size_t chunk_size = 64; // 64 bytes
    const int iterations = 1000000;

    printf("CRC32C Benchmark: Small chunks (%zu bytes, %d iterations)\n",
           chunk_size, iterations);

    char *data = malloc(chunk_size);
    if (!data)
        return 1;

    // Fill with pattern data
    for (size_t i = 0; i < chunk_size; i++)
    {
        data[i] = (char)(i % 256);
    }

    bfc_crc32c_ctx_t ctx;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    uint32_t final_crc = 0;
    for (int i = 0; i < iterations; i++)
    {
        bfc_crc32c_reset(&ctx);
        bfc_crc32c_update(&ctx, data, chunk_size);
        final_crc = bfc_crc32c_final(&ctx);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(data);

    double elapsed = benchmark_time_diff(&start, &end);
    uint64_t total_bytes = (uint64_t)iterations * chunk_size;

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Final CRC32C: 0x%08x\n", final_crc);
    printf("  Throughput: %.2f MB/s\n", benchmark_throughput_mbps(total_bytes, elapsed));
    printf("  Operations/sec: %.0f\n", benchmark_ops_per_sec(iterations, elapsed));

    return 0;
}

static int benchmark_crc32c_large_chunks(void)
{
    const size_t chunk_size = 1024 * 1024; // 1MB
    const int iterations = 1000;

    printf("\nCRC32C Benchmark: Large chunks (%zu MB, %d iterations)\n",
           chunk_size / (1024 * 1024), iterations);

    char *data = malloc(chunk_size);
    if (!data)
        return 1;

    // Fill with pattern data
    for (size_t i = 0; i < chunk_size; i++)
    {
        data[i] = (char)(i % 256);
    }

    bfc_crc32c_ctx_t ctx;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    uint32_t final_crc = 0;
    for (int i = 0; i < iterations; i++)
    {
        bfc_crc32c_reset(&ctx);
        bfc_crc32c_update(&ctx, data, chunk_size);
        final_crc = bfc_crc32c_final(&ctx);

        if (i % 100 == 0)
        {
            printf("  Progress: %d/%d iterations\n", i, iterations);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(data);

    double elapsed = benchmark_time_diff(&start, &end);
    uint64_t total_bytes = (uint64_t)iterations * chunk_size;

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Final CRC32C: 0x%08x\n", final_crc);
    printf("  Throughput: %.2f MB/s\n", benchmark_throughput_mbps(total_bytes, elapsed));
    printf("  Operations/sec: %.0f\n", benchmark_ops_per_sec(iterations, elapsed));

    return 0;
}

static int benchmark_crc32c_streaming(void)
{
    const size_t total_size = 100 * 1024 * 1024; // 100MB total
    const size_t chunk_size = 8192;              // 8KB chunks
    const int num_chunks = total_size / chunk_size;

    printf("\nCRC32C Benchmark: Streaming (%zu MB in %zu byte chunks)\n",
           total_size / (1024 * 1024), chunk_size);

    char *chunk = malloc(chunk_size);
    if (!chunk)
        return 1;

    // Fill chunk with pattern data
    for (size_t i = 0; i < chunk_size; i++)
    {
        chunk[i] = (char)(i % 256);
    }

    bfc_crc32c_ctx_t ctx;
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    bfc_crc32c_reset(&ctx);

    for (int i = 0; i < num_chunks; i++)
    {
        bfc_crc32c_update(&ctx, chunk, chunk_size);

        if (i % 1000 == 0)
        {
            printf("  Progress: %d/%d chunks\n", i, num_chunks);
        }
    }

    uint32_t final_crc = bfc_crc32c_final(&ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(chunk);

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Final CRC32C: 0x%08x\n", final_crc);
    printf("  Throughput: %.2f MB/s\n", benchmark_throughput_mbps(total_size, elapsed));
    printf("  Chunks/sec: %.0f\n", benchmark_ops_per_sec(num_chunks, elapsed));

    return 0;
}

static int benchmark_crc32c_alignment(void)
{
    const size_t chunk_size = 16384; // 16KB
    const int iterations = 10000;

    printf("\nCRC32C Benchmark: Alignment test (%zu KB, %d iterations)\n",
           chunk_size / 1024, iterations);

    // Allocate buffer with extra space for alignment testing
    char *buffer = malloc(chunk_size + 64);
    if (!buffer)
        return 1;

    // Test different alignments
    int alignments[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16};
    int num_alignments = sizeof(alignments) / sizeof(alignments[0]);

    for (int a = 0; a < num_alignments; a++)
    {
        char *aligned_data = buffer + alignments[a];

        // Fill with pattern data
        for (size_t i = 0; i < chunk_size; i++)
        {
            aligned_data[i] = (char)(i % 256);
        }

        bfc_crc32c_ctx_t ctx;
        struct timespec start, end;

        clock_gettime(CLOCK_MONOTONIC, &start);

        uint32_t final_crc = 0;
        for (int i = 0; i < iterations; i++)
        {
            bfc_crc32c_reset(&ctx);
            bfc_crc32c_update(&ctx, aligned_data, chunk_size);
            final_crc = bfc_crc32c_final(&ctx);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        double elapsed = benchmark_time_diff(&start, &end);
        uint64_t total_bytes = (uint64_t)iterations * chunk_size;

        printf("  Alignment +%d: %.2f MB/s (CRC: 0x%08x)\n",
               alignments[a],
               benchmark_throughput_mbps(total_bytes, elapsed),
               final_crc);
    }

    free(buffer);
    return 0;
}

int main(void)
{
    printf("=== BFC CRC32C Performance Benchmarks ===\n\n");

    // Check hardware support
    if (bfc_crc32c_has_hw_support())
    {
        printf("Hardware CRC32C support: Available\n\n");
    }
    else
    {
        printf("Hardware CRC32C support: Not available (using software fallback)\n\n");
    }

    if (benchmark_crc32c_small_chunks() != 0)
    {
        printf("Small chunks benchmark failed\n");
        return 1;
    }

    if (benchmark_crc32c_large_chunks() != 0)
    {
        printf("Large chunks benchmark failed\n");
        return 1;
    }

    if (benchmark_crc32c_streaming() != 0)
    {
        printf("Streaming benchmark failed\n");
        return 1;
    }

    if (benchmark_crc32c_alignment() != 0)
    {
        printf("Alignment benchmark failed\n");
        return 1;
    }

    printf("\n=== CRC32C Benchmarks Complete ===\n");
    return 0;
}