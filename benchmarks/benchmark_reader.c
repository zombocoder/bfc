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

// Create a test container for reading benchmarks
static int create_test_container(const char *container, int num_files, size_t file_size)
{
    unlink(container);

    bfc_t *writer = NULL;
    int result = bfc_create(container, 4096, 0, &writer);
    if (result != BFC_OK)
        return result;

    char *content = malloc(file_size);
    if (!content)
    {
        bfc_close(writer);
        return BFC_E_IO;
    }

    // Fill with pattern
    for (size_t i = 0; i < file_size; i++)
    {
        content[i] = (char)(i % 256);
    }

    // Add directories and files
    for (int i = 0; i < num_files; i++)
    {
        char path[128];

        // Create some directory structure
        if (i % 10 == 0)
        {
            snprintf(path, sizeof(path), "dir_%03d", i / 10);
            bfc_add_dir(writer, path, 0755, 0);
        }

        snprintf(path, sizeof(path), "dir_%03d/file_%06d.bin", i / 10, i);

        FILE *temp = tmpfile();
        if (!temp)
            break;

        fwrite(content, 1, file_size, temp);
        rewind(temp);

        result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
        fclose(temp);

        if (result != BFC_OK)
            break;
    }

    free(content);

    if (result == BFC_OK)
    {
        result = bfc_finish(writer);
    }

    bfc_close(writer);
    return result;
}

static int benchmark_random_reads(void)
{
    const char *container = "/tmp/benchmark_read_random.bfc";
    const int num_files = 1000;
    const size_t file_size = 8192; // 8KB files
    const int num_reads = 5000;

    printf("Reader Benchmark: Random file reads\n");
    printf("  Creating test container with %d files...\n", num_files);

    int result = create_test_container(container, num_files, file_size);
    if (result != BFC_OK)
    {
        printf("  Failed to create test container: %d\n", result);
        return 1;
    }

    bfc_t *reader = NULL;
    result = bfc_open(container, &reader);
    if (result != BFC_OK)
    {
        printf("  Failed to open container: %d\n", result);
        unlink(container);
        return 1;
    }

    // Prepare read buffer
    char *buffer = malloc(file_size);
    if (!buffer)
    {
        bfc_close_read(reader);
        unlink(container);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t bytes_read = 0;
    int successful_reads = 0;

    for (int i = 0; i < num_reads; i++)
    {
        int file_idx = rand() % num_files;
        char path[128];
        snprintf(path, sizeof(path), "dir_%03d/file_%06d.bin", file_idx / 10, file_idx);

        size_t read_bytes = bfc_read(reader, path, 0, buffer, file_size);
        if (read_bytes == file_size)
        {
            bytes_read += read_bytes;
            successful_reads++;
        }

        if (i % 1000 == 0)
        {
            printf("  Progress: %d/%d reads\n", i, num_reads);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(buffer);
    bfc_close_read(reader);
    unlink(container);

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Successful reads: %d/%d\n", successful_reads, num_reads);
    printf("  Throughput: %.2f MB/s\n", (bytes_read / (1024.0 * 1024.0)) / elapsed);
    printf("  Reads/sec: %.0f\n", successful_reads / elapsed);

    return 0;
}

static int benchmark_sequential_reads(void)
{
    const char *container = "/tmp/benchmark_read_seq.bfc";
    const int num_files = 500;
    const size_t file_size = 64 * 1024; // 64KB files

    printf("\nReader Benchmark: Sequential file reads\n");
    printf("  Creating test container with %d files...\n", num_files);

    int result = create_test_container(container, num_files, file_size);
    if (result != BFC_OK)
    {
        printf("  Failed to create test container: %d\n", result);
        return 1;
    }

    bfc_t *reader = NULL;
    result = bfc_open(container, &reader);
    if (result != BFC_OK)
    {
        printf("  Failed to open container: %d\n", result);
        unlink(container);
        return 1;
    }

    char *buffer = malloc(file_size);
    if (!buffer)
    {
        bfc_close_read(reader);
        unlink(container);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t bytes_read = 0;
    int successful_reads = 0;

    // Read all files sequentially
    for (int i = 0; i < num_files; i++)
    {
        char path[128];
        snprintf(path, sizeof(path), "dir_%03d/file_%06d.bin", i / 10, i);

        size_t read_bytes = bfc_read(reader, path, 0, buffer, file_size);
        if (read_bytes == file_size)
        {
            bytes_read += read_bytes;
            successful_reads++;
        }

        if (i % 50 == 0)
        {
            printf("  Progress: %d/%d files\n", i, num_files);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(buffer);
    bfc_close_read(reader);
    unlink(container);

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Successful reads: %d/%d\n", successful_reads, num_files);
    printf("  Throughput: %.2f MB/s\n", (bytes_read / (1024.0 * 1024.0)) / elapsed);
    printf("  Files/sec: %.0f\n", successful_reads / elapsed);

    return 0;
}

static int benchmark_stat_operations(void)
{
    const char *container = "/tmp/benchmark_stat.bfc";
    const int num_files = 10000;
    const size_t file_size = 1024; // 1KB files
    const int num_stats = 50000;

    printf("\nReader Benchmark: File stat operations\n");
    printf("  Creating test container with %d files...\n", num_files);

    int result = create_test_container(container, num_files, file_size);
    if (result != BFC_OK)
    {
        printf("  Failed to create test container: %d\n", result);
        return 1;
    }

    bfc_t *reader = NULL;
    result = bfc_open(container, &reader);
    if (result != BFC_OK)
    {
        printf("  Failed to open container: %d\n", result);
        unlink(container);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int successful_stats = 0;

    for (int i = 0; i < num_stats; i++)
    {
        int file_idx = rand() % num_files;
        char path[128];
        snprintf(path, sizeof(path), "dir_%03d/file_%06d.bin", file_idx / 10, file_idx);

        bfc_entry_t entry;
        if (bfc_stat(reader, path, &entry) == BFC_OK)
        {
            successful_stats++;
        }

        if (i % 10000 == 0)
        {
            printf("  Progress: %d/%d stats\n", i, num_stats);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    bfc_close_read(reader);
    unlink(container);

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Successful stats: %d/%d\n", successful_stats, num_stats);
    printf("  Stats/sec: %.0f\n", successful_stats / elapsed);

    return 0;
}

// List callback for counting
static int count_entries(const bfc_entry_t *entry, void *user)
{
    (void)entry; // Unused parameter
    int *count = (int *)user;
    (*count)++;
    return 0;
}

static int benchmark_list_operations(void)
{
    const char *container = "/tmp/benchmark_list.bfc";
    const int num_files = 5000;
    const size_t file_size = 1024;
    const int num_lists = 1000;

    printf("\nReader Benchmark: Directory listing operations\n");
    printf("  Creating test container with %d files...\n", num_files);

    int result = create_test_container(container, num_files, file_size);
    if (result != BFC_OK)
    {
        printf("  Failed to create test container: %d\n", result);
        return 1;
    }

    bfc_t *reader = NULL;
    result = bfc_open(container, &reader);
    if (result != BFC_OK)
    {
        printf("  Failed to open container: %d\n", result);
        unlink(container);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int total_entries = 0;

    for (int i = 0; i < num_lists; i++)
    {
        int count = 0;

        if (i % 2 == 0)
        {
            // List all entries
            bfc_list(reader, NULL, count_entries, &count);
        }
        else
        {
            // List specific directory
            int dir_idx = rand() % (num_files / 10);
            char dir_path[128];
            snprintf(dir_path, sizeof(dir_path), "dir_%03d", dir_idx);
            bfc_list(reader, dir_path, count_entries, &count);
        }

        total_entries += count;

        if (i % 100 == 0)
        {
            printf("  Progress: %d/%d lists\n", i, num_lists);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    bfc_close_read(reader);
    unlink(container);

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Lists performed: %d\n", num_lists);
    printf("  Total entries processed: %d\n", total_entries);
    printf("  Lists/sec: %.0f\n", num_lists / elapsed);
    printf("  Entries/sec: %.0f\n", total_entries / elapsed);

    return 0;
}

int main(void)
{
    printf("=== BFC Reader Performance Benchmarks ===\n\n");

    // Seed random number generator
    srand((unsigned int)time(NULL));

    if (benchmark_random_reads() != 0)
    {
        printf("Random reads benchmark failed\n");
        return 1;
    }

    if (benchmark_sequential_reads() != 0)
    {
        printf("Sequential reads benchmark failed\n");
        return 1;
    }

    if (benchmark_stat_operations() != 0)
    {
        printf("Stat operations benchmark failed\n");
        return 1;
    }

    if (benchmark_list_operations() != 0)
    {
        printf("List operations benchmark failed\n");
        return 1;
    }

    printf("\n=== Reader Benchmarks Complete ===\n");
    return 0;
}