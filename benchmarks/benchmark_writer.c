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

static int benchmark_small_files(void)
{
    const char *container = "/tmp/benchmark_small.bfc";
    const int num_files = 10000;
    const size_t file_size = 1024; // 1KB files

    unlink(container);

    printf("Writer Benchmark: %d small files (%zu bytes each)\n", num_files, file_size);

    // Prepare content
    char *content = malloc(file_size);
    if (!content)
        return 1;

    memset(content, 'A', file_size);

    bfc_t *writer = NULL;
    int result = bfc_create(container, 4096, 0, &writer);
    if (result != BFC_OK)
    {
        free(content);
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_files; i++)
    {
        char path[64];
        snprintf(path, sizeof(path), "file_%06d.txt", i);

        FILE *temp = tmpfile();
        if (!temp)
            break;

        fwrite(content, 1, file_size, temp);
        rewind(temp);

        result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
        fclose(temp);

        if (result != BFC_OK)
            break;

        if (i % 1000 == 0)
        {
            printf("  Progress: %d/%d files\n", i, num_files);
        }
    }

    result = bfc_finish(writer);
    bfc_close(writer);

    clock_gettime(CLOCK_MONOTONIC, &end);

    free(content);

    if (result != BFC_OK)
    {
        printf("  FAILED\n");
        return 1;
    }

    double elapsed = benchmark_time_diff(&start, &end);
    uint64_t total_size = (uint64_t)num_files * file_size;

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Throughput: %.2f MB/s\n", (total_size / (1024.0 * 1024.0)) / elapsed);
    printf("  Files/sec: %.0f\n", num_files / elapsed);

    struct stat st;
    if (stat(container, &st) == 0)
    {
        printf("  Container size: %.2f MB\n", st.st_size / (1024.0 * 1024.0));
        printf("  Overhead: %.1f%%\n", ((double)st.st_size - total_size) * 100.0 / total_size);
    }

    unlink(container);
    return 0;
}

static int benchmark_large_files(void)
{
    const char *container = "/tmp/benchmark_large.bfc";
    const int num_files = 10;
    const size_t file_size = 100 * 1024 * 1024; // 100MB files

    unlink(container);

    printf("\nWriter Benchmark: %d large files (%zu MB each)\n",
           num_files, file_size / (1024 * 1024));

    bfc_t *writer = NULL;
    int result = bfc_create(container, 4096, 0, &writer);
    if (result != BFC_OK)
    {
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_files; i++)
    {
        char path[64];
        snprintf(path, sizeof(path), "large_file_%02d.bin", i);

        printf("  Creating file %d/%d...\n", i + 1, num_files);

        // Create temporary file with pattern
        FILE *temp = tmpfile();
        if (!temp)
            break;

        // Write pattern data
        const size_t chunk_size = 64 * 1024; // 64KB chunks
        char *chunk = malloc(chunk_size);
        if (!chunk)
        {
            fclose(temp);
            break;
        }

        // Fill chunk with pattern
        for (size_t j = 0; j < chunk_size; j++)
        {
            chunk[j] = (char)(j % 256);
        }

        for (size_t written = 0; written < file_size; written += chunk_size)
        {
            size_t to_write = (file_size - written < chunk_size) ? (file_size - written) : chunk_size;
            fwrite(chunk, 1, to_write, temp);
        }

        free(chunk);
        rewind(temp);

        result = bfc_add_file(writer, path, temp, 0644, 0, NULL);
        fclose(temp);

        if (result != BFC_OK)
            break;
    }

    printf("  Finalizing container...\n");
    result = bfc_finish(writer);
    bfc_close(writer);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != BFC_OK)
    {
        printf("  FAILED\n");
        return 1;
    }

    double elapsed = benchmark_time_diff(&start, &end);
    uint64_t total_size = (uint64_t)num_files * file_size;

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Throughput: %.2f MB/s\n", (total_size / (1024.0 * 1024.0)) / elapsed);
    printf("  Files/sec: %.2f\n", num_files / elapsed);

    struct stat st;
    if (stat(container, &st) == 0)
    {
        printf("  Container size: %.2f MB\n", st.st_size / (1024.0 * 1024.0));
        printf("  Overhead: %.2f%%\n", ((double)st.st_size - total_size) * 100.0 / total_size);
    }

    unlink(container);
    return 0;
}

static int benchmark_mixed_workload(void)
{
    const char *container = "/tmp/benchmark_mixed.bfc";

    unlink(container);

    printf("\nWriter Benchmark: Mixed workload (files + directories)\n");

    bfc_t *writer = NULL;
    int result = bfc_create(container, 4096, 0, &writer);
    if (result != BFC_OK)
    {
        return 1;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int total_files = 0;
    uint64_t total_size = 0;

    // Create directory structure with files
    for (int dir = 0; dir < 50; dir++)
    {
        char dir_path[512];
        snprintf(dir_path, sizeof(dir_path), "dir_%03d", dir);

        result = bfc_add_dir(writer, dir_path, 0755, 0);
        if (result != BFC_OK)
            break;

        // Add subdirectory
        char subdir_path[512];
        snprintf(subdir_path, sizeof(subdir_path), "%s/subdir", dir_path);
        result = bfc_add_dir(writer, subdir_path, 0755, 0);
        if (result != BFC_OK)
            break;

        // Add files of varying sizes
        for (int file = 0; file < 20; file++)
        {
            char file_path[512];
            snprintf(file_path, sizeof(file_path), "%s/file_%03d.txt", dir_path, file);

            // Vary file sizes: 1KB to 1MB
            size_t file_size = 1024 + (file * 51200); // 1KB + file * 50KB

            FILE *temp = tmpfile();
            if (!temp)
                break;

            char *content = malloc(file_size);
            if (!content)
            {
                fclose(temp);
                break;
            }

            // Fill with pattern
            for (size_t i = 0; i < file_size; i++)
            {
                content[i] = (char)((i + file + dir) % 256);
            }

            fwrite(content, 1, file_size, temp);
            rewind(temp);

            result = bfc_add_file(writer, file_path, temp, 0644, 0, NULL);

            free(content);
            fclose(temp);

            if (result != BFC_OK)
                break;

            total_files++;
            total_size += file_size;
        }

        if (result != BFC_OK)
            break;

        if (dir % 10 == 0)
        {
            printf("  Progress: %d/50 directories, %d files\n", dir, total_files);
        }
    }

    result = bfc_finish(writer);
    bfc_close(writer);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != BFC_OK)
    {
        printf("  FAILED\n");
        return 1;
    }

    double elapsed = benchmark_time_diff(&start, &end);

    printf("  Time: %.2f seconds\n", elapsed);
    printf("  Files created: %d\n", total_files);
    printf("  Throughput: %.2f MB/s\n", (total_size / (1024.0 * 1024.0)) / elapsed);
    printf("  Files/sec: %.0f\n", total_files / elapsed);

    struct stat st;
    if (stat(container, &st) == 0)
    {
        printf("  Container size: %.2f MB\n", st.st_size / (1024.0 * 1024.0));
        printf("  Overhead: %.1f%%\n", ((double)st.st_size - total_size) * 100.0 / total_size);
    }

    unlink(container);
    return 0;
}

int main(void)
{
    printf("=== BFC Writer Performance Benchmarks ===\n\n");

    if (benchmark_small_files() != 0)
    {
        printf("Small files benchmark failed\n");
        return 1;
    }

    if (benchmark_large_files() != 0)
    {
        printf("Large files benchmark failed\n");
        return 1;
    }

    if (benchmark_mixed_workload() != 0)
    {
        printf("Mixed workload benchmark failed\n");
        return 1;
    }

    printf("\n=== Writer Benchmarks Complete ===\n");
    return 0;
}