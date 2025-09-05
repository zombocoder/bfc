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

#ifndef BENCHMARK_COMMON_H
#define BENCHMARK_COMMON_H

#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

// Calculate time difference in seconds
static inline double benchmark_time_diff(const struct timespec *start, const struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

// Format bytes in human readable format
static inline const char *benchmark_format_bytes(uint64_t bytes, char *buffer, size_t buf_size)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = (double)bytes;

    while (size >= 1024.0 && unit < 4)
    {
        size /= 1024.0;
        unit++;
    }

    if (unit == 0)
    {
        snprintf(buffer, buf_size, "%" PRIu64 " %s", bytes, units[unit]);
    }
    else
    {
        snprintf(buffer, buf_size, "%.2f %s", size, units[unit]);
    }

    return buffer;
}

// Format throughput in MB/s
static inline double benchmark_throughput_mbps(uint64_t bytes, double elapsed_seconds)
{
    return (bytes / (1024.0 * 1024.0)) / elapsed_seconds;
}

// Format operations per second
static inline double benchmark_ops_per_sec(int operations, double elapsed_seconds)
{
    return operations / elapsed_seconds;
}

#endif // BENCHMARK_COMMON_H