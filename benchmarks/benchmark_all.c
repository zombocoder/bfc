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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

// External benchmark functions
extern int benchmark_crc32c_main(void);
extern int benchmark_writer_main(void);
extern int benchmark_reader_main(void);

static void print_system_info(void)
{
    printf("=== System Information ===\n");

    struct utsname info;
    if (uname(&info) == 0)
    {
        printf("System: %s %s %s\n", info.sysname, info.release, info.machine);
        printf("Node: %s\n", info.nodename);
    }

    printf("Compiler: ");
#ifdef __clang__
    printf("Clang %s\n", __clang_version__);
#elif defined(__GNUC__)
    printf("GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    printf("Unknown\n");
#endif

    printf("Build: ");
#ifdef NDEBUG
    printf("Release\n");
#else
    printf("Debug\n");
#endif

    printf("Features: ");
#ifdef __SSE4_2__
    printf("SSE4.2 ");
#endif
#ifdef __ARM_FEATURE_CRC32
    printf("ARM-CRC32 ");
#endif
#ifdef BFC_WITH_FUSE
    printf("FUSE ");
#endif
#ifdef BFC_WITH_ZSTD
    printf("ZSTD ");
#endif
    printf("\n");

    time_t now = time(NULL);
    printf("Date: %s", ctime(&now));
    printf("\n");
}

static void print_benchmark_header(const char *name)
{
    printf("===========================================\n");
    printf("  %s\n", name);
    printf("===========================================\n\n");
}

static void print_benchmark_footer(void)
{
    printf("\n===========================================\n\n");
}

typedef struct
{
    const char *name;
    int (*func)(void);
} benchmark_t;

// Wrapper functions to match expected signatures
static int run_crc32c_benchmark(void)
{
    // We'll need to run the CRC32C benchmark directly
    // For now, just indicate success
    return 0;
}

static int run_writer_benchmark(void)
{
    // We'll need to run the writer benchmark directly
    return 0;
}

static int run_reader_benchmark(void)
{
    // We'll need to run the reader benchmark directly
    return 0;
}

int main(int argc, char *argv[])
{
    int run_all = 1;
    const char *specific_benchmark = NULL;

    if (argc == 2)
    {
        run_all = 0;
        specific_benchmark = argv[1];
    }
    else if (argc > 2)
    {
        fprintf(stderr, "Usage: %s [benchmark_name]\n", argv[0]);
        fprintf(stderr, "Available benchmarks: crc32c, writer, reader\n");
        return 1;
    }

    print_system_info();

    benchmark_t benchmarks[] = {
        {"CRC32C Performance Benchmark", run_crc32c_benchmark},
        {"Writer Performance Benchmark", run_writer_benchmark},
        {"Reader Performance Benchmark", run_reader_benchmark},
        {NULL, NULL}};

    const char *benchmark_names[] = {"crc32c", "writer", "reader"};

    int failed = 0;

    for (int i = 0; benchmarks[i].name; i++)
    {
        if (!run_all)
        {
            if (strcmp(specific_benchmark, benchmark_names[i]) != 0)
            {
                continue;
            }
        }

        print_benchmark_header(benchmarks[i].name);

        // Run the actual benchmark executables
        char command[256];
        int result = 0;

        if (i == 0)
        { // CRC32C
            snprintf(command, sizeof(command), "./benchmark_crc32c");
            result = system(command);
        }
        else if (i == 1)
        { // Writer
            snprintf(command, sizeof(command), "./benchmark_writer");
            result = system(command);
        }
        else if (i == 2)
        { // Reader
            snprintf(command, sizeof(command), "./benchmark_reader");
            result = system(command);
        }

        if (result != 0)
        {
            printf("❌ %s FAILED\n", benchmarks[i].name);
            failed = 1;
        }
        else
        {
            printf("✅ %s COMPLETED\n", benchmarks[i].name);
        }

        print_benchmark_footer();

        if (!run_all)
        {
            break;
        }

        // Small delay between benchmarks to let system settle
        sleep(1);
    }

    if (run_all)
    {
        printf("=== Benchmark Summary ===\n");
        if (failed)
        {
            printf("[FAILED] Some benchmarks failed\n");
            return 1;
        }
        else
        {
            printf("[SUCCESS] All benchmarks completed successfully\n");
        }
    }

    return 0;
}