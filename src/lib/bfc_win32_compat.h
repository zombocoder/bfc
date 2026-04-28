/*
 * Copyright 2026 Gemini CLI
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

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <process.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <winsock2.h>
#include <time.h>

#if defined(_MSC_VER) && _MSC_VER < 1900
#ifndef _TIMESPEC_DEFINED
#define _TIMESPEC_DEFINED
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
#endif
#endif

// Missing POSIX types
typedef ptrdiff_t ssize_t;

// Missing POSIX constants for stat
#ifndef S_IFMT
#define S_IFMT 0170000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif

#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (0)
#define S_ISBLK(m) (0)
#define S_ISFIFO(m) (0)
#define S_ISSOCK(m) (0)

#ifndef S_IRUSR
#define S_IRUSR 0000400
#endif
#ifndef S_IWUSR
#define S_IWUSR 0000200
#endif
#ifndef S_IXUSR
#define S_IXUSR 0000100
#endif
#ifndef S_IRGRP
#define S_IRGRP 0000040
#endif
#ifndef S_IWGRP
#define S_IWGRP 0000020
#endif
#ifndef S_IXGRP
#define S_IXGRP 0000010
#endif
#ifndef S_IROTH
#define S_IROTH 0000004
#endif
#ifndef S_IWOTH
#define S_IWOTH 0000002
#endif
#ifndef S_IXOTH
#define S_IXOTH 0000001
#endif

#ifndef S_ISUID
#define S_ISUID 0004000
#endif
#ifndef S_ISGID
#define S_ISGID 0002000
#endif
#ifndef S_ISVTX
#define S_ISVTX 0001000
#endif

#ifndef F_OK
#define F_OK 0
#endif

// usleep replacement
static inline void usleep(unsigned long usec) {
    Sleep(usec / 1000);
}

#define sleep(seconds) Sleep((seconds) * 1000)

// clock_gettime basic replacement for benchmarks
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

typedef int clockid_t;

static inline int clock_gettime(clockid_t clk_id, struct timespec* tp) {
    (void)clk_id;
    FILETIME ft;
    uint64_t tim;
    GetSystemTimeAsFileTime(&ft);
    tim = ft.dwLowDateTime;
    tim |= ((uint64_t)ft.dwHighDateTime) << 32;
    tim -= 116444736000000000ULL; // 1601 to 1970
    tp->tv_sec = (time_t)(tim / 10000000ULL);
    tp->tv_nsec = (long)((tim % 10000000ULL) * 100ULL);
    return 0;
}

// Map mkdir to _mkdir
#define mkdir(path, ...) _mkdir(path)

// Map fseeko/ftello to 64-bit Windows equivalents
#define fseeko _fseeki64
#define ftello _ftelli64

// Map fileno to _fileno
#define fileno _fileno

// Map getpid to _getpid
#define getpid _getpid

#endif // _WIN32
