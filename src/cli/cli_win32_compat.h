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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../lib/bfc_win32_compat.h"

// dirname replacement
static char* dirname(char* path) {
    static char buffer[MAX_PATH];
    if (!path || !*path) {
        strcpy(buffer, ".");
        return buffer;
    }
    
    char* last_slash = strrchr(path, '/');
    char* last_backslash = strrchr(path, '\\');
    char* sep = (last_slash > last_backslash) ? last_slash : last_backslash;

    if (!sep) {
        strcpy(buffer, ".");
    } else if (sep == path) {
        strcpy(buffer, "/");
    } else {
        size_t len = sep - path;
        if (len >= MAX_PATH) len = MAX_PATH - 1;
        strncpy(buffer, path, len);
        buffer[len] = '\0';
    }
    return buffer;
}

// POSIX function mappings for Windows
#define chdir _chdir
#define lstat stat
#define symlink(target, linkpath) (-1) // Not supported for now
#define lutimes(path, tv) (0) // Stub
#define futimens(fd, ts) (0) // Stub
#define utimensat(dirfd, path, ts, flags) (0) // Stub
#define fchmod(fd, mode) (0) // Stub
#define chmod _chmod

// dirent.h basic replacement for Windows
typedef struct dirent {
    char d_name[MAX_PATH];
} dirent_t;

typedef struct DIR {
    HANDLE hFind;
    WIN32_FIND_DATA findData;
    struct dirent ent;
    int first;
} DIR;

static DIR* opendir(const char* name) {
    DIR* dir = (DIR*)malloc(sizeof(DIR));
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s/*", name);
    dir->hFind = FindFirstFile(searchPath, &dir->findData);
    if (dir->hFind == INVALID_HANDLE_VALUE) {
        free(dir);
        return NULL;
    }
    dir->first = 1;
    return dir;
}

static struct dirent* readdir(DIR* dir) {
    if (dir->first) {
        dir->first = 0;
    } else {
        if (!FindNextFile(dir->hFind, &dir->findData)) {
            return NULL;
        }
    }
    strncpy(dir->ent.d_name, dir->findData.cFileName, MAX_PATH);
    return &dir->ent;
}

static int closedir(DIR* dir) {
    FindClose(dir->hFind);
    free(dir);
    return 0;
}

#endif // _WIN32
