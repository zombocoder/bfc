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

#include "cli.h"
#include <stdarg.h>
#include <stdio.h>

void print_error(const char* format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
}

void print_verbose(const char* format, ...) {
  if (!g_options.verbose || g_options.quiet) {
    return;
  }

  va_list args;
  va_start(args, format);
  fprintf(stderr, "Verbose: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
}

const char* bfc_error_string(int error_code) {
  switch (error_code) {
  case BFC_OK:
    return "Success";
  case BFC_E_BADMAGIC:
    return "Invalid container format";
  case BFC_E_IO:
    return "I/O error";
  case BFC_E_CRC:
    return "CRC mismatch";
  case BFC_E_INVAL:
    return "Invalid argument";
  case BFC_E_EXISTS:
    return "Already exists";
  case BFC_E_NOTFOUND:
    return "Not found";
  case BFC_E_PERM:
    return "Permission denied";
  default:
    return "Unknown error";
  }
}