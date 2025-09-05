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

#ifndef CLI_H
#define CLI_H

#include <bfc.h>

// Command handler function type
typedef int (*cmd_handler_t)(int argc, char* argv[]);

// Command structure
typedef struct {
  const char* name;
  const char* description;
  cmd_handler_t handler;
} bfc_command_t;

// Global options structure
typedef struct {
  int verbose;
  int quiet;
  const char* container;
} bfc_options_t;

// Command handlers
int cmd_create(int argc, char* argv[]);
int cmd_list(int argc, char* argv[]);
int cmd_extract(int argc, char* argv[]);
int cmd_info(int argc, char* argv[]);
int cmd_verify(int argc, char* argv[]);
int cmd_help(int argc, char* argv[]);

// Utility functions
void print_usage(const char* program_name);
void print_version(void);
void print_error(const char* format, ...);
void print_verbose(const char* format, ...);
int parse_global_options(int* argc, char*** argv, bfc_options_t* opts);
const char* bfc_error_string(int error_code);

// Global options (extern declaration)
extern bfc_options_t g_options;

#endif // CLI_H