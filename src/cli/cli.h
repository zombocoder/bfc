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

#ifdef _WIN32
#include "cli_win32_compat.h"
#else
#include <sys/stat.h>
#endif

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
int read_key_from_file(const char* keyfile, uint8_t key[32]);

// Password and key-file options, shared by create, extract and verify
typedef struct {
  const char* password;      // -p, --password
  const char* password_file; // --password-file ("-" for stdin)
  const char* keyfile;       // -K, --keyfile
  char* owned_password;      // read from file or prompt; wiped on free
} cli_credentials_t;

void cli_credentials_init(cli_credentials_t* c);
void cli_credentials_free(cli_credentials_t* c);
// Returns 1 if argv[*i] was a credential option (and consumes its value),
// 0 if it was not, -1 on error.
int cli_parse_credential_option(int argc, char* argv[], int* i, cli_credentials_t* c);
int cli_credentials_given(const cli_credentials_t* c);
int cli_credentials_check(const cli_credentials_t* c);
// prompt_if_needed: ask on the terminal when the container is encrypted and
// no credentials were given (only when stdin is a terminal).
// Both return 1 if a password or key was set, 0 if none was given, -1 on error.
int cli_apply_reader_credentials(bfc_t* reader, cli_credentials_t* c, int prompt_if_needed);
int cli_apply_writer_credentials(bfc_t* writer, cli_credentials_t* c);

// Global options (extern declaration)
extern bfc_options_t g_options;

#endif // CLI_H