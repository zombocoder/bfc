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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global options
bfc_options_t g_options = {0};

// Available commands
static const bfc_command_t commands[] = {
    {"create", "Create a new BFC container", cmd_create},
    {"list", "List contents of a BFC container", cmd_list},
    {"extract", "Extract files from a BFC container", cmd_extract},
    {"info", "Show information about a BFC container", cmd_info},
    {"verify", "Verify integrity of a BFC container", cmd_verify},
    {"help", "Show help information", cmd_help},
    {NULL, NULL, NULL}};

void print_usage(const char* program_name) {
  printf("Usage: %s [global-options] <command> [command-options] [arguments]\n\n", program_name);

  printf("Global Options:\n");
  printf("  -v, --verbose     Enable verbose output\n");
  printf("  -q, --quiet       Suppress non-error output\n");
  printf("  -h, --help        Show this help message\n");
  printf("  --version         Show version information\n\n");

  printf("Commands:\n");
  for (int i = 0; commands[i].name; i++) {
    printf("  %-12s %s\n", commands[i].name, commands[i].description);
  }

  printf("\nUse '%s <command> --help' for command-specific help.\n", program_name);
  printf("\nExamples:\n");
  printf("  %s create myfiles.bfc /path/to/files/\n", program_name);
  printf("  %s list myfiles.bfc\n", program_name);
  printf("  %s extract myfiles.bfc --output /path/to/extract/\n", program_name);
}

void print_version(void) {
  printf("bfc version 1.0.0\n");
  printf("Binary File Container CLI tool\n");
  printf("Copyright 2021 zombocoder (Taras Havryliak)\n");
}

int parse_global_options(int* argc, char*** argv, bfc_options_t* opts) {
  int i, j;

  // Initialize options
  memset(opts, 0, sizeof(bfc_options_t));

  for (i = 1; i < *argc; i++) {
    if (strcmp((*argv)[i], "-v") == 0 || strcmp((*argv)[i], "--verbose") == 0) {
      opts->verbose = 1;
      // Remove this argument
      for (j = i; j < *argc - 1; j++) {
        (*argv)[j] = (*argv)[j + 1];
      }
      (*argc)--;
      i--; // Check same position again
    } else if (strcmp((*argv)[i], "-q") == 0 || strcmp((*argv)[i], "--quiet") == 0) {
      opts->quiet = 1;
      // Remove this argument
      for (j = i; j < *argc - 1; j++) {
        (*argv)[j] = (*argv)[j + 1];
      }
      (*argc)--;
      i--;
    } else if (strcmp((*argv)[i], "-h") == 0 || strcmp((*argv)[i], "--help") == 0) {
      print_usage((*argv)[0]);
      return 1; // Exit after showing help
    } else if (strcmp((*argv)[i], "--version") == 0) {
      print_version();
      return 1; // Exit after showing version
    } else if ((*argv)[i][0] == '-') {
      fprintf(stderr, "Unknown global option: %s\n", (*argv)[i]);
      return -1;
    } else {
      // Not a global option, stop parsing
      break;
    }
  }

  return 0;
}

int cmd_help(int argc, char* argv[]) {
  if (argc > 1) {
    // Look for specific command help
    const char* cmd_name = argv[1];
    for (int i = 0; commands[i].name; i++) {
      if (strcmp(commands[i].name, cmd_name) == 0) {
        // Call the command with --help
        char* help_argv[] = {(char*) cmd_name, "--help"};
        return commands[i].handler(2, help_argv);
      }
    }
    printf("Unknown command: %s\n", cmd_name);
    return 1;
  }

  print_usage("bfc");
  return 0;
}

int main(int argc, char* argv[]) {
  // Parse global options
  int result = parse_global_options(&argc, &argv, &g_options);
  if (result != 0) {
    return (result > 0) ? 0 : 1; // Exit normally for help/version, error for unknown options
  }

  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  const char* command = argv[1];

  // Find and execute command
  for (int i = 0; commands[i].name; i++) {
    if (strcmp(commands[i].name, command) == 0) {
      return commands[i].handler(argc - 1, argv + 1);
    }
  }

  printf("Unknown command: %s\n", command);
  printf("Use '%s help' for available commands.\n", argv[0]);
  return 1;
}