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

// Password and key-file options shared by create, extract and verify, so the
// commands spell and handle them the same way.

#include "cli.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <termios.h>
#include <unistd.h>
#endif

#define CLI_PASSWORD_MAX 1024

void cli_credentials_init(cli_credentials_t* c) {
  c->password = NULL;
  c->password_file = NULL;
  c->keyfile = NULL;
  c->owned_password = NULL;
}

void cli_credentials_free(cli_credentials_t* c) {
  if (c->owned_password) {
    memset(c->owned_password, 0, strlen(c->owned_password));
    free(c->owned_password);
    c->owned_password = NULL;
  }
}

int cli_parse_credential_option(int argc, char* argv[], int* i, cli_credentials_t* c) {
  const char* arg = argv[*i];
  const char** target = NULL;

  if (strcmp(arg, "-p") == 0 || strcmp(arg, "--password") == 0) {
    target = &c->password;
  } else if (strcmp(arg, "--password-file") == 0) {
    target = &c->password_file;
  } else if (strcmp(arg, "-K") == 0 || strcmp(arg, "--keyfile") == 0) {
    target = &c->keyfile;
  } else {
    return 0;
  }

  if (*i + 1 >= argc) {
    print_error("%s requires an argument", arg);
    return -1;
  }
  *target = argv[++(*i)];
  return 1;
}

int cli_credentials_given(const cli_credentials_t* c) {
  return c->password || c->password_file || c->keyfile;
}

int cli_credentials_check(const cli_credentials_t* c) {
  int n = (c->password != NULL) + (c->password_file != NULL) + (c->keyfile != NULL);
  if (n > 1) {
    print_error("Use only one of --password, --password-file and --keyfile");
    return -1;
  }
  return 0;
}

// Read the first line of a file ("-" for stdin) as the password.
static char* read_password_file(const char* path) {
  FILE* f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
  if (!f) {
    print_error("Cannot open password file '%s': %s", path, strerror(errno));
    return NULL;
  }

  char* buf = malloc(CLI_PASSWORD_MAX);
  if (!buf) {
    if (f != stdin) {
      fclose(f);
    }
    print_error("Out of memory");
    return NULL;
  }

  if (!fgets(buf, CLI_PASSWORD_MAX, f)) {
    buf[0] = '\0';
  }
  if (f != stdin) {
    fclose(f);
  }

  buf[strcspn(buf, "\r\n")] = '\0';
  if (buf[0] == '\0') {
    print_error("Password file '%s' is empty", path);
    free(buf);
    return NULL;
  }
  return buf;
}

// Prompt on the terminal with echo turned off. Returns NULL if stdin is not a
// terminal, so scripts never block waiting for input.
static char* prompt_password(const char* prompt) {
  if (!isatty(fileno(stdin))) {
    return NULL;
  }

  char* buf = malloc(CLI_PASSWORD_MAX);
  if (!buf) {
    print_error("Out of memory");
    return NULL;
  }

  fprintf(stderr, "%s", prompt);
  fflush(stderr);

#ifdef _WIN32
  size_t n = 0;
  int ch;
  while ((ch = _getch()) != '\r' && ch != '\n' && ch != EOF) {
    if (ch == '\b') {
      if (n > 0) {
        n--;
      }
    } else if (n + 1 < CLI_PASSWORD_MAX) {
      buf[n++] = (char) ch;
    }
  }
  buf[n] = '\0';
#else
  struct termios old_t, new_t;
  int restore = 0;
  if (tcgetattr(fileno(stdin), &old_t) == 0) {
    new_t = old_t;
    new_t.c_lflag &= ~(tcflag_t) ECHO;
    restore = tcsetattr(fileno(stdin), TCSAFLUSH, &new_t) == 0;
  }
  if (!fgets(buf, CLI_PASSWORD_MAX, stdin)) {
    buf[0] = '\0';
  }
  if (restore) {
    tcsetattr(fileno(stdin), TCSAFLUSH, &old_t);
  }
  buf[strcspn(buf, "\r\n")] = '\0';
#endif

  fprintf(stderr, "\n");
  return buf;
}

// Resolve the password from --password or --password-file. Returns 0 with
// *out set (or NULL if none was given), -1 on error.
static int resolve_password(cli_credentials_t* c, const char** out) {
  *out = c->password;
  if (c->password_file) {
    c->owned_password = read_password_file(c->password_file);
    if (!c->owned_password) {
      return -1;
    }
    *out = c->owned_password;
  }
  return 0;
}

int cli_apply_reader_credentials(bfc_t* reader, cli_credentials_t* c, int prompt_if_needed) {
  const char* password;
  if (resolve_password(c, &password) != 0) {
    return -1;
  }

  if (!password && !c->keyfile && prompt_if_needed && bfc_has_encryption(reader)) {
    c->owned_password = prompt_password("Password: ");
    password = c->owned_password;
    if (!password) {
      print_error("Container is encrypted; pass --password, --password-file or --keyfile");
      return -1;
    }
    if (password[0] == '\0') {
      print_error("No password entered");
      return -1;
    }
  }

  if (!password && !c->keyfile) {
    return 0;
  }

#ifdef BFC_WITH_SODIUM
  int result;
  if (password) {
    result = bfc_reader_set_encryption_password(reader, password, strlen(password));
  } else {
    uint8_t key[32];
    if (read_key_from_file(c->keyfile, key) != 0) {
      return -1;
    }
    result = bfc_reader_set_encryption_key(reader, key);
    memset(key, 0, sizeof(key));
  }
  if (result != BFC_OK) {
    print_error("Failed to set encryption key: %s", bfc_error_string(result));
    return -1;
  }
  return 1;
#else
  (void) reader;
  print_error("Encryption support not available. Please build with BFC_WITH_SODIUM=ON");
  return -1;
#endif
}

int cli_apply_writer_credentials(bfc_t* writer, cli_credentials_t* c) {
  const char* password;
  if (resolve_password(c, &password) != 0) {
    return -1;
  }

  if (!password && !c->keyfile) {
    return 0;
  }

#ifdef BFC_WITH_SODIUM
  int result;
  if (password) {
    result = bfc_set_encryption_password(writer, password, strlen(password));
    print_verbose("Encryption: ChaCha20-Poly1305 with password-based key derivation");
  } else {
    uint8_t key[32];
    if (read_key_from_file(c->keyfile, key) != 0) {
      return -1;
    }
    result = bfc_set_encryption_key(writer, key);
    memset(key, 0, sizeof(key));
    print_verbose("Encryption: ChaCha20-Poly1305 with key from file");
  }
  if (result != BFC_OK) {
    print_error("Failed to set encryption key: %s", bfc_error_string(result));
    return -1;
  }
  return 1;
#else
  (void) writer;
  print_error("Encryption support not available. Rebuild with -DBFC_WITH_SODIUM=ON");
  return -1;
#endif
}
