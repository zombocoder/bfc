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

// Test declarations
int test_format(void);
int test_crc32c(void);
int test_path(void);
int test_writer(void);
int test_reader(void);
int test_util(void);
int test_os(void);
int test_compress(void);
int test_encrypt(void);
int test_oci(void);
// int test_encrypt_integration(void);  // Temporarily disabled

typedef struct {
  const char* name;
  int (*func)(void);
} test_case_t;

static test_case_t tests[] = {
    {"format", test_format},
    {"crc32c", test_crc32c},
    {"path", test_path},
    {"writer", test_writer},
    {"reader", test_reader},
    {"util", test_util},
    {"os", test_os},
    {"compress", test_compress},
    {"encrypt", test_encrypt},
    {"oci", test_oci},
    // {"encrypt_integration", test_encrypt_integration},  // Temporarily disabled
    {NULL, NULL}};

static int run_test(const char* name, int (*func)(void)) {
  printf("Running test: %s... ", name);
  fflush(stdout);

  int result = func();

  if (result == 0) {
    printf("PASS\n");
  } else {
    printf("FAIL\n");
  }

  return result;
}

int main(int argc, char* argv[]) {
  int failed = 0;

  if (argc == 2) {
    // Run specific test
    const char* test_name = argv[1];

    for (int i = 0; tests[i].name; i++) {
      if (strcmp(tests[i].name, test_name) == 0) {
        return run_test(tests[i].name, tests[i].func);
      }
    }

    printf("Unknown test: %s\n", test_name);
    return 1;
  }

  // Run all tests
  printf("Running all unit tests...\n");

  for (int i = 0; tests[i].name; i++) {
    if (run_test(tests[i].name, tests[i].func) != 0) {
      failed = 1;
    }
  }

  if (failed) {
    printf("\nSome tests failed.\n");
    return 1;
  } else {
    printf("\nAll tests passed.\n");
    return 0;
  }
}