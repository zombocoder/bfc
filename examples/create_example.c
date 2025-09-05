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

#include <bfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <container.bfc>\n", argv[0]);
    return 1;
  }

  const char* container_path = argv[1];

  // Create a new BFC container
  printf("Creating container: %s\n", container_path);

  bfc_t* writer = NULL;
  int result = bfc_create(container_path, 4096, 0, &writer);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to create container: %d\n", result);
    return 1;
  }

  // Add a directory
  printf("Adding directory: docs/\n");
  result = bfc_add_dir(writer, "docs", 0755, 1704067200000000000ULL); // 2024-01-01
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to add directory: %d\n", result);
    bfc_close(writer);
    return 1;
  }

  // Create some sample content in memory
  const char* readme_content = "# BFC Container Example\n"
                               "\n"
                               "This is a sample README file stored in a BFC container.\n"
                               "BFC (Binary File Container) is a single-file archive format.\n"
                               "\n"
                               "Features:\n"
                               "- Single file containers\n"
                               "- POSIX metadata preservation\n"
                               "- CRC32C integrity checking\n"
                               "- Fast random access\n";

  const char* config_content = "{\n"
                               "  \"version\": \"1.0\",\n"
                               "  \"compression\": \"none\",\n"
                               "  \"block_size\": 4096\n"
                               "}\n";

  // Create temporary files for content
  FILE* readme_file = tmpfile();
  FILE* config_file = tmpfile();

  if (!readme_file || !config_file) {
    fprintf(stderr, "Failed to create temporary files\n");
    bfc_close(writer);
    return 1;
  }

  fwrite(readme_content, 1, strlen(readme_content), readme_file);
  fwrite(config_content, 1, strlen(config_content), config_file);
  rewind(readme_file);
  rewind(config_file);

  // Add files to container
  printf("Adding file: README.md\n");
  uint32_t readme_crc;
  result =
      bfc_add_file(writer, "README.md", readme_file, 0644, 1704067200000000000ULL, &readme_crc);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to add README.md: %d\n", result);
    fclose(readme_file);
    fclose(config_file);
    bfc_close(writer);
    return 1;
  }
  printf("README.md CRC32C: 0x%08x\n", readme_crc);

  printf("Adding file: docs/config.json\n");
  uint32_t config_crc;
  result = bfc_add_file(writer, "docs/config.json", config_file, 0644, 1704067200000000000ULL,
                        &config_crc);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to add config.json: %d\n", result);
    fclose(readme_file);
    fclose(config_file);
    bfc_close(writer);
    return 1;
  }
  printf("config.json CRC32C: 0x%08x\n", config_crc);

  // Clean up temporary files
  fclose(readme_file);
  fclose(config_file);

  // Finish and close the container
  printf("Finalizing container...\n");
  result = bfc_finish(writer);
  if (result != BFC_OK) {
    fprintf(stderr, "Failed to finish container: %d\n", result);
    bfc_close(writer);
    return 1;
  }

  bfc_close(writer);

  printf("Container created successfully!\n");
  printf("Try: ./read_example %s\n", container_path);

  return 0;
}