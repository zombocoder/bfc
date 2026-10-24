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

// Test helper: writes a container holding a symlink "lnk" -> <target> and a
// file "lnk/file.txt" below it. `bfc create` never produces this layout, so
// the CLI tests use it to check that extract refuses to write through the
// symlink.
//
// usage: make_symlink_parent <out.bfc> <symlink-target>

#include <bfc.h>
#include <stdio.h>

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <out.bfc> <symlink-target>\n", argv[0]);
    return 2;
  }

  bfc_t* w = NULL;
  if (bfc_create(argv[1], 4096, 0, &w) != BFC_OK) {
    return 1;
  }

  FILE* content = tmpfile();
  if (!content) {
    bfc_close(w);
    return 1;
  }
  fputs("written through a symlink\n", content);
  rewind(content);

  uint32_t crc;
  int ok = bfc_add_symlink(w, "lnk", argv[2], 0755, 0) == BFC_OK &&
           bfc_add_file(w, "lnk/file.txt", content, 0644, 0, &crc) == BFC_OK &&
           bfc_finish(w) == BFC_OK;

  fclose(content);
  bfc_close(w);
  return ok ? 0 : 1;
}
