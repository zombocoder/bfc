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

#define _GNU_SOURCE /* strdup */

#include <stdio.h>

#ifdef BFC_WITH_OCI

#include "bfc_os.h"
#include <assert.h>
#include <bfc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Use the real OCI types, constants, and declarations — not local mocks, which
// previously drifted from the header (wrong struct layout => UB when passed to
// the library functions).
#include <bfc_oci.h>

// Unique per-process paths so the suite is safe under parallel ctest.
static void oci_tmp_path(char* buf, size_t n, const char* name) {
  snprintf(buf, n, "/tmp/bfc_oci_%d_%s.bfc", (int) getpid(), name);
}

// Create a real, finished container so the "NULL argument" assertions below
// actually execute (they used to hide behind bfc_open() on a file that was
// never created, so the second half of each test silently never ran).
static int oci_make_container(const char* path) {
  bfc_t* w = NULL;
  if (bfc_create(path, 4096, 0, &w) != BFC_OK) {
    return -1;
  }
  bfc_oci_manifest_t m = {0};
  m.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  m.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);
  int rc = bfc_create_from_oci_manifest(w, &m, "{\"architecture\":\"amd64\",\"os\":\"linux\"}");
  bfc_free_oci_manifest(&m);
  if (rc != BFC_OK || bfc_finish(w) != BFC_OK) {
    bfc_close(w);
    return -1;
  }
  bfc_close(w);
  return 0;
}

static int test_validate_oci_manifest_null(void) {
  // Test with NULL manifest
  int result = bfc_validate_oci_manifest(NULL);
  assert(result == BFC_E_INVAL);
  return 0;
}

static int test_validate_oci_manifest_missing_fields(void) {
  bfc_oci_manifest_t manifest = {0};

  // Test with NULL schema_version
  int result = bfc_validate_oci_manifest(&manifest);
  assert(result == BFC_E_INVAL);

  // Test with NULL media_type
  manifest.schema_version = strdup("2");
  result = bfc_validate_oci_manifest(&manifest);
  assert(result == BFC_E_INVAL);
  free(manifest.schema_version);

  return 0;
}

static int test_validate_oci_manifest_invalid_schema(void) {
  bfc_oci_manifest_t manifest = {0};
  manifest.schema_version = strdup("1");
  manifest.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);

  int result = bfc_validate_oci_manifest(&manifest);
  assert(result == BFC_E_INVAL);

  free(manifest.schema_version);
  free(manifest.media_type);

  return 0;
}

static int test_validate_oci_manifest_invalid_media_type(void) {
  bfc_oci_manifest_t manifest = {0};
  manifest.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  manifest.media_type = strdup("invalid/type");

  int result = bfc_validate_oci_manifest(&manifest);
  assert(result == BFC_E_INVAL);

  free(manifest.schema_version);
  free(manifest.media_type);

  return 0;
}

static int test_validate_oci_manifest_valid(void) {
  bfc_oci_manifest_t manifest = {0};
  manifest.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  manifest.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);

  int result = bfc_validate_oci_manifest(&manifest);
  assert(result == BFC_OK);

  free(manifest.schema_version);
  free(manifest.media_type);

  return 0;
}

static int test_validate_oci_config_null(void) {
  // Test with NULL config
  int result = bfc_validate_oci_config(NULL);
  assert(result == BFC_E_INVAL);
  return 0;
}

static int test_validate_oci_config_missing_fields(void) {
  bfc_oci_config_t config = {0};

  // Test with NULL architecture
  int result = bfc_validate_oci_config(&config);
  assert(result == BFC_E_INVAL);

  // Test with NULL os
  config.architecture = strdup("amd64");
  result = bfc_validate_oci_config(&config);
  assert(result == BFC_E_INVAL);
  free(config.architecture);

  return 0;
}

static int test_validate_oci_config_valid(void) {
  bfc_oci_config_t config = {0};
  config.architecture = strdup("amd64");
  config.os = strdup("linux");

  int result = bfc_validate_oci_config(&config);
  assert(result == BFC_OK);

  free(config.architecture);
  free(config.os);

  return 0;
}

static int test_create_from_oci_manifest_null_args(void) {
  // Test with NULL bfc
  bfc_oci_manifest_t manifest = {0};
  int result = bfc_create_from_oci_manifest(NULL, &manifest, NULL);
  assert(result == BFC_E_INVAL);

  // Test with NULL manifest
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "null");
  bfc_t* writer = NULL;
  result = bfc_create(filename, 4096, 0, &writer);
  if (result == BFC_OK && writer != NULL) {
    result = bfc_create_from_oci_manifest(writer, NULL, NULL);
    assert(result == BFC_E_INVAL);
    bfc_close(writer);
    unlink(filename);
  }

  return 0;
}

static int test_create_from_oci_manifest_basic(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "manifest");
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  if (result != BFC_OK) {
    return 0; // Skip if can't create
  }

  bfc_oci_manifest_t manifest = {0};
  manifest.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  manifest.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);

  result = bfc_create_from_oci_manifest(writer, &manifest, NULL);
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  // Verify container exists
  FILE* file = fopen(filename, "rb");
  assert(file != NULL);
  fclose(file);

  free(manifest.schema_version);
  free(manifest.media_type);
  unlink(filename);

  return 0;
}

static int test_create_from_oci_index_null_args(void) {
  // Test with NULL bfc
  bfc_oci_index_t index = {0};
  int result = bfc_create_from_oci_index(NULL, &index);
  assert(result == BFC_E_INVAL);

  // Test with NULL index
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "index");
  bfc_t* writer = NULL;
  result = bfc_create(filename, 4096, 0, &writer);
  if (result == BFC_OK && writer != NULL) {
    result = bfc_create_from_oci_index(writer, NULL);
    assert(result == BFC_E_INVAL);
    bfc_close(writer);
    unlink(filename);
  }

  return 0;
}

static int test_create_from_oci_index_basic(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "index");
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  if (result != BFC_OK) {
    return 0; // Skip if can't create
  }

  bfc_oci_index_t index = {0};
  index.schema_version = strdup("2");

  result = bfc_create_from_oci_index(writer, &index);
  assert(result == BFC_OK);

  result = bfc_finish(writer);
  assert(result == BFC_OK);

  bfc_close(writer);

  // Verify container exists
  FILE* file = fopen(filename, "rb");
  assert(file != NULL);
  fclose(file);

  free(index.schema_version);
  unlink(filename);

  return 0;
}

static int test_get_oci_manifest_null_args(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "get_manifest");
  assert(oci_make_container(filename) == 0);
  bfc_oci_manifest_t manifest;

  // Test with NULL bfc
  int result = bfc_get_oci_manifest(NULL, &manifest);
  assert(result == BFC_E_INVAL);

  // Test with NULL manifest
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK && reader != NULL);
  result = bfc_get_oci_manifest(reader, NULL);
  assert(result == BFC_E_INVAL);
  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_get_oci_config_null_args(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "get_config");
  assert(oci_make_container(filename) == 0);
  bfc_oci_config_t config;

  // Test with NULL bfc
  int result = bfc_get_oci_config(NULL, &config);
  assert(result == BFC_E_INVAL);

  // Test with NULL config
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK && reader != NULL);
  result = bfc_get_oci_config(reader, NULL);
  assert(result == BFC_E_INVAL);
  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_list_oci_layers_null_args(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "list_layers");
  assert(oci_make_container(filename) == 0);
  bfc_oci_layer_t* layers = NULL;
  size_t layer_count = 0;

  // Test with NULL bfc
  int result = bfc_list_oci_layers(NULL, &layers, &layer_count);
  assert(result == BFC_E_INVAL);

  // Test with NULL layers
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK && reader != NULL);
  result = bfc_list_oci_layers(reader, NULL, &layer_count);
  assert(result == BFC_E_INVAL);
  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_extract_to_oci_null_args(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "extract");
  assert(oci_make_container(filename) == 0);
  // Test with NULL bfc
  int result = bfc_extract_to_oci(NULL, "/tmp/test_output");
  assert(result == BFC_E_INVAL);

  // Test with NULL output_dir
  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK && reader != NULL);
  result = bfc_extract_to_oci(reader, NULL);
  assert(result == BFC_E_INVAL);
  bfc_close_read(reader);
  unlink(filename);

  return 0;
}

static int test_free_functions_null(void) {
  // Test that free functions handle NULL gracefully
  bfc_free_oci_manifest(NULL);
  bfc_free_oci_config(NULL);
  bfc_free_oci_layer(NULL);
  bfc_free_oci_index(NULL);
  bfc_free_oci_layers(NULL, 0);

  return 0;
}

// Round-trip: write a manifest (+config) then read it back and verify fields.
static int test_oci_manifest_roundtrip(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "roundtrip");
  unlink(filename);

  bfc_t* writer = NULL;
  int result = bfc_create(filename, 4096, 0, &writer);
  if (result != BFC_OK) {
    return 0; // skip if can't create
  }

  bfc_oci_manifest_t in = {0};
  in.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  in.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);
  in.config_digest =
      strdup("sha256:1111111111111111111111111111111111111111111111111111111111111111");
  in.config_size = 512;
  in.layer_count = 2;
  in.layer_digests = calloc(2, sizeof(char*));
  in.layer_digests[0] =
      strdup("sha256:2222222222222222222222222222222222222222222222222222222222222222");
  in.layer_digests[1] =
      strdup("sha256:3333333333333333333333333333333333333333333333333333333333333333");

  const char* config_json = "{\"architecture\":\"amd64\",\"os\":\"linux\"}";
  result = bfc_create_from_oci_manifest(writer, &in, config_json);
  assert(result == BFC_OK);
  assert(bfc_finish(writer) == BFC_OK);
  bfc_close(writer);

  bfc_t* reader = NULL;
  result = bfc_open(filename, &reader);
  assert(result == BFC_OK);

  // Manifest round-trips with all fields intact.
  bfc_oci_manifest_t out = {0};
  result = bfc_get_oci_manifest(reader, &out);
  assert(result == BFC_OK);
  assert(out.schema_version && strcmp(out.schema_version, BFC_OCI_SCHEMA_VERSION) == 0);
  assert(out.media_type && strcmp(out.media_type, BFC_OCI_MEDIA_TYPE_MANIFEST) == 0);
  assert(out.config_digest && strcmp(out.config_digest, in.config_digest) == 0);
  assert(out.config_size == in.config_size);
  assert(out.layer_count == 2);
  assert(out.layer_digests[0] && strcmp(out.layer_digests[0], in.layer_digests[0]) == 0);
  assert(out.layer_digests[1] && strcmp(out.layer_digests[1], in.layer_digests[1]) == 0);
  assert(bfc_validate_oci_manifest(&out) == BFC_OK);
  free(out.schema_version);
  free(out.media_type);
  free(out.config_digest);
  for (size_t i = 0; i < out.layer_count; i++) {
    free(out.layer_digests[i]);
  }
  free(out.layer_digests);

  // Layer listing round-trips.
  bfc_oci_layer_t* layers = NULL;
  size_t layer_count = 0;
  result = bfc_list_oci_layers(reader, &layers, &layer_count);
  assert(result == BFC_OK);
  assert(layer_count == 2);
  assert(layers[0].digest && strcmp(layers[0].digest, in.layer_digests[0]) == 0);
  assert(layers[1].digest && strcmp(layers[1].digest, in.layer_digests[1]) == 0);
  bfc_free_oci_layers(layers, layer_count);

  // Config round-trips.
  bfc_oci_config_t cfg = {0};
  result = bfc_get_oci_config(reader, &cfg);
  assert(result == BFC_OK);
  assert(cfg.architecture && strcmp(cfg.architecture, "amd64") == 0);
  assert(cfg.os && strcmp(cfg.os, "linux") == 0);
  assert(bfc_validate_oci_config(&cfg) == BFC_OK);
  free(cfg.architecture);
  free(cfg.os);
  free(cfg.created);
  free(cfg.author);

  bfc_close_read(reader);

  free(in.schema_version);
  free(in.media_type);
  free(in.config_digest);
  free(in.layer_digests[0]);
  free(in.layer_digests[1]);
  free(in.layer_digests);
  unlink(filename);
  return 0;
}

// Write a layer, extract the container to an OCI directory, and confirm the blob
// actually lands on disk. This is the case the prefix mismatch silently broke:
// the writer stored blobs/sha256/<hex> while the extractor listed "layers/", so
// extraction reported success having found nothing.
static int test_oci_layer_extract_roundtrip(void) {
  char filename[256];
  oci_tmp_path(filename, sizeof(filename), "layer_rt");
  unlink(filename);

  const char* digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
  const char* payload = "layer-bytes";

  bfc_t* writer = NULL;
  if (bfc_create(filename, 4096, 0, &writer) != BFC_OK) {
    return 0; // skip if the fs won't cooperate
  }

  bfc_oci_manifest_t m = {0};
  m.schema_version = strdup(BFC_OCI_SCHEMA_VERSION);
  m.media_type = strdup(BFC_OCI_MEDIA_TYPE_MANIFEST);
  assert(bfc_create_from_oci_manifest(writer, &m,
                                      "{\"architecture\":\"amd64\",\"os\":\"linux\"}") == BFC_OK);
  bfc_free_oci_manifest(&m);

  bfc_oci_layer_t layer = {0};
  layer.digest = strdup(digest);
  layer.media_type = strdup("application/vnd.oci.image.layer.v1.tar+gzip");
  layer.size = strlen(payload);

  FILE* data = tmpfile();
  assert(data != NULL);
  fwrite(payload, 1, strlen(payload), data);
  rewind(data);
  assert(bfc_add_oci_layer(writer, &layer, data) == BFC_OK);
  fclose(data);
  bfc_free_oci_layer(&layer);

  assert(bfc_finish(writer) == BFC_OK);
  bfc_close(writer);

  // Extract and verify the blob is really there, named by its hex (no doubled
  // "sha256:" in the path).
  char outdir[256];
  snprintf(outdir, sizeof(outdir), "/tmp/bfc_oci_%d_extract", (int) getpid());
  mkdir(outdir, 0755);

  bfc_t* reader = NULL;
  assert(bfc_open(filename, &reader) == BFC_OK);
  assert(bfc_extract_to_oci(reader, outdir) == BFC_OK);
  bfc_close_read(reader);

  char blob[512];
  snprintf(blob, sizeof(blob), "%s/oci/blobs/sha256/%s", outdir, strchr(digest, ':') + 1);
  FILE* f = fopen(blob, "rb");
  assert(f != NULL); // the whole point: extraction produced the layer
  char got[64] = {0};
  size_t n = fread(got, 1, sizeof(got) - 1, f);
  fclose(f);
  assert(n == strlen(payload));
  assert(strcmp(got, payload) == 0);

  unlink(blob);
  unlink(filename);
  return 0;
}

// Main test function
int test_oci(void) {
  printf("Running OCI tests...\n");

  test_validate_oci_manifest_null();
  test_validate_oci_manifest_missing_fields();
  test_validate_oci_manifest_invalid_schema();
  test_validate_oci_manifest_invalid_media_type();
  test_validate_oci_manifest_valid();

  test_validate_oci_config_null();
  test_validate_oci_config_missing_fields();
  test_validate_oci_config_valid();

  test_create_from_oci_manifest_null_args();
  test_create_from_oci_manifest_basic();

  test_create_from_oci_index_null_args();
  test_create_from_oci_index_basic();

  test_get_oci_manifest_null_args();
  test_get_oci_config_null_args();
  test_list_oci_layers_null_args();
  test_extract_to_oci_null_args();

  test_oci_manifest_roundtrip();
  test_oci_layer_extract_roundtrip();

  test_free_functions_null();

  printf("OCI tests passed!\n");
  return 0;
}

#else // BFC_WITH_OCI not defined

int test_oci(void) { return 0; }

#endif // BFC_WITH_OCI
