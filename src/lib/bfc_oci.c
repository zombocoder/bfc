/*
 * Copyright 2021 zombocoder (Taras Havryliak)
 * Copyright 2024 Proxmox-LXCRI Contributors
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

#define _GNU_SOURCE /* strdup, fmemopen */

#include "bfc_oci.h"
#include <cjson/cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Single source of truth for where layer blobs live inside the container. The
// writer and the extractor MUST agree on this prefix — they previously did not
// (writer used blobs/sha256/, extractor listed layers/), so extraction silently
// found nothing.
#define BFC_OCI_BLOB_PREFIX "blobs/sha256/"

// Build the container path for a layer digest.
// An OCI digest is "<algorithm>:<hex>"; the algorithm already appears in the
// blob directory, so it is stripped to avoid blobs/sha256/sha256:<hex>.
static int oci_layer_path(const char* digest, char* buf, size_t buflen) {
  if (!digest || !*digest) {
    return BFC_E_INVAL;
  }
  const char* hex = strchr(digest, ':');
  hex = hex ? hex + 1 : digest;
  if (!*hex) {
    return BFC_E_INVAL;
  }
  if (snprintf(buf, buflen, BFC_OCI_BLOB_PREFIX "%s", hex) >= (int) buflen) {
    return BFC_E_INVAL;
  }
  return BFC_OK;
}

// Read an entire container entry into a NUL-terminated heap buffer.
static int oci_read_entry(bfc_t* bfc, const char* path, char** out, size_t* out_len) {
  bfc_entry_t e;
  if (bfc_stat(bfc, path, &e) != BFC_OK) {
    return BFC_E_NOTFOUND;
  }
  char* buf = malloc((size_t) e.size + 1);
  if (!buf) {
    return BFC_E_IO;
  }
  size_t n = (e.size > 0) ? bfc_read(bfc, path, 0, buf, (size_t) e.size) : 0;
  if (n != (size_t) e.size) {
    free(buf);
    return BFC_E_IO;
  }
  buf[e.size] = '\0';
  *out = buf;
  *out_len = (size_t) e.size;
  return BFC_OK;
}

// schemaVersion is an integer in JSON; we store it as a string ("2").
static char* oci_dup_schema_version(const cJSON* root) {
  const cJSON* sv = cJSON_GetObjectItemCaseSensitive(root, "schemaVersion");
  if (cJSON_IsNumber(sv)) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%d", (int) sv->valuedouble);
    return strdup(tmp);
  }
  if (cJSON_IsString(sv) && sv->valuestring) {
    return strdup(sv->valuestring);
  }
  return NULL;
}

static char* oci_dup_str_field(const cJSON* obj, const char* key) {
  const cJSON* it = cJSON_GetObjectItemCaseSensitive(obj, key);
  return (cJSON_IsString(it) && it->valuestring) ? strdup(it->valuestring) : NULL;
}

// Callback to collect all file entries for extraction
struct extract_context {
  char** files;
  int count;
  int capacity;
};

static int collect_files(const bfc_entry_t* entry, void* user) {
  struct extract_context* ctx = (struct extract_context*) user;

  // Only collect regular files, skip directories
  if (!S_ISREG(entry->mode)) {
    return 0;
  }

  // Expand array if needed
  if (ctx->count >= ctx->capacity) {
    ctx->capacity = ctx->capacity ? ctx->capacity * 2 : 10;
    ctx->files = realloc(ctx->files, ctx->capacity * sizeof(char*));
    if (!ctx->files) {
      return -1;
    }
  }

  // Store a copy of the path
  ctx->files[ctx->count] = strdup(entry->path);
  if (!ctx->files[ctx->count]) {
    return -1;
  }
  ctx->count++;

  return 0;
}

static void cleanup_extract_context(struct extract_context* ctx) {
  if (ctx->files) {
    for (int i = 0; i < ctx->count; i++) {
      free(ctx->files[i]);
    }
    free(ctx->files);
    ctx->files = NULL;
  }
  ctx->count = 0;
  ctx->capacity = 0;
}

// Create BFC container from OCI image manifest
int bfc_create_from_oci_manifest(bfc_t* bfc, const bfc_oci_manifest_t* manifest,
                                 const char* config_json) {
  if (!bfc || !manifest) {
    return BFC_E_INVAL;
  }

  // Build manifest.json with cJSON so every string is escaped correctly and
  // schemaVersion lands in a real JSON number slot (a raw "%s" of "2.0.1" would
  // emit {"schemaVersion":2.0.1}, which is not parseable).
  cJSON* root = cJSON_CreateObject();
  if (!root) {
    return BFC_E_IO;
  }
  cJSON_AddNumberToObject(root, "schemaVersion",
                          manifest->schema_version ? atoi(manifest->schema_version) : 2);
  cJSON_AddStringToObject(root, "mediaType", manifest->media_type ? manifest->media_type : "");
  if (manifest->config_digest) {
    cJSON* cfg = cJSON_AddObjectToObject(root, "config");
    if (cfg) {
      cJSON_AddStringToObject(cfg, "digest", manifest->config_digest);
      cJSON_AddNumberToObject(cfg, "size", (double) manifest->config_size);
    }
  }
  cJSON* layers = cJSON_AddArrayToObject(root, "layers");
  for (size_t i = 0; layers && i < manifest->layer_count; i++) {
    cJSON* l = cJSON_CreateObject();
    if (!l) {
      continue;
    }
    cJSON_AddStringToObject(
        l, "digest",
        (manifest->layer_digests && manifest->layer_digests[i]) ? manifest->layer_digests[i] : "");
    cJSON_AddItemToArray(layers, l);
  }
  char* json = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!json) {
    return BFC_E_IO;
  }
  size_t json_len = strlen(json);

  // Add manifest.json to BFC
  FILE* manifest_file = fmemopen(json, json_len, "r");
  if (!manifest_file) {
    free(json);
    return BFC_E_IO;
  }
  int mrc = bfc_add_file(bfc, "manifest.json", manifest_file, 0, 0, NULL);
  fclose(manifest_file);
  free(json);
  if (mrc != BFC_OK) {
    return BFC_E_IO;
  }

  // Add config.json to BFC
  if (config_json) {
    FILE* config_file = fmemopen((void*) config_json, strlen(config_json), "r");
    if (!config_file) {
      return BFC_E_IO;
    }

    if (bfc_add_file(bfc, "config.json", config_file, 0, 0, NULL) != BFC_OK) {
      fclose(config_file);
      return BFC_E_IO;
    }

    fclose(config_file);
  }

  return BFC_OK;
}

// Create BFC container from OCI image index
int bfc_create_from_oci_index(bfc_t* bfc, const bfc_oci_index_t* index) {
  if (!bfc || !index) {
    return BFC_E_INVAL;
  }

  // Build index.json with cJSON (same escaping/number-slot reasoning as above).
  cJSON* root = cJSON_CreateObject();
  if (!root) {
    return BFC_E_IO;
  }
  cJSON_AddNumberToObject(root, "schemaVersion",
                          index->schema_version ? atoi(index->schema_version) : 2);
  cJSON_AddStringToObject(root, "mediaType", index->media_type ? index->media_type : "");
  cJSON* arr = cJSON_AddArrayToObject(root, "manifests");
  for (size_t i = 0; arr && i < index->manifest_count; i++) {
    const bfc_oci_manifest_t* m = index->manifests ? index->manifests[i] : NULL;
    cJSON* item = cJSON_CreateObject();
    if (!item) {
      continue;
    }
    cJSON_AddStringToObject(item, "mediaType", (m && m->media_type) ? m->media_type : "");
    cJSON_AddStringToObject(item, "digest", (m && m->config_digest) ? m->config_digest : "");
    cJSON_AddItemToArray(arr, item);
  }
  char* json = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!json) {
    return BFC_E_IO;
  }
  size_t json_len = strlen(json);

  // Add index.json to BFC
  FILE* index_file = fmemopen(json, json_len, "r");
  if (!index_file) {
    free(json);
    return BFC_E_IO;
  }
  int irc = bfc_add_file(bfc, "index.json", index_file, 0, 0, NULL);
  fclose(index_file);
  free(json);
  if (irc != BFC_OK) {
    return BFC_E_IO;
  }

  return BFC_OK;
}

// Add OCI layer to BFC container
int bfc_add_oci_layer(bfc_t* bfc, const bfc_oci_layer_t* layer, FILE* layer_data) {
  if (!bfc || !layer || !layer_data || !layer->digest) {
    return BFC_E_INVAL;
  }

  // Create layer path from digest (refuse over-long digests rather than silently truncating)
  char layer_path[256];
  if (oci_layer_path(layer->digest, layer_path, sizeof(layer_path)) != BFC_OK) {
    return BFC_E_INVAL;
  }

  // Add layer data to BFC
  if (bfc_add_file(bfc, layer_path, layer_data, 0, 0, NULL) != BFC_OK) {
    return BFC_E_IO;
  }

  return BFC_OK;
}

// Extract BFC container to OCI format
int bfc_extract_to_oci(bfc_t* bfc, const char* output_dir) {
  if (!bfc || !output_dir) {
    return BFC_E_INVAL;
  }

  // Create OCI directory structure (guard each path against truncation)
  char oci_dir[1024];
  if (snprintf(oci_dir, sizeof(oci_dir), "%s/oci", output_dir) >= (int) sizeof(oci_dir)) {
    return BFC_E_INVAL;
  }

  if (mkdir(oci_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Create blobs directory
  char blobs_dir[1024];
  if (snprintf(blobs_dir, sizeof(blobs_dir), "%s/blobs", oci_dir) >= (int) sizeof(blobs_dir)) {
    return BFC_E_INVAL;
  }

  if (mkdir(blobs_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Create sha256 subdirectory
  char sha256_dir[1024];
  if (snprintf(sha256_dir, sizeof(sha256_dir), "%s/sha256", blobs_dir) >=
      (int) sizeof(sha256_dir)) {
    return BFC_E_INVAL;
  }

  if (mkdir(sha256_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Extract OCI manifest
  char manifest_path[1024];
  if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", oci_dir) >=
      (int) sizeof(manifest_path)) {
    return BFC_E_INVAL;
  }

  int manifest_fd = open(manifest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (manifest_fd < 0) {
    return BFC_E_IO;
  }

  int result = bfc_extract_to_fd(bfc, "manifest.json", manifest_fd);
  close(manifest_fd);

  if (result != BFC_OK) {
    return result;
  }

  // Extract OCI config
  char config_path[1024];
  if (snprintf(config_path, sizeof(config_path), "%s/config.json", oci_dir) >=
      (int) sizeof(config_path)) {
    return BFC_E_INVAL;
  }

  int config_fd = open(config_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (config_fd < 0) {
    return BFC_E_IO;
  }

  result = bfc_extract_to_fd(bfc, "config.json", config_fd);
  close(config_fd);

  if (result != BFC_OK) {
    return result;
  }

  // Extract layer blobs using callback approach. The prefix must match what
  // bfc_add_oci_layer writes, hence the shared BFC_OCI_BLOB_PREFIX.
  struct extract_context ctx = {0};
  result = bfc_list(bfc, BFC_OCI_BLOB_PREFIX, collect_files, &ctx);
  if (result != BFC_OK) {
    cleanup_extract_context(&ctx);
    return result;
  }

  for (int i = 0; i < ctx.count; i++) {
    const char* file_path = ctx.files[i];

    // Container paths are "blobs/sha256/<hex>"; sha256_dir already IS that
    // directory on disk, so only the blob name is appended (appending the whole
    // container path would nest blobs/sha256/ twice).
    const char* blob_name = strrchr(file_path, '/');
    blob_name = blob_name ? blob_name + 1 : file_path;

    char output_path[1024];
    if (snprintf(output_path, sizeof(output_path), "%s/%s", sha256_dir, blob_name) >=
        (int) sizeof(output_path)) {
      cleanup_extract_context(&ctx);
      return BFC_E_INVAL;
    }

    // Open output file
    int out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
      fprintf(stderr, "Failed to create output file '%s': %s\n", output_path, strerror(errno));
      continue;
    }

    // Extract file content
    result = bfc_extract_to_fd(bfc, file_path, out_fd);
    close(out_fd);

    if (result != BFC_OK) {
      fprintf(stderr, "Failed to extract '%s': %d\n", file_path, result);
      unlink(output_path); // Remove partial file
    } else {
      // Get file stats for verification
      bfc_entry_t entry;
      if (bfc_stat(bfc, file_path, &entry) == BFC_OK) {
        printf("  Layer size: %" PRIu64 " bytes, CRC32C: 0x%08x\n", entry.size, entry.crc32c);
      }
    }
  }

  // Clean up
  cleanup_extract_context(&ctx);

  printf("OCI extraction complete to: %s\n", oci_dir);
  return BFC_OK;
}

// Get OCI manifest from BFC container
int bfc_get_oci_manifest(bfc_t* bfc, bfc_oci_manifest_t* manifest) {
  if (!bfc || !manifest) {
    return BFC_E_INVAL;
  }

  char* buf = NULL;
  size_t len = 0;
  int rc = oci_read_entry(bfc, "manifest.json", &buf, &len);
  if (rc != BFC_OK) {
    return rc;
  }

  cJSON* root = cJSON_ParseWithLength(buf, len);
  free(buf);
  if (!root) {
    return BFC_E_INVAL;
  }

  memset(manifest, 0, sizeof(*manifest));
  manifest->schema_version = oci_dup_schema_version(root);
  manifest->media_type = oci_dup_str_field(root, "mediaType");

  const cJSON* cfg = cJSON_GetObjectItemCaseSensitive(root, "config");
  if (cJSON_IsObject(cfg)) {
    manifest->config_digest = oci_dup_str_field(cfg, "digest");
    const cJSON* sz = cJSON_GetObjectItemCaseSensitive(cfg, "size");
    if (cJSON_IsNumber(sz)) {
      manifest->config_size = (size_t) sz->valuedouble;
    }
  }

  const cJSON* layers = cJSON_GetObjectItemCaseSensitive(root, "layers");
  int n = cJSON_IsArray(layers) ? cJSON_GetArraySize(layers) : 0;
  if (n > 0) {
    manifest->layer_digests = calloc((size_t) n, sizeof(char*));
    if (manifest->layer_digests) {
      for (int i = 0; i < n; i++) {
        const cJSON* item = cJSON_GetArrayItem(layers, i);
        char* d = cJSON_IsObject(item) ? oci_dup_str_field(item, "digest") : NULL;
        manifest->layer_digests[manifest->layer_count++] = d ? d : strdup("");
      }
    }
  }

  cJSON_Delete(root);
  return BFC_OK;
}

// Get OCI config from BFC container
int bfc_get_oci_config(bfc_t* bfc, bfc_oci_config_t* config) {
  if (!bfc || !config) {
    return BFC_E_INVAL;
  }

  char* buf = NULL;
  size_t len = 0;
  int rc = oci_read_entry(bfc, "config.json", &buf, &len);
  if (rc != BFC_OK) {
    return rc;
  }

  cJSON* root = cJSON_ParseWithLength(buf, len);
  free(buf);
  if (!root) {
    return BFC_E_INVAL;
  }

  memset(config, 0, sizeof(*config));
  config->architecture = oci_dup_str_field(root, "architecture");
  config->os = oci_dup_str_field(root, "os");
  config->created = oci_dup_str_field(root, "created");
  config->author = oci_dup_str_field(root, "author");

  cJSON_Delete(root);
  return BFC_OK;
}

// List OCI layers in BFC container
int bfc_list_oci_layers(bfc_t* bfc, bfc_oci_layer_t** layers, size_t* layer_count) {
  if (!bfc || !layers || !layer_count) {
    return BFC_E_INVAL;
  }

  *layers = NULL;
  *layer_count = 0;

  char* buf = NULL;
  size_t len = 0;
  int rc = oci_read_entry(bfc, "manifest.json", &buf, &len);
  if (rc != BFC_OK) {
    return rc;
  }

  cJSON* root = cJSON_ParseWithLength(buf, len);
  free(buf);
  if (!root) {
    return BFC_E_INVAL;
  }

  const cJSON* arr = cJSON_GetObjectItemCaseSensitive(root, "layers");
  int n = cJSON_IsArray(arr) ? cJSON_GetArraySize(arr) : 0;
  if (n > 0) {
    bfc_oci_layer_t* out = calloc((size_t) n, sizeof(bfc_oci_layer_t));
    if (!out) {
      cJSON_Delete(root);
      return BFC_E_IO;
    }
    for (int i = 0; i < n; i++) {
      const cJSON* item = cJSON_GetArrayItem(arr, i);
      char* d = cJSON_IsObject(item) ? oci_dup_str_field(item, "digest") : NULL;
      out[i].digest = d ? d : strdup("");
      out[i].media_type = cJSON_IsObject(item) ? oci_dup_str_field(item, "mediaType") : NULL;
      const cJSON* sz =
          cJSON_IsObject(item) ? cJSON_GetObjectItemCaseSensitive(item, "size") : NULL;
      if (cJSON_IsNumber(sz)) {
        out[i].size = (size_t) sz->valuedouble;
      }
    }
    *layers = out;
    *layer_count = (size_t) n;
  }

  cJSON_Delete(root);
  return BFC_OK;
}

// Validate OCI manifest
int bfc_validate_oci_manifest(const bfc_oci_manifest_t* manifest) {
  if (!manifest) {
    return BFC_E_INVAL;
  }

  // Check required fields
  if (!manifest->schema_version || !manifest->media_type) {
    return BFC_E_INVAL;
  }

  // Validate schema version
  if (strcmp(manifest->schema_version, BFC_OCI_SCHEMA_VERSION) != 0) {
    return BFC_E_INVAL;
  }

  // Validate media type
  if (strcmp(manifest->media_type, BFC_OCI_MEDIA_TYPE_MANIFEST) != 0) {
    return BFC_E_INVAL;
  }

  return BFC_OK;
}

// Validate OCI config
int bfc_validate_oci_config(const bfc_oci_config_t* config) {
  if (!config) {
    return BFC_E_INVAL;
  }

  // Check required fields
  if (!config->architecture || !config->os) {
    return BFC_E_INVAL;
  }

  return BFC_OK;
}

// Free OCI manifest
void bfc_free_oci_manifest(bfc_oci_manifest_t* manifest) {
  if (!manifest)
    return;

  free(manifest->schema_version);
  free(manifest->media_type);
  free(manifest->config_digest);
  free(manifest->annotations);

  if (manifest->layer_digests) {
    for (size_t i = 0; i < manifest->layer_count; i++) {
      free(manifest->layer_digests[i]);
    }
    free(manifest->layer_digests);
  }

  // Ownership: the caller owns the struct (the getters fill a caller-provided
  // one, often a stack local), the library owns the fields. Zeroing makes a
  // second call safe.
  memset(manifest, 0, sizeof(*manifest));
}

// Free OCI config
void bfc_free_oci_config(bfc_oci_config_t* config) {
  if (!config)
    return;

  free(config->architecture);
  free(config->os);
  free(config->created);
  free(config->author);
  free(config->config);
  free(config->rootfs);
  free(config->history);

  memset(config, 0, sizeof(*config));
}

// Free OCI layer
void bfc_free_oci_layer(bfc_oci_layer_t* layer) {
  if (!layer)
    return;

  free(layer->digest);
  free(layer->media_type);
  free(layer->annotations);

  if (layer->urls) {
    for (size_t i = 0; i < layer->url_count; i++) {
      free(layer->urls[i]);
    }
    free(layer->urls);
  }

  memset(layer, 0, sizeof(*layer));
}

// Free OCI index
void bfc_free_oci_index(bfc_oci_index_t* index) {
  if (!index)
    return;

  free(index->schema_version);
  free(index->media_type);
  free(index->annotations);

  if (index->manifests) {
    for (size_t i = 0; i < index->manifest_count; i++) {
      // manifests[] is an array of individually-allocated pointers owned by the
      // index, so each one is released as well as its fields.
      bfc_free_oci_manifest(index->manifests[i]);
      free(index->manifests[i]);
    }
    free(index->manifests);
  }

  memset(index, 0, sizeof(*index));
}

// Free the contiguous layer array produced by bfc_list_oci_layers.
// Takes bfc_oci_layer_t* (one calloc'd block), NOT an array of pointers.
void bfc_free_oci_layers(bfc_oci_layer_t* layers, size_t layer_count) {
  if (!layers)
    return;

  for (size_t i = 0; i < layer_count; i++) {
    bfc_free_oci_layer(&layers[i]);
  }

  free(layers);
}
