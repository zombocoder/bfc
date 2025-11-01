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

#include "bfc_oci.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

  // Add manifest.json to BFC
  if (bfc_add_file(bfc, "manifest.json", NULL, 0, 0, NULL) != BFC_OK) {
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

  // Add index.json to BFC
  if (bfc_add_file(bfc, "index.json", NULL, 0, 0, NULL) != BFC_OK) {
    return BFC_E_IO;
  }

  return BFC_OK;
}

// Add OCI layer to BFC container
int bfc_add_oci_layer(bfc_t* bfc, const bfc_oci_layer_t* layer, FILE* layer_data) {
  if (!bfc || !layer || !layer_data) {
    return BFC_E_INVAL;
  }

  // Create layer path from digest
  char layer_path[256];
  snprintf(layer_path, sizeof(layer_path), "blobs/sha256/%s", layer->digest);

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

  // Create OCI directory structure
  char oci_dir[1024];
  snprintf(oci_dir, sizeof(oci_dir), "%s/oci", output_dir);

  if (mkdir(oci_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Create blobs directory
  char blobs_dir[1024];
  snprintf(blobs_dir, sizeof(blobs_dir), "%s/blobs", oci_dir);

  if (mkdir(blobs_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Create sha256 subdirectory
  char sha256_dir[1024];
  snprintf(sha256_dir, sizeof(sha256_dir), "%s/sha256", blobs_dir);

  if (mkdir(sha256_dir, 0755) != 0 && errno != EEXIST) {
    return BFC_E_IO;
  }

  // Extract OCI manifest
  char manifest_path[1024];
  snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", oci_dir);

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
  snprintf(config_path, sizeof(config_path), "%s/config.json", oci_dir);

  int config_fd = open(config_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (config_fd < 0) {
    return BFC_E_IO;
  }

  result = bfc_extract_to_fd(bfc, "config.json", config_fd);
  close(config_fd);

  if (result != BFC_OK) {
    return result;
  }

  // Extract layer blobs using callback approach
  struct extract_context ctx = {0};
  result = bfc_list(bfc, "layers/", collect_files, &ctx);
  if (result != BFC_OK) {
    cleanup_extract_context(&ctx);
    return result;
  }

  printf("Found %d layer files to extract\n", ctx.count);

  for (int i = 0; i < ctx.count; i++) {
    const char* file_path = ctx.files[i];
    printf("Extracting layer: %s\n", file_path);

    // Create output path in blobs/sha256/
    char output_path[1024];
    snprintf(output_path, sizeof(output_path), "%s/%s", sha256_dir, file_path);

    // Create parent directories if needed
    char* path_copy = strdup(output_path);
    if (!path_copy) {
      cleanup_extract_context(&ctx);
      return BFC_E_NOTFOUND;
    }

    char* dir = dirname(path_copy);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
      free(path_copy);
      cleanup_extract_context(&ctx);
      return BFC_E_IO;
    }
    free(path_copy);

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

  // TODO: Implement manifest extraction
  // This would involve reading manifest.json from BFC

  return BFC_OK;
}

// Get OCI config from BFC container
int bfc_get_oci_config(bfc_t* bfc, bfc_oci_config_t* config) {
  if (!bfc || !config) {
    return BFC_E_INVAL;
  }

  // TODO: Implement config extraction
  // This would involve reading config.json from BFC

  return BFC_OK;
}

// List OCI layers in BFC container
int bfc_list_oci_layers(bfc_t* bfc, bfc_oci_layer_t** layers, size_t* layer_count) {
  if (!bfc || !layers || !layer_count) {
    return BFC_E_INVAL;
  }

  // TODO: Implement layer listing
  // This would involve parsing manifest.json and listing layer blobs

  *layers = NULL;
  *layer_count = 0;

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

  free(manifest);
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

  free(config);
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

  free(layer);
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
      bfc_free_oci_manifest(index->manifests[i]);
    }
    free(index->manifests);
  }

  free(index);
}

// Free OCI layers array
void bfc_free_oci_layers(bfc_oci_layer_t** layers, size_t layer_count) {
  if (!layers)
    return;

  for (size_t i = 0; i < layer_count; i++) {
    bfc_free_oci_layer(layers[i]);
  }

  free(layers);
}
