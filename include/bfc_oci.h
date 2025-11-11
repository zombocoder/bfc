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

#pragma once
#include "bfc.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// OCI Image Specs support for BFC
// This header provides functions to work with BFC as an OCI image storage format

// OCI Image Manifest structure
typedef struct {
  char* schema_version;
  char* media_type;
  char* config_digest;
  size_t config_size;
  char** layer_digests;
  size_t layer_count;
  char* annotations;
} bfc_oci_manifest_t;

// OCI Image Config structure
typedef struct {
  char* architecture;
  char* os;
  char* created;
  char* author;
  char* config;
  char* rootfs;
  char* history;
} bfc_oci_config_t;

// OCI Layer structure
typedef struct {
  char* digest;
  char* media_type;
  size_t size;
  char** urls;
  size_t url_count;
  char* annotations;
} bfc_oci_layer_t;

// OCI Image Index structure
typedef struct {
  char* schema_version;
  char* media_type;
  bfc_oci_manifest_t** manifests;
  size_t manifest_count;
  char* annotations;
} bfc_oci_index_t;

// OCI Image functions

/// Create BFC container from OCI image manifest
int bfc_create_from_oci_manifest(bfc_t* bfc, const bfc_oci_manifest_t* manifest,
                                 const char* config_json);

/// Create BFC container from OCI image index
int bfc_create_from_oci_index(bfc_t* bfc, const bfc_oci_index_t* index);

/// Add OCI layer to BFC container
int bfc_add_oci_layer(bfc_t* bfc, const bfc_oci_layer_t* layer, FILE* layer_data);

/// Extract BFC container to OCI format
int bfc_extract_to_oci(bfc_t* bfc, const char* output_dir);

/// Get OCI manifest from BFC container
int bfc_get_oci_manifest(bfc_t* bfc, bfc_oci_manifest_t* manifest);

/// Get OCI config from BFC container
int bfc_get_oci_config(bfc_t* bfc, bfc_oci_config_t* config);

/// List OCI layers in BFC container
int bfc_list_oci_layers(bfc_t* bfc, bfc_oci_layer_t** layers, size_t* layer_count);

/// Validate OCI manifest
int bfc_validate_oci_manifest(const bfc_oci_manifest_t* manifest);

/// Validate OCI config
int bfc_validate_oci_config(const bfc_oci_config_t* config);

/// Free OCI manifest
void bfc_free_oci_manifest(bfc_oci_manifest_t* manifest);

/// Free OCI config
void bfc_free_oci_config(bfc_oci_config_t* config);

/// Free OCI layer
void bfc_free_oci_layer(bfc_oci_layer_t* layer);

/// Free OCI index
void bfc_free_oci_index(bfc_oci_index_t* index);

/// Free OCI layers array
void bfc_free_oci_layers(bfc_oci_layer_t** layers, size_t layer_count);

// OCI Image Specs constants
#define BFC_OCI_MEDIA_TYPE_MANIFEST "application/vnd.oci.image.manifest.v1+json"
#define BFC_OCI_MEDIA_TYPE_CONFIG "application/vnd.oci.image.config.v1+json"
#define BFC_OCI_MEDIA_TYPE_LAYER "application/vnd.oci.image.layer.v1.tar+gzip"
#define BFC_OCI_MEDIA_TYPE_LAYER_GZIP "application/vnd.oci.image.layer.v1.tar+gzip"
#define BFC_OCI_MEDIA_TYPE_LAYER_ZSTD "application/vnd.oci.image.layer.v1.tar+zstd"
#define BFC_OCI_MEDIA_TYPE_INDEX "application/vnd.oci.image.index.v1+json"

#define BFC_OCI_SCHEMA_VERSION "2.0.1"

#ifdef __cplusplus
}
#endif
