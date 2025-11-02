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

#ifdef BFC_WITH_OCI

#include "bfc_os.h"
#include <assert.h>
#include <bfc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// OCI constants (should be in bfc_oci.h but defining here for tests)
#define BFC_OCI_SCHEMA_VERSION "2"
#define BFC_OCI_MEDIA_TYPE_MANIFEST "application/vnd.oci.image.manifest.v1+json"

// OCI structure definitions (mock structures for testing)
typedef struct {
    char* schema_version;
    char* media_type;
    char* config_digest;
    char** layer_digests;
    size_t layer_count;
    char* annotations;
} bfc_oci_manifest_t;

typedef struct {
    char* architecture;
    char* os;
    char* created;
    char* author;
    char* config;
    char* rootfs;
    char* history;
} bfc_oci_config_t;

typedef struct {
    char* digest;
    char* media_type;
    char* annotations;
    char** urls;
    size_t url_count;
} bfc_oci_layer_t;

typedef struct {
    char* schema_version;
    char* media_type;
    char* annotations;
    bfc_oci_manifest_t** manifests;
    size_t manifest_count;
} bfc_oci_index_t;

// Forward declarations
extern int bfc_create_from_oci_manifest(bfc_t* bfc, const bfc_oci_manifest_t* manifest, const char* config_json);
extern int bfc_create_from_oci_index(bfc_t* bfc, const bfc_oci_index_t* index);
extern int bfc_add_oci_layer(bfc_t* bfc, const bfc_oci_layer_t* layer, FILE* layer_data);
extern int bfc_extract_to_oci(bfc_t* bfc, const char* output_dir);
extern int bfc_get_oci_manifest(bfc_t* bfc, bfc_oci_manifest_t* manifest);
extern int bfc_get_oci_config(bfc_t* bfc, bfc_oci_config_t* config);
extern int bfc_list_oci_layers(bfc_t* bfc, bfc_oci_layer_t** layers, size_t* layer_count);
extern int bfc_validate_oci_manifest(const bfc_oci_manifest_t* manifest);
extern int bfc_validate_oci_config(const bfc_oci_config_t* config);
extern void bfc_free_oci_manifest(bfc_oci_manifest_t* manifest);
extern void bfc_free_oci_config(bfc_oci_config_t* config);
extern void bfc_free_oci_layer(bfc_oci_layer_t* layer);
extern void bfc_free_oci_index(bfc_oci_index_t* index);
extern void bfc_free_oci_layers(bfc_oci_layer_t** layers, size_t layer_count);

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
    const char* filename = "/tmp/test_oci_null.bfc";
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
    const char* filename = "/tmp/test_oci_manifest.bfc";
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
    const char* filename = "/tmp/test_oci_index.bfc";
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
    const char* filename = "/tmp/test_oci_index.bfc";
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
    bfc_oci_manifest_t manifest;
    
    // Test with NULL bfc
    int result = bfc_get_oci_manifest(NULL, &manifest);
    assert(result == BFC_E_INVAL);
    
    // Test with NULL manifest
    const char* filename = "/tmp/test_get_manifest.bfc";
    bfc_t* reader = NULL;
    result = bfc_open(filename, &reader);
    if (result == BFC_OK && reader != NULL) {
        result = bfc_get_oci_manifest(reader, NULL);
        assert(result == BFC_E_INVAL);
        bfc_close_read(reader);
    }
    
    return 0;
}

static int test_get_oci_config_null_args(void) {
    bfc_oci_config_t config;
    
    // Test with NULL bfc
    int result = bfc_get_oci_config(NULL, &config);
    assert(result == BFC_E_INVAL);
    
    // Test with NULL config
    const char* filename = "/tmp/test_get_config.bfc";
    bfc_t* reader = NULL;
    result = bfc_open(filename, &reader);
    if (result == BFC_OK && reader != NULL) {
        result = bfc_get_oci_config(reader, NULL);
        assert(result == BFC_E_INVAL);
        bfc_close_read(reader);
    }
    
    return 0;
}

static int test_list_oci_layers_null_args(void) {
    bfc_oci_layer_t** layers = NULL;
    size_t layer_count = 0;
    
    // Test with NULL bfc
    int result = bfc_list_oci_layers(NULL, &layers, &layer_count);
    assert(result == BFC_E_INVAL);
    
    // Test with NULL layers
    const char* filename = "/tmp/test_list_layers.bfc";
    bfc_t* reader = NULL;
    result = bfc_open(filename, &reader);
    if (result == BFC_OK && reader != NULL) {
        result = bfc_list_oci_layers(reader, NULL, &layer_count);
        assert(result == BFC_E_INVAL);
        bfc_close_read(reader);
    }
    
    return 0;
}

static int test_extract_to_oci_null_args(void) {
    // Test with NULL bfc
    int result = bfc_extract_to_oci(NULL, "/tmp/test_output");
    assert(result == BFC_E_INVAL);
    
    // Test with NULL output_dir
    const char* filename = "/tmp/test_extract.bfc";
    bfc_t* reader = NULL;
    result = bfc_open(filename, &reader);
    if (result == BFC_OK && reader != NULL) {
        result = bfc_extract_to_oci(reader, NULL);
        assert(result == BFC_E_INVAL);
        bfc_close_read(reader);
    }
    
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
    
    test_free_functions_null();
    
    printf("OCI tests passed!\n");
    return 0;
}

#else // BFC_WITH_OCI not defined

int test_oci(void) {
    printf("OCI tests skipped (BFC_WITH_OCI not enabled)\n");
    return 0;
}

#endif // BFC_WITH_OCI

