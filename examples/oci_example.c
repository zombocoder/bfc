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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bfc_oci.h"

int main() {
    printf("BFC OCI Image Specs Example\n");
    
    // Create BFC container
    bfc_t* bfc = NULL;
    if (bfc_create("example.bfc", 4096, 0, &bfc) != BFC_OK) {
        fprintf(stderr, "Failed to create BFC container\n");
        return 1;
    }
    
    // Create OCI manifest
    bfc_oci_manifest_t* manifest = calloc(1, sizeof(bfc_oci_manifest_t));
    if (!manifest) {
        fprintf(stderr, "Failed to allocate manifest\n");
        bfc_close(bfc);
        return 1;
    }
    
    manifest->schema_version = strdup("2.0.1");
    manifest->media_type = strdup("application/vnd.oci.image.manifest.v1+json");
    manifest->config_digest = strdup("sha256:abc123...");
    manifest->config_size = 1024;
    manifest->layer_count = 2;
    manifest->layer_digests = calloc(2, sizeof(char*));
    manifest->layer_digests[0] = strdup("sha256:def456...");
    manifest->layer_digests[1] = strdup("sha256:ghi789...");
    manifest->annotations = strdup("{}");
    
    // Create OCI config
    const char* config_json = "{\"architecture\":\"amd64\",\"os\":\"linux\"}";
    
    // Add manifest to BFC
    if (bfc_create_from_oci_manifest(bfc, manifest, config_json) != BFC_OK) {
        fprintf(stderr, "Failed to add OCI manifest to BFC\n");
        bfc_free_oci_manifest(manifest);
        bfc_close(bfc);
        return 1;
    }
    
    // Add OCI layers
    bfc_oci_layer_t* layer1 = calloc(1, sizeof(bfc_oci_layer_t));
    layer1->digest = strdup("sha256:def456...");
    layer1->media_type = strdup("application/vnd.oci.image.layer.v1.tar+gzip");
    layer1->size = 1024 * 1024; // 1MB
    
    // Create dummy layer data
    FILE* layer_data = tmpfile();
    if (!layer_data) {
        fprintf(stderr, "Failed to create layer data\n");
        bfc_free_oci_layer(layer1);
        bfc_free_oci_manifest(manifest);
        bfc_close(bfc);
        return 1;
    }
    
    // Write dummy data to layer
    const char* dummy_data = "dummy layer data";
    fwrite(dummy_data, 1, strlen(dummy_data), layer_data);
    rewind(layer_data);
    
    // Add layer to BFC
    if (bfc_add_oci_layer(bfc, layer1, layer_data) != BFC_OK) {
        fprintf(stderr, "Failed to add OCI layer to BFC\n");
        fclose(layer_data);
        bfc_free_oci_layer(layer1);
        bfc_free_oci_manifest(manifest);
        bfc_close(bfc);
        return 1;
    }
    
    fclose(layer_data);
    
    // Finish BFC container
    if (bfc_finish(bfc) != BFC_OK) {
        fprintf(stderr, "Failed to finish BFC container\n");
        bfc_free_oci_layer(layer1);
        bfc_free_oci_manifest(manifest);
        bfc_close(bfc);
        return 1;
    }
    
    printf("Successfully created BFC container with OCI image specs\n");
    
    // Cleanup
    bfc_free_oci_layer(layer1);
    bfc_free_oci_manifest(manifest);
    bfc_close(bfc);
    
    return 0;
}
