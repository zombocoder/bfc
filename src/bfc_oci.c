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
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// Create BFC container from OCI image manifest
int bfc_create_from_oci_manifest(bfc_t* bfc, const bfc_oci_manifest_t* manifest, const char* config_json) {
    if (!bfc || !manifest) {
        return BFC_E_INVAL;
    }
    
    // Add manifest.json to BFC
    if (bfc_add_file(bfc, "manifest.json", NULL, 0, 0, NULL) != BFC_OK) {
        return BFC_E_IO;
    }
    
    // Add config.json to BFC
    if (config_json) {
        FILE* config_file = fmemopen((void*)config_json, strlen(config_json), "r");
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
    
    // TODO: Implement OCI extraction
    // This would involve:
    // 1. Creating the OCI directory structure
    // 2. Extracting manifest.json
    // 3. Extracting config.json
    // 4. Extracting layer blobs
    
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
    if (!manifest) return;
    
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
    if (!config) return;
    
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
    if (!layer) return;
    
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
    if (!index) return;
    
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
    if (!layers) return;
    
    for (size_t i = 0; i < layer_count; i++) {
        bfc_free_oci_layer(layers[i]);
    }
    
    free(layers);
}
