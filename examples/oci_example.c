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

static const char* detect_os(void) {
    // Map OS to OCI "os" names
    #if defined(__linux__)
        return "linux";
    #elif defined(_WIN32)
        return "windows";
    #elif defined(__APPLE__) && defined(__MACH__)
        return "darwin";
    #elif defined(__FreeBSD__)
        return "freebsd";
    #elif defined(__OpenBSD__)
        return "openbsd";
    #elif defined(__NetBSD__)
        return "netbsd";
    #else
        return "unknown";
    #endif
}

static const char* detect_arch(void) {
    // Map common compiler macros to OCI arch names
    #if defined(__x86_64__) || defined(_M_X64)
        return "amd64";
    #elif defined(__aarch64__) || defined(_M_ARM64)
        return "arm64";
    #elif defined(__i386__) || defined(_M_IX86)
        return "386";
    #elif defined(__ppc64le__)
        return "ppc64le";
    #elif defined(__ppc64__)
        return "ppc64";
    #elif defined(__riscv) || defined(__riscv__)
        #if defined(__riscv_xlen) && __riscv_xlen == 64
            return "riscv64";
        #else
            return "riscv"; // fallback
        #endif
    #else
        return "unknown";
    #endif
}

static int build_oci_config_json(char **out_json) {
    if (!out_json) return -1;
    const char *arch = detect_arch();
    const char *os   = detect_os();

    // 2 keys + quotes + punctuation; 64 is plenty of slack
    size_t need = strlen(arch) + strlen(os) + 64;
    char *buf = (char*)malloc(need);
    if (!buf) return -1;

    // You can add more fields here later (env, cmd, rootfs, etc.)
    // Keep it minimal for your example.
    int n = snprintf(buf, need,
                     "{\"architecture\":\"%s\",\"os\":\"%s\"}",
                     arch, os);
    if (n < 0 || (size_t)n >= need) { free(buf); return -1; }

    *out_json = buf;
    return 0;
}

int main() {
    printf("BFC OCI Image Specs Example\n");
    
    // Detect current architecture and OS
    const char *arch = detect_arch();
    const char *os = detect_os();
    printf("Detected architecture: %s, OS: %s\n", arch, os);
    
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
    
    // Create OCI config (dynamic)
    char *config_json = NULL;
    if (build_oci_config_json(&config_json) != 0) {
        fprintf(stderr, "Failed to build OCI config JSON\n");
        // clean up and return...
        bfc_close(bfc);
        free(manifest->schema_version);
        free(manifest->media_type);
        free(manifest->config_digest);
        free(manifest->layer_digests[0]);
        free(manifest->layer_digests[1]);
        free(manifest->layer_digests);
        free(manifest->annotations);
        free(manifest);
        return 1;
    }
    
    printf("Using config: %s\n", config_json);
    
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
    free(config_json);
    bfc_free_oci_layer(layer1);
    bfc_free_oci_manifest(manifest);
    bfc_close(bfc);
    
    return 0;
}
