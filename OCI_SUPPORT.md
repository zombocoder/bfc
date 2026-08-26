# BFC OCI Image Specs Support

This document describes the OCI (Open Container Initiative) Image Specs support added to BFC (Binary File Container).

## Overview

BFC now supports storing and managing OCI container images in its efficient single-file format. This allows BFC to be used as a storage backend for OCI-compliant container registries and image management systems.

## Features

- **OCI Manifest Support**: Store and manage OCI image manifests
- **OCI Config Support**: Store and manage OCI image configurations
- **OCI Layer Support**: Store and manage OCI image layers
- **OCI Index Support**: Store and manage OCI image indexes
- **Validation**: Validate OCI manifests and configs
- **Extraction**: Extract BFC containers to OCI format

## Building

OCI support is opt-in and **off by default**. Enable it with `-DBFC_WITH_OCI=ON`.
It requires **libcjson** (used to read manifests/configs back), detected via
pkg-config like the other optional dependencies:

```bash
# Debian/Ubuntu
sudo apt-get install libcjson-dev
# FreeBSD
sudo pkg install libcjson
# Windows (vcpkg)
vcpkg install cjson:x64-windows

cmake -B build -DBFC_WITH_OCI=ON
cmake --build build
```

### Memory ownership

The **caller owns the struct; the library owns the fields.** The `bfc_free_oci_*`
helpers release the fields and zero the struct — they never `free()` the struct
itself, so they are safe on stack locals:

```c
bfc_oci_manifest_t m = {0};
bfc_get_oci_manifest(bfc, &m);   /* fills m, allocates its fields */
bfc_free_oci_manifest(&m);       /* frees the fields only */
```

If you allocated the struct yourself, free it yourself after the helper returns.
`bfc_list_oci_layers()` is the exception that allocates a block: it returns one
contiguous array, released with `bfc_free_oci_layers(layers, count)`.

### Platform support

OCI support is **POSIX-only** for now: the implementation uses `fmemopen`,
two-argument `mkdir`, `<unistd.h>` and `<libgen.h>`, none of which exist under
MSVC. Linux, macOS and FreeBSD are supported; `-DBFC_WITH_OCI=ON` is not
expected to build on Windows/MSVC yet.

The write path serializes manifests/indexes to JSON; the read path
(`bfc_get_oci_manifest`/`bfc_get_oci_config`/`bfc_list_oci_layers`) parses them
back with libcjson.

## API Reference

### OCI Manifest Functions

```c
// Create BFC container from OCI image manifest
int bfc_create_from_oci_manifest(bfc_t* bfc, const bfc_oci_manifest_t* manifest, const char* config_json);

// Get OCI manifest from BFC container
int bfc_get_oci_manifest(bfc_t* bfc, bfc_oci_manifest_t* manifest);

// Validate OCI manifest
int bfc_validate_oci_manifest(const bfc_oci_manifest_t* manifest);
```

### OCI Layer Functions

```c
// Add OCI layer to BFC container
int bfc_add_oci_layer(bfc_t* bfc, const bfc_oci_layer_t* layer, FILE* layer_data);

// List OCI layers in BFC container
int bfc_list_oci_layers(bfc_t* bfc, bfc_oci_layer_t** layers, size_t* layer_count);
```

### OCI Index Functions

```c
// Create BFC container from OCI image index
int bfc_create_from_oci_index(bfc_t* bfc, const bfc_oci_index_t* index);
```

### Utility Functions

```c
// Extract BFC container to OCI format
int bfc_extract_to_oci(bfc_t* bfc, const char* output_dir);

// Free OCI structures
void bfc_free_oci_manifest(bfc_oci_manifest_t* manifest);
void bfc_free_oci_config(bfc_oci_config_t* config);
void bfc_free_oci_layer(bfc_oci_layer_t* layer);
void bfc_free_oci_index(bfc_oci_index_t* index);
void bfc_free_oci_layers(bfc_oci_layer_t* layers, size_t layer_count);
```

## Data Structures

### OCI Manifest

```c
typedef struct {
    char* schema_version;        // OCI schema version — always "2" per the image-spec
    char* media_type;            // Media type (e.g., "application/vnd.oci.image.manifest.v1+json")
    char* config_digest;         // SHA256 digest of config
    size_t config_size;          // Size of config in bytes
    char** layer_digests;        // Array of layer digests
    size_t layer_count;          // Number of layers
    char* annotations;           // JSON annotations
} bfc_oci_manifest_t;
```

### OCI Config

```c
typedef struct {
    char* architecture;          // Target architecture (e.g., "amd64")
    char* os;                    // Target OS (e.g., "linux")
    char* created;               // Creation timestamp
    char* author;                // Image author
    char* config;                // Container configuration
    char* rootfs;                // Root filesystem configuration
    char* history;               // Image history
} bfc_oci_config_t;
```

### OCI Layer

```c
typedef struct {
    char* digest;                // Layer digest (e.g., "sha256:abc123...")
    char* media_type;            // Layer media type
    size_t size;                 // Layer size in bytes
    char** urls;                 // Optional URLs for layer
    size_t url_count;            // Number of URLs
    char* annotations;           // Layer annotations
} bfc_oci_layer_t;
```

## Usage Example

```c
#include "bfc_oci.h"

int main() {
    // Create BFC container
    bfc_t* bfc = NULL;
    bfc_create("image.bfc", 4096, 0, &bfc);
    
    // Create OCI manifest
    bfc_oci_manifest_t* manifest = calloc(1, sizeof(bfc_oci_manifest_t));
    manifest->schema_version = strdup("2");
    manifest->media_type = strdup("application/vnd.oci.image.manifest.v1+json");
    manifest->config_digest = strdup("sha256:abc123...");
    manifest->config_size = 1024;
    manifest->layer_count = 1;
    manifest->layer_digests = calloc(1, sizeof(char*));
    manifest->layer_digests[0] = strdup("sha256:def456...");
    
    // Add manifest to BFC
    bfc_create_from_oci_manifest(bfc, manifest, "{\"architecture\":\"amd64\"}");
    
    // Add layer
    bfc_oci_layer_t* layer = calloc(1, sizeof(bfc_oci_layer_t));
    layer->digest = strdup("sha256:def456...");
    layer->media_type = strdup("application/vnd.oci.image.layer.v1.tar+gzip");
    layer->size = 1024 * 1024;
    
    FILE* layer_data = fopen("layer.tar.gz", "rb");
    bfc_add_oci_layer(bfc, layer, layer_data);
    fclose(layer_data);
    
    // Finish container
    bfc_finish(bfc);
    bfc_close(bfc);
    
    // Cleanup: the helpers release the FIELDS; these structs were malloc'd
    // by us, so we release them ourselves.
    bfc_free_oci_manifest(manifest);
    free(manifest);
    bfc_free_oci_layer(layer);
    free(layer);
    
    return 0;
}
```

## Building with OCI Support

OCI support is built through CMake (see **Building** above) — the module lives at
`src/lib/bfc_oci.c` and is compiled only when `BFC_WITH_OCI=ON`:

```bash
cmake -B build -DBFC_WITH_OCI=ON && cmake --build build
```

## Integration with Container Runtimes

BFC with OCI support can be integrated with:

- **Docker**: Use BFC as a storage backend for Docker images
- **Podman**: Use BFC as a storage backend for Podman images
- **containerd**: Use BFC as a storage backend for containerd
- **CRI-O**: Use BFC as a storage backend for CRI-O
- **Custom Runtimes**: Use BFC as a storage backend for custom container runtimes

## Benefits

1. **Efficiency**: Single file storage for entire OCI images
2. **Compression**: Built-in zstd compression support
3. **Encryption**: Built-in ChaCha20-Poly1305 encryption support
4. **Integrity**: Built-in CRC32c checksums
5. **Portability**: Easy to copy and transfer OCI images
6. **ZFS Integration**: Works well with ZFS snapshots and clones

## Future Enhancements

- **Registry Integration**: Direct integration with OCI registries
- **Layer Deduplication**: Automatic deduplication of identical layers
- **Compression Optimization**: Automatic compression level selection
- **Encryption Key Management**: Advanced encryption key management
- **Metadata Indexing**: Fast metadata search and indexing

## Contributing

Contributions to OCI support are welcome! Please see the main BFC repository for contribution guidelines.

## License

This OCI support code is licensed under the Apache License 2.0, same as the main BFC project.
