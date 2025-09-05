# BFC - Binary File Container

[![CI](https://github.com/zombocoder/bfc/actions/workflows/ci.yml/badge.svg)](https://github.com/zombocoder/bfc/actions/workflows/ci.yml)
[![Release](https://github.com/zombocoder/bfc/actions/workflows/release.yml/badge.svg)](https://github.com/zombocoder/bfc/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![C17](https://img.shields.io/badge/C-C17-blue.svg)](<https://en.wikipedia.org/wiki/C17_(C_standard_revision)>)

A high-performance, single-file container format for storing files and directories with complete POSIX metadata preservation.

## Features

- **Single-file containers** - Everything in one `.bfc` file
- **POSIX metadata** - Preserves permissions, timestamps, and file types
- **Fast random access** - O(log N) file lookup with sorted index
- **Optional compression** - ZSTD compression with intelligent content analysis
- **Integrity validation** - CRC32C checksums with hardware acceleration
- **Cross-platform** - Works on Linux, macOS, and other Unix systems
- **Crash-safe writes** - Atomic container creation with index at EOF
- **Memory efficient** - Optimized for large containers and small memory footprint

## Quick Start

```bash
# Build the project
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Create a container
./build/bin/bfc create archive.bfc /path/to/files/

# List contents
./build/bin/bfc list archive.bfc

# Extract files
./build/bin/bfc extract archive.bfc

# Verify integrity
./build/bin/bfc verify --deep archive.bfc

# Get detailed information
./build/bin/bfc info archive.bfc
```

## Installation

### Prerequisites

- C17 compatible compiler (GCC 7+, Clang 6+)
- CMake 3.10+
- POSIX-compliant system

### Build from source

```bash
git clone https://github.com/zombocoder/bfc.git
cd bfc

# Debug build
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Release build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Install system-wide
sudo cmake --install build --prefix /usr/local
```

### Build options

```bash
# Enable optional features
cmake -B build -DBFC_WITH_FUSE=ON -DBFC_WITH_ZSTD=ON
cmake --build build

# Enable code coverage
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBFC_COVERAGE=ON
cmake --build build
cmake --build build --target coverage
```

## CLI Usage

### Creating containers

```bash
# Create from directory
bfc create documents.bfc ~/Documents/

# Create from multiple sources
bfc create backup.bfc file1.txt file2.txt ~/Pictures/ ~/Music/

# Custom block size (default: 4096)
bfc create -b 8192 archive.bfc /data/

# Force overwrite existing container
bfc create -f archive.bfc /path/to/files/
```

### Compression support

BFC supports optional file compression to reduce storage space. When built with ZSTD support (`-DBFC_WITH_ZSTD=ON`), containers can automatically compress files based on content analysis.

```bash
# Enable ZSTD compression (default level: 3)
bfc create -c zstd archive.bfc /path/to/files/

# Set specific compression level (1-22, higher = better compression)
bfc create -c zstd -l 6 archive.bfc /path/to/files/

# Set compression threshold (only compress files larger than size)
bfc create -c zstd -t 1024 archive.bfc /path/to/files/

# Disable compression explicitly
bfc create -c none archive.bfc /path/to/files/

# View compression information
bfc info archive.bfc path/to/file.txt
# Shows:
#   Compression: zstd
#   Size: 1048576 bytes (1.0 MiB)
#   Stored size: 524288 bytes (512.0 KiB)
#   Storage ratio: 50.0%
#   Compression ratio: 50.0%
```

**Compression behavior:**
- **Automatic detection** - BFC analyzes file content to recommend compression
- **Small file threshold** - Files smaller than 64 bytes are never compressed
- **Content analysis** - Text files, repetitive data, and files with patterns compress well
- **Transparent extraction** - Compressed files are automatically decompressed on extraction
- **Integrity validation** - CRC32C checksums protect both original and compressed data

### Listing contents

```bash
# Simple listing
bfc list archive.bfc

# Long format (like ls -l)
bfc list -l archive.bfc

# Show file sizes and checksums
bfc list -sc archive.bfc

# Filter by path prefix
bfc list archive.bfc docs/
```

### Extracting files

```bash
# Extract all files to current directory
bfc extract archive.bfc

# Extract to specific directory
bfc extract -C /tmp archive.bfc

# Extract specific files/directories
bfc extract archive.bfc docs/ README.txt

# Preserve full directory paths
bfc extract -k archive.bfc

# Force overwrite existing files
bfc extract -f archive.bfc
```

### Container information

```bash
# Basic container info
bfc info archive.bfc

# Detailed listing with metadata
bfc info -d archive.bfc

# Information about specific file
bfc info archive.bfc path/to/file.txt
```

### Verifying integrity

```bash
# Quick structural verification
bfc verify archive.bfc

# Deep verification (check all file contents)
bfc verify --deep archive.bfc

# Show progress for large containers
bfc verify -p --deep archive.bfc
```

## Library Usage

BFC provides a C library for integration into other applications.

### Basic example

```c
#include <bfc.h>

// Create a container
bfc_t *writer;
bfc_create("archive.bfc", 4096, 0, &writer);

// Add files
FILE *file = fopen("document.txt", "rb");
uint32_t crc;
bfc_add_file(writer, "document.txt", file, 0644, time_ns, &crc);
fclose(file);

// Add directories
bfc_add_dir(writer, "docs", 0755, time_ns);

// Finalize
bfc_finish(writer);
bfc_close(writer);

// Read container
bfc_t *reader;
bfc_open("archive.bfc", &reader);

// List entries
bfc_list(reader, NULL, callback, userdata);

// Extract file
int fd = open("output.txt", O_WRONLY | O_CREAT, 0644);
bfc_extract_to_fd(reader, "document.txt", fd);
close(fd);

bfc_close_read(reader);
```

See the [examples/](examples/) directory for complete examples.

## File Format

BFC uses a simple, efficient binary format:

```
[Header 4 KiB] → [Data Objects...] → [Index] → [Footer 56B]
```

- **Header**: Magic, version, features, UUID (first 4 KiB)
- **Data Objects**: Type-length-value encoding, 16-byte aligned
- **Index**: Sorted entries for O(log N) lookup, stored at EOF
- **Footer**: Index location and validation data (last 56 bytes)

Key design features:

- **Append-only writes** for crash safety
- **Index at EOF** for fast container opening
- **CRC32C validation** on all data
- **UTF-8 path encoding** with normalization
- **16-byte alignment** for performance

## Performance

Performance targets on modern hardware:

- **Write**: ≥300 MB/s for 1 MiB files
- **Read**: ≥1 GB/s sequential, ≥50 MB/s random 4 KiB
- **List**: ≤1 ms for directories with ≤1024 entries
- **Index load**: ≤5 ms for 100K entries on NVMe SSD

## Testing

```bash
# Run all tests
cmake --build build --target test

# Run specific test suites
ctest --test-dir build -R unit
ctest --test-dir build -R fuzz
ctest --test-dir build -R golden

# Run with verbose output
ctest --test-dir build --verbose

# Run benchmarks
cd build/benchmarks
./bench_write
./bench_read
./bench_list
```

## Development

### Code style

```bash
# Format code
find src include tests -name "*.c" -o -name "*.h" | xargs clang-format -i

# Static analysis
clang-tidy src/**/*.c include/**/*.h
```

### Debugging

```bash
# Build with debug info
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run with GDB
gdb ./build/bin/bfc
```

### Fuzzing

```bash
cd build/tests/fuzz
./fuzz_open_index corpus/
./fuzz_paths corpus/
```

## Security

BFC implements several security measures:

- **Path traversal prevention** with strict normalization
- **Safe extraction** using `O_NOFOLLOW` and parent directory validation
- **CRC32C validation** on all read operations
- **Bounds checking** on all buffer operations
- **No arbitrary code execution** - pure data format

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes with tests
4. Run the test suite: `cmake --build build --target test`
5. Submit a pull request

Please follow the existing code style and add tests for new functionality.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2025 zombocoder (Taras Havryliak)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Changelog

### v1.0.0

- Initial release
- Complete CLI tool with create, list, extract, info, verify commands
- C library with full read/write API
- Hardware-accelerated CRC32C
- Comprehensive test suite
- Cross-platform support (Linux, macOS)
- Performance optimizations
- Security hardening

## Support

- **Documentation**: See [docs/](docs/) directory
- **Examples**: See [examples/](examples/) directory
- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Use GitHub Discussions for questions

BFC focuses on simplicity, performance, and POSIX metadata preservation for modern systems.
