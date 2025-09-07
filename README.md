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
- **Optional encryption** - ChaCha20-Poly1305 AEAD with Argon2id key derivation
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
- CMake 3.15+
- POSIX-compliant system

**Optional dependencies:**
- ZSTD library for compression support
- libsodium for encryption support

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
# Enable compression and encryption (recommended)
cmake -B build -DBFC_WITH_ZSTD=ON -DBFC_WITH_SODIUM=ON
cmake --build build

# Enable all optional features (requires macFUSE/FUSE3 installation)
cmake -B build -DBFC_WITH_FUSE=ON -DBFC_WITH_ZSTD=ON -DBFC_WITH_SODIUM=ON
cmake --build build

# Enable individual features
cmake -B build -DBFC_WITH_ZSTD=ON        # Compression only
cmake -B build -DBFC_WITH_SODIUM=ON      # Encryption only  
cmake -B build -DBFC_WITH_FUSE=ON        # FUSE filesystem support

# Enable code coverage
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBFC_COVERAGE=ON
cmake --build build
cmake --build build --target coverage
```

## CLI Usage

### Global Options

All commands support these global options:

```bash
-v, --verbose      Enable verbose output showing detailed operations
-q, --quiet        Suppress non-error output (only show errors)
-h, --help         Show help message for the command
--version          Show version information
```

### Creating containers

The `create` command builds new BFC containers from files and directories.

**Syntax:** `bfc create [options] <container.bfc> <input-paths...>`

**Options:**
- `-b, --block-size SIZE` - Set container block size (default: 4096 bytes)
- `-f, --force` - Overwrite existing container file
- `-c, --compression TYPE` - Compression: `none`, `zstd`, `auto` (default: none)
- `-l, --compression-level N` - Compression level for ZSTD (1-22, default: 3)
- `-t, --compression-threshold SIZE` - Minimum file size to compress (default: 64 bytes)
- `-e, --encrypt PASSWORD` - Encrypt files with password (requires libsodium)
- `-k, --keyfile FILE` - Encrypt with 32-byte key from file (requires libsodium)

**Examples:**
```bash
# Create from directory
bfc create documents.bfc ~/Documents/

# Create from multiple sources  
bfc create backup.bfc file1.txt file2.txt ~/Pictures/ ~/Music/

# Custom block size (for performance tuning)
bfc create -b 8192 archive.bfc /data/

# Force overwrite existing container
bfc create -f archive.bfc /path/to/files/

# Create with compression
bfc create -c zstd archive.bfc /data/
bfc create -c zstd -l 9 archive.bfc /data/  # Maximum compression

# Create with encryption
bfc create -e mypassword secure.bfc /sensitive/data/
bfc create -k secret.key secure.bfc /sensitive/data/

# Combined compression and encryption
bfc create -c zstd -e secret -l 6 archive.bfc /data/
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

### Encryption support

BFC supports optional file encryption using industry-standard ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) with Argon2id key derivation. When built with libsodium support (`-DBFC_WITH_SODIUM=ON`), containers can encrypt individual files with strong cryptographic protection.

```bash
# Password-based encryption
bfc create -e mypassword secure.bfc /sensitive/data/

# Key file encryption (32 bytes)
echo -n "0123456789abcdef0123456789abcdef" > secret.key
bfc create -k secret.key secure.bfc /sensitive/data/

# Combine encryption with compression
bfc create -e mypassword -c zstd archive.bfc /data/

# Extract encrypted container with password
bfc extract -p mypassword secure.bfc

# Extract with key file
bfc extract -K secret.key secure.bfc

# View encryption status
bfc info secure.bfc
bfc info secure.bfc path/to/file.txt
# Shows:
#   Encryption: ChaCha20-Poly1305
#   Size: 1048576 bytes (1.0 MiB)
#   Stored size: 1048592 bytes (16 bytes overhead)
```

**Encryption behavior:**
- **Strong cryptography** - ChaCha20-Poly1305 AEAD with 256-bit keys and 96-bit nonces
- **Key derivation** - Argon2id with configurable parameters for password-based encryption
- **Per-file encryption** - Each file encrypted independently with unique nonces
- **Authenticated encryption** - Built-in integrity validation prevents tampering
- **Metadata protection** - File paths and metadata remain in plaintext (container structure visible)
- **Transparent operation** - Works seamlessly with compression (compress → encrypt pipeline)
- **Memory security** - Keys securely cleared from memory after use

**Security considerations:**
- Container structure and file names are **not encrypted** - only file contents
- Use strong passwords (≥20 characters) or properly generated key files
- Key derivation uses memory-hard Argon2id to resist brute-force attacks
- Store key files securely and separately from encrypted containers

### Listing contents

The `list` command displays container contents with various formatting options.

**Syntax:** `bfc list [options] <container.bfc> [path]`

**Options:**
- `-l, --long` - Use long listing format (like `ls -l`) showing permissions, size, date
- `-s, --size` - Show file sizes in human-readable format  
- `-c, --checksum` - Show CRC32C checksums for integrity verification
- Combine options: `-sc` shows both sizes and checksums

**Examples:**
```bash
# Simple listing (names only)
bfc list archive.bfc

# Long format with permissions, size, and timestamps
bfc list -l archive.bfc

# Show file sizes and checksums
bfc list -sc archive.bfc

# Filter by path prefix or directory
bfc list archive.bfc docs/
bfc list archive.bfc docs/readme.txt

# Combined: long format with sizes and checksums
bfc list -lsc archive.bfc
```

### Extracting files

The `extract` command extracts files and directories from containers.

**Syntax:** `bfc extract [options] <container.bfc> [paths...]`

**Options:**
- `-C, --directory DIR` - Extract to specific directory (changes to DIR before extracting)
- `-f, --force` - Overwrite existing files without prompting
- `-k, --keep-paths` - Preserve full directory structure (default: flatten to basenames)
- `-p, --password PASS` - Provide password for encrypted containers
- `-K, --keyfile FILE` - Use key file for encrypted containers (32 bytes)

**Examples:**
```bash
# Extract all files to current directory (flattened)
bfc extract archive.bfc

# Extract to specific directory
bfc extract -C /tmp/extracted archive.bfc

# Extract preserving directory structure
bfc extract -k archive.bfc

# Extract specific files/directories only
bfc extract archive.bfc docs/ README.txt

# Force overwrite existing files
bfc extract -f archive.bfc

# Extract encrypted container with password
bfc extract -p mypassword secure.bfc

# Extract encrypted container with key file  
bfc extract -K secret.key secure.bfc

# Combined: extract to directory, preserve paths, force overwrite
bfc extract -kf -C /tmp/output archive.bfc
```

### Container information

The `info` command displays detailed information about containers and individual files.

**Syntax:** `bfc info [options] <container.bfc> [path]`

**Options:**
- `-d, --detailed` - Show detailed information including compression ratios, encryption status

**Examples:**
```bash
# Basic container summary
bfc info archive.bfc

# Detailed container information
bfc info -d archive.bfc

# Information about specific file
bfc info archive.bfc path/to/file.txt

# Detailed info about specific file (shows compression, encryption)
bfc info -d archive.bfc path/to/file.txt
```

### Verifying integrity

The `verify` command checks container and file integrity.

**Syntax:** `bfc verify [options] <container.bfc>`

**Options:**
- `--deep` - Perform deep verification (read and verify all file contents, slower but thorough)
- `-p, --progress` - Show progress bar during verification (useful for large containers)

**Examples:**
```bash
# Quick structural verification (fast)
bfc verify archive.bfc

# Deep verification checking all file contents (slower but complete)
bfc verify --deep archive.bfc

# Deep verification with progress indicator
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

// Optional: Enable compression
bfc_set_compression(writer, BFC_COMP_ZSTD, 3);

// Optional: Enable encryption
bfc_set_encryption_password(writer, "my_password", 11);
// or use key file:
// uint8_t key[32] = {...}; // 32-byte key
// bfc_set_encryption_key(writer, key);

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

// For encrypted containers, set decryption key
bfc_set_encryption_password(reader, "my_password", 11);

// List entries
bfc_list(reader, NULL, callback, userdata);

// Extract file
int fd = open("output.txt", O_WRONLY | O_CREAT, 0644);
bfc_extract_to_fd(reader, "document.txt", fd);
close(fd);

bfc_close_read(reader);
```

See the [examples/](examples/) directory for complete examples.

## CLI Reference

### Quick Reference

**Global Options** (available for all commands):
```
-v, --verbose      Enable verbose output
-q, --quiet        Suppress non-error output  
-h, --help         Show help message
--version          Show version information
```

**Commands Summary:**

| Command | Purpose | Key Options |
|---------|---------|-------------|
| `create` | Build new container | `-c` (compression), `-e` (encrypt), `-f` (force) |
| `list` | Show contents | `-l` (long format), `-s` (sizes), `-c` (checksums) |
| `extract` | Extract files | `-C` (directory), `-k` (keep paths), `-p` (password) |
| `info` | Container info | `-d` (detailed) |
| `verify` | Check integrity | `--deep` (full check), `-p` (progress) |

### Complete Option Reference

**`bfc create [options] <container.bfc> <input-paths...>`**
```
-b, --block-size SIZE       Block size (default: 4096)
-f, --force                 Overwrite existing container
-c, --compression TYPE      none|zstd|auto (default: none)
-l, --compression-level N   ZSTD level 1-22 (default: 3)
-t, --compression-threshold SIZE  Min size to compress (default: 64)
-e, --encrypt PASSWORD      Encrypt with password
-k, --keyfile FILE          Encrypt with key file (32 bytes)
```

**`bfc list [options] <container.bfc> [path]`**
```
-l, --long         Long format (permissions, size, date)
-s, --size         Show file sizes
-c, --checksum     Show CRC32C checksums
```

**`bfc extract [options] <container.bfc> [paths...]`**
```
-C, --directory DIR    Extract to specific directory
-f, --force           Overwrite existing files
-k, --keep-paths      Preserve directory structure
-p, --password PASS   Password for encrypted containers
-K, --keyfile FILE    Key file for encrypted containers
```

**`bfc info [options] <container.bfc> [path]`**
```
-d, --detailed        Show detailed information
```

**`bfc verify [options] <container.bfc>`**
```
--deep                Deep verification (check all content)
-p, --progress        Show progress indicator
```

### Common Usage Patterns

```bash
# Create compressed encrypted archive
bfc create -c zstd -e password archive.bfc /data/

# List with full details
bfc list -lsc archive.bfc

# Extract preserving structure to specific location
bfc extract -k -C /tmp/restored archive.bfc

# Verify with progress
bfc verify -p --deep archive.bfc

# Get detailed info about specific file
bfc info -d archive.bfc path/to/file.txt
```

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

### v1.1.0 (Coming Soon)

- **NEW**: ChaCha20-Poly1305 AEAD encryption with libsodium integration
- **NEW**: Password-based and key-file encryption modes
- **NEW**: Argon2id key derivation for strong password security
- **NEW**: Transparent encryption/decryption in CLI and library
- Enhanced CI/CD pipeline with encryption testing
- Improved test coverage for encryption code paths

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
