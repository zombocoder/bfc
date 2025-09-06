# BFC Performance Benchmarks

This directory contains comprehensive performance benchmarks for the BFC (Binary File Container) library. The benchmarks measure various aspects of library performance including write throughput, read performance, and CRC32C computation speed.

## Available Benchmarks

### 1. Writer Benchmark (`benchmark_writer`)
Tests container creation and file writing performance:

**Small Files Test:**
- Creates 10,000 files of 1KB each
- Measures files/second and write throughput
- Evaluates container overhead

**Large Files Test:**
- Creates 10 files of 100MB each  
- Tests sustained write performance
- Measures large file handling efficiency

**Mixed Workload Test:**
- Creates complex directory structures
- Mixes files of varying sizes (1KB to 1MB)
- Tests real-world usage patterns

### 2. Reader Benchmark (`benchmark_reader`)
Tests container reading and access performance:

**Random Access Test:**
- Performs 5,000 random file reads from 1,000 files
- Measures random access performance
- Tests index lookup efficiency

**Sequential Read Test:**
- Reads all files sequentially
- Measures sequential throughput
- Evaluates streaming performance

**Stat Operations Test:**
- Performs 50,000 random stat operations
- Tests metadata lookup performance
- Measures index search speed

**Directory Listing Test:**
- Performs directory listing operations
- Tests directory traversal performance
- Measures filtering efficiency

### 3. CRC32C Benchmark (`benchmark_crc32c`)
Tests checksum computation performance:

**Small Chunks Test:**
- Processes 1M iterations of 64-byte chunks
- Measures small data CRC performance
- Tests function call overhead

**Large Chunks Test:**
- Processes 1,000 iterations of 1MB chunks
- Measures bulk CRC performance
- Tests memory bandwidth utilization

**Streaming Test:**
- Processes 100MB in 8KB streaming chunks
- Tests incremental CRC computation
- Measures streaming performance

**Alignment Test:**
- Tests performance with different memory alignments
- Measures hardware acceleration effectiveness
- Evaluates unaligned access penalties

### 4. Compression Benchmark (`benchmark_compress`)
Tests compression and decompression performance with ZSTD:

**Compression Level Test:**
- Tests compression levels 1, 3, 6, 9, 12 with different content types
- Compares compressible text vs random data compression ratios
- Measures write throughput and space savings across compression levels

**Compression Scaling Test:**
- Tests different file sizes (1KB to 1MB) with and without compression
- Measures compression effectiveness and performance impact
- Evaluates compression overhead for various workloads

**Decompression Performance Test:**
- Benchmarks reading/decompression speed of compressed containers
- Measures decompression throughput and file processing rates
- Tests end-to-end compressed file access performance

**Typical Results:**
- **Compressible content**: 95-99% space savings with ZSTD
- **Random data**: No compression applied (smart detection)
- **Write performance**: 90-450 MB/s depending on compression level and file size
- **Decompression speed**: 500-600 MB/s (often faster than compression)

### 5. Encryption Benchmark (`benchmark_encrypt`) 
Tests encryption and decryption performance with ChaCha20-Poly1305 AEAD (requires libsodium):

**Encryption Performance Test:**
- Tests encryption/decryption throughput with different data sizes (1KB to 4MB)
- Benchmarks key derivation time with Argon2id
- Tests different content types (text, binary, sparse)
- Measures authentication failure detection

**Encrypted Container Creation Test:**
- Compares performance of different scenarios:
  - No encryption/compression
  - Encryption only
  - Compression only (if ZSTD available)
  - Combined encryption + compression
- Measures container creation and reading performance
- Evaluates storage overhead and compression ratios

**Typical Results:**
- **Encryption speed**: 200-800 MB/s depending on data size and type
- **Decryption speed**: Similar to encryption, often slightly faster
- **Key derivation**: 100-500ms (intentionally slow for security)
- **Storage overhead**: ~28 bytes per file (nonce + authentication tag)
- **Authentication**: 100% failure detection for tampered/wrong key data

**Note:** This benchmark is only available when BFC is built with libsodium support (`-DBFC_WITH_SODIUM=ON`).

### 6. All Benchmarks Runner (`benchmark_all`)
Runs all benchmarks in sequence with system information reporting.

## Building and Running

### Build with main project
```bash
# Basic benchmarks
cmake -S . -B build -DBFC_BUILD_BENCHMARKS=ON
cmake --build build

# With ZSTD compression support for compression benchmarks
cmake -S . -B build -DBFC_BUILD_BENCHMARKS=ON -DBFC_WITH_ZSTD=ON
cmake --build build

# With encryption support for encryption benchmarks (requires libsodium)
cmake -S . -B build -DBFC_BUILD_BENCHMARKS=ON -DBFC_WITH_SODIUM=ON
cmake --build build

# With all optional features
cmake -S . -B build -DBFC_BUILD_BENCHMARKS=ON -DBFC_WITH_ZSTD=ON -DBFC_WITH_SODIUM=ON
cmake --build build
```

### Run individual benchmarks
```bash
# Writer benchmark
./build/benchmarks/benchmark_writer

# Reader benchmark  
./build/benchmarks/benchmark_reader

# CRC32C benchmark
./build/benchmarks/benchmark_crc32c

# Compression benchmark (requires ZSTD support)
./build/benchmarks/benchmark_compress

# Encryption benchmark (requires libsodium support)
./build/benchmarks/benchmark_encrypt

# All benchmarks
./build/benchmarks/benchmark_all
```

### Run using Make targets
```bash
# Individual benchmarks
make bench-writer
make bench-reader
make bench-crc32c
make bench-compress
make bench-encrypt  # (requires libsodium support)

# All benchmarks
make benchmarks
# or
make bench-all
```

### Run specific benchmark category
```bash
# Run only CRC32C benchmark
./build/benchmarks/benchmark_all crc32c

# Run only writer benchmark
./build/benchmarks/benchmark_all writer

# Run only reader benchmark  
./build/benchmarks/benchmark_all reader
```

## Interpreting Results

### Writer Performance
- **Throughput (MB/s)**: Data write rate, higher is better
- **Files/sec**: File creation rate, higher is better
- **Overhead (%)**: Container vs raw data size, lower is better

### Reader Performance  
- **Throughput (MB/s)**: Data read rate, higher is better
- **Operations/sec**: Access rate, higher is better
- **Success Rate**: Should be 100% for valid containers

### CRC32C Performance
- **Throughput (MB/s)**: Checksum computation rate, higher is better
- **Hardware vs Software**: Hardware should be 3-10x faster
- **Alignment Impact**: Well-aligned data should perform better

## Expected Performance Ranges

Performance varies significantly by hardware, but typical ranges:

### Writer Performance
- **Small files**: 1,000-10,000 files/sec
- **Large files**: 100-500 MB/s sustained
- **Mixed workload**: 500-2,000 files/sec

### Reader Performance
- **Random reads**: 10,000-50,000 reads/sec
- **Sequential reads**: 200-800 MB/s
- **Stat operations**: 50,000-200,000 stats/sec

### CRC32C Performance (with hardware acceleration)
- **Small chunks**: 200-800 MB/s
- **Large chunks**: 2,000-8,000 MB/s
- **Streaming**: 1,500-6,000 MB/s

## Benchmark Files

All benchmarks create temporary files in `/tmp/` with names like:
- `/tmp/benchmark_*.bfc` - Test containers
- `/tmp/extracted_*` - Extracted test files

Files are automatically cleaned up after each benchmark completes.

## Performance Tuning

### Writer Optimization
- Use larger block sizes (8KB-64KB) for better performance
- Batch file operations when possible
- Ensure sufficient disk space for large benchmarks

### Reader Optimization  
- Enable hardware CRC32C if available
- Use memory mapping for better read performance
- Consider container placement on fast storage

### System Optimization
- Run on dedicated hardware when possible
- Disable power management during benchmarks
- Ensure adequate RAM for large file tests
- Use fast storage (SSD) for temporary files

## Hardware Acceleration

The benchmarks automatically detect and use hardware CRC32C acceleration:

### x86_64 Systems
- Requires SSE4.2 instruction set
- Intel processors since 2008 (Core i7 and later)
- AMD processors since 2011 (Bulldozer and later)

### ARM Systems  
- Requires ARMv8 with CRC extension
- Most ARM Cortex-A processors since 2014
- Apple Silicon (M1/M2) processors

Hardware acceleration typically provides 3-10x performance improvement for CRC32C computation.

## Troubleshooting

### Benchmark Failures
- Ensure `/tmp` has sufficient space (1-2 GB)
- Check file descriptor limits (`ulimit -n`)
- Verify write permissions to `/tmp`

### Performance Issues
- Check system load during benchmarks
- Monitor memory usage for large file tests
- Verify storage is not the bottleneck
- Disable swap if possible during testing

### Compilation Issues
- Ensure proper optimization flags (`-O2` or `-O3`)
- Link against optimized libraries
- Use release builds for accurate measurements

## Contributing

When adding new benchmarks:

1. Follow existing naming conventions
2. Include progress reporting for long operations
3. Clean up temporary files properly
4. Add appropriate error handling
5. Update this README with new benchmark descriptions