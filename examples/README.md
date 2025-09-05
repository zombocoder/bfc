# BFC Library Examples

This directory contains example programs demonstrating how to use the BFC (Binary File Container) library.

## Examples

### 1. create_example.c
Demonstrates how to create a new BFC container and add files and directories to it.

**Features shown:**
- Creating a new container with `bfc_create()`
- Adding directories with `bfc_add_dir()`
- Adding files with `bfc_add_file()`
- Finalizing the container with `bfc_finish()`
- Proper resource cleanup with `bfc_close()`

**Usage:**
```bash
./create_example my_container.bfc
```

### 2. read_example.c
Demonstrates how to read from an existing BFC container.

**Features shown:**
- Opening a container with `bfc_open()`
- Verifying container integrity with `bfc_verify()`
- Listing container contents with `bfc_list()`
- Getting file statistics with `bfc_stat()`
- Reading file content with `bfc_read()`
- Partial file reading with offset and length
- Proper resource cleanup with `bfc_close_read()`

**Usage:**
```bash
./read_example my_container.bfc
```

### 3. extract_example.c
Demonstrates how to extract files from a BFC container to the filesystem.

**Features shown:**
- Opening and listing container contents
- Creating directory structure on extraction
- Extracting files with `bfc_extract_to_fd()`
- Error handling and cleanup
- File verification after extraction

**Usage:**
```bash
./extract_example my_container.bfc [output_directory]
```

## Building the Examples

### Option 1: Build with main project
The examples are automatically built when you build the main BFC project:

```bash
cmake -S . -B build
cmake --build build
```

The example executables will be located in `build/examples/`.

### Option 2: Build examples standalone
You can also build the examples as a standalone project if you have BFC installed:

```bash
cd examples
mkdir build && cd build
cmake -S .. -B .
cmake --build .
```

## Quick Demo

Here's a quick demo showing all three examples in action:

```bash
# Build the project
cmake -S . -B build
cmake --build build

# Go to examples directory
cd build/examples

# Create a sample container
./create_example demo.bfc

# Read the container contents
./read_example demo.bfc

# Extract all files to a directory
mkdir extracted
./extract_example demo.bfc extracted

# Verify extracted content
ls -la extracted/
cat extracted/README.md
```

## API Usage Patterns

### Error Handling
All BFC functions return an integer result code. Always check for `BFC_OK`:

```c
int result = bfc_create("container.bfc", 4096, 0, &writer);
if (result != BFC_OK) {
    fprintf(stderr, "Failed to create container: %d\n", result);
    return 1;
}
```

### Resource Management
Always pair create/open calls with corresponding close calls:

```c
// Writer
bfc_t *writer;
bfc_create(..., &writer);
// ... use writer ...
bfc_close(writer);

// Reader  
bfc_t *reader;
bfc_open(..., &reader);
// ... use reader ...
bfc_close_read(reader);
```

### File Content Handling
Use temporary files or file descriptors for adding content:

```c
// From memory via tmpfile()
FILE *temp = tmpfile();
fwrite(content, 1, content_len, temp);
rewind(temp);
bfc_add_file(writer, "path", temp, mode, mtime, &crc);
fclose(temp);

// Extract to file descriptor
int fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
bfc_extract_to_fd(reader, "path", fd);
close(fd);
```

### Listing Content
Use callback functions for processing container entries:

```c
static int process_entry(const bfc_entry_t *entry, void *user_data) {
    printf("Found: %s (size: %llu)\n", entry->path, entry->size);
    return 0; // Continue iteration
}

bfc_list(reader, NULL, process_entry, NULL);
```

## Compilation Notes

When compiling your own programs that use BFC:

```bash
# Include the header directory
gcc -I/path/to/bfc/include your_program.c -lbfc -o your_program

# Or with pkg-config (if installed)
gcc $(pkg-config --cflags --libs bfc) your_program.c -o your_program
```

Required headers:
- `<bfc.h>` - Main BFC API
- `<sys/stat.h>` - For file mode constants (S_IFREG, S_IFDIR, etc.)
- `<fcntl.h>` - For file descriptor operations (when using extract_to_fd)