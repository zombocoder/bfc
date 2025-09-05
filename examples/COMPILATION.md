# Compiling Programs with BFC Library

This document explains how to compile your own programs that use the BFC library.

## Prerequisites

Make sure you have BFC library installed. You can either:

1. **Install from build**: After building BFC, run `sudo make install` 
2. **Use from build directory**: Link directly to the built library

## Compilation Methods

### Method 1: Using pkg-config (Recommended)

If BFC is installed system-wide with pkg-config support:

```bash
# Compile a single file
gcc $(pkg-config --cflags --libs bfc) your_program.c -o your_program

# Compile multiple files
gcc $(pkg-config --cflags --libs bfc) file1.c file2.c -o your_program
```

### Method 2: Manual flags

If you built BFC locally or pkg-config isn't available:

```bash
# Using static library
gcc -I/path/to/bfc/include -L/path/to/bfc/build/lib -lbfc your_program.c -o your_program

# Using shared library (preferred for smaller binaries)
gcc -I/path/to/bfc/include -L/path/to/bfc/build/lib -lbfc your_program.c -o your_program

# If using from source tree directly
gcc -I../include -L../build/lib -lbfc your_program.c -o your_program
```

### Method 3: CMake Integration

Create a `CMakeLists.txt` for your project:

```cmake
cmake_minimum_required(VERSION 3.15)
project(my_bfc_app)

set(CMAKE_C_STANDARD 17)

# Method 3a: Find installed BFC
find_package(PkgConfig REQUIRED)
pkg_check_modules(BFC REQUIRED bfc)

add_executable(my_app your_program.c)
target_include_directories(my_app PRIVATE ${BFC_INCLUDE_DIRS})
target_link_libraries(my_app ${BFC_LIBRARIES})

# Method 3b: Use BFC as subdirectory (if you have the source)
# add_subdirectory(path/to/bfc)
# target_link_libraries(my_app bfc)
```

## Required Headers

Your program should include:

```c
#include <bfc.h>          // Main BFC API
#include <stdio.h>        // Standard I/O
#include <stdlib.h>       // Standard library
#include <sys/stat.h>     // File mode constants (S_IFREG, S_IFDIR, etc.)
#include <fcntl.h>        // File descriptor operations (for extract_to_fd)
#include <unistd.h>       // UNIX standard functions
```

## Example Makefile

```makefile
CC = gcc
CFLAGS = -std=c17 -Wall -Wextra
BFC_CFLAGS = $(shell pkg-config --cflags bfc)
BFC_LIBS = $(shell pkg-config --libs bfc)

# Fallback if pkg-config fails
ifeq ($(BFC_CFLAGS),)
    BFC_CFLAGS = -I../include
    BFC_LIBS = -L../build/lib -lbfc
endif

SOURCES = my_program.c
TARGET = my_program

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(BFC_CFLAGS) $(SOURCES) $(BFC_LIBS) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean
```

## Common Compilation Issues

### 1. Library not found
```
/usr/bin/ld: cannot find -lbfc
```

**Solutions:**
- Add `-L/path/to/lib/directory` with the correct path to libbfc.a or libbfc.so
- Make sure you built the library successfully
- Use `LD_LIBRARY_PATH` for shared libraries: `export LD_LIBRARY_PATH=/path/to/bfc/build/lib:$LD_LIBRARY_PATH`

### 2. Header not found
```
fatal error: bfc.h: No such file or directory
```

**Solutions:**
- Add `-I/path/to/include/directory` with the correct path to bfc.h
- Ensure the include path points to the directory containing bfc.h

### 3. Undefined symbols
```
undefined reference to 'bfc_create'
```

**Solutions:**
- Make sure you're linking with `-lbfc`
- Verify the library path is correct
- For static linking, ensure all dependencies are included

### 4. Runtime library not found (shared library)
```
error while loading shared libraries: libbfc.so.1: cannot open shared object file
```

**Solutions:**
```bash
# Set library path for current session
export LD_LIBRARY_PATH=/path/to/bfc/build/lib:$LD_LIBRARY_PATH

# Or install the library system-wide
sudo cp /path/to/bfc/build/lib/libbfc.so* /usr/local/lib/
sudo ldconfig
```

## Complete Example

Here's a minimal working example:

**simple_example.c:**
```c
#include <bfc.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    bfc_t *writer;
    int result = bfc_create("test.bfc", 4096, 0, &writer);
    if (result != BFC_OK) {
        printf("Failed to create container\\n");
        return 1;
    }
    
    FILE *content = tmpfile();
    fputs("Hello, World!", content);
    rewind(content);
    
    bfc_add_file(writer, "hello.txt", content, 0644, 0, NULL);
    bfc_finish(writer);
    bfc_close(writer);
    fclose(content);
    
    printf("Container created successfully!\\n");
    return 0;
}
```

**Compile and run:**
```bash
# Using pkg-config
gcc $(pkg-config --cflags --libs bfc) simple_example.c -o simple_example

# Or manually
gcc -I../include -L../build/lib -lbfc simple_example.c -o simple_example

# Run
./simple_example
```

## Linking Options

### Static Linking (Recommended for distribution)
- Uses `libbfc.a`
- Creates larger executables but no runtime dependencies
- More portable across systems

```bash
gcc -static -I../include -L../build/lib -lbfc your_program.c -o your_program
```

### Dynamic Linking (Recommended for development)
- Uses `libbfc.so` (Linux) or `libbfc.dylib` (macOS)
- Smaller executables
- Requires library to be available at runtime

```bash
gcc -I../include -L../build/lib -lbfc your_program.c -o your_program
```

## Cross-Platform Considerations

### macOS
- Use `.dylib` extension for shared libraries
- May need to adjust library paths with `install_name_tool`

### Windows (MinGW/MSYS2)
- Use `.dll` for shared libraries, `.lib` for import libraries
- May need additional flags for Windows API compatibility

### Linux
- Use `.so` for shared libraries
- Consider using `rpath` for runtime library discovery: `-Wl,-rpath,/path/to/lib`