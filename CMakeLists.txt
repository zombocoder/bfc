# Copyright 2021 zombocoder (Taras Havryliak)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.15)
project(bfc VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(BFC_WITH_FUSE "Build with FUSE support for mounting" OFF)
option(BFC_WITH_ZSTD "Build with Zstd compression support" OFF)
option(BFC_WITH_SODIUM "Build with libsodium encryption support" OFF)
option(BFC_WITH_OCI "Build with OCI Image Specs support" OFF)
option(BFC_COVERAGE "Enable coverage reporting" OFF)
option(BFC_BUILD_BENCHMARKS "Build benchmarks" ON)
option(BFC_BUILD_EXAMPLES "Build examples" ON)

# Automatically disable tests for Release builds to avoid unused variable warnings
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    option(BFC_BUILD_TESTS "Build tests" OFF)
else()
    option(BFC_BUILD_TESTS "Build tests" ON)
endif()

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -fsanitize=address,undefined")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
    
    if(BFC_COVERAGE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    endif()
endif()

# Find dependencies
if(BFC_WITH_FUSE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FUSE REQUIRED fuse3)
endif()

if(BFC_WITH_ZSTD)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZSTD REQUIRED libzstd)
    message(STATUS "ZSTD compression support enabled")
endif()

if(BFC_WITH_SODIUM)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    message(STATUS "libsodium encryption support enabled")
endif()

# Include directories
include_directories(include)

# Library
add_subdirectory(src/lib)

# CLI tool
add_subdirectory(src/cli)

# Tests
if(BFC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Benchmarks (skip during coverage builds to avoid compilation issues)
if(BFC_BUILD_BENCHMARKS AND NOT BFC_COVERAGE AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/benchmarks/CMakeLists.txt)
    add_subdirectory(benchmarks)
endif()

# Examples
if(BFC_BUILD_EXAMPLES AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt)
    add_subdirectory(examples)
endif()

# Install pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/bfc.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/bfc.pc"
    @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/bfc.pc"
        DESTINATION "lib/pkgconfig")

# Coverage target
if(BFC_COVERAGE)
    find_program(GCOVR_PATH gcovr)
    if(GCOVR_PATH)
        add_custom_target(coverage
            COMMAND ${GCOVR_PATH} -r ${CMAKE_SOURCE_DIR} --html --html-details -o coverage.html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating coverage report"
        )
    endif()
endif()