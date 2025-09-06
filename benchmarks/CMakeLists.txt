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

# BFC Performance Benchmarks

# Writer benchmark
add_executable(benchmark_writer benchmark_writer.c)
target_link_libraries(benchmark_writer bfc)
target_include_directories(benchmark_writer PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# Reader benchmark  
add_executable(benchmark_reader benchmark_reader.c)
target_link_libraries(benchmark_reader bfc)
target_include_directories(benchmark_reader PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# CRC32C benchmark
add_executable(benchmark_crc32c benchmark_crc32c.c)
target_link_libraries(benchmark_crc32c bfc)
target_include_directories(benchmark_crc32c PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# Compression benchmark
add_executable(benchmark_compress benchmark_compress.c)
target_link_libraries(benchmark_compress bfc)
target_include_directories(benchmark_compress PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# Encryption benchmark
if(BFC_WITH_SODIUM)
    add_executable(benchmark_encrypt benchmark_encrypt.c)
    target_link_libraries(benchmark_encrypt bfc)
    target_include_directories(benchmark_encrypt PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src/lib)
endif()

# All benchmarks runner
add_executable(benchmark_all benchmark_all.c)
target_link_libraries(benchmark_all bfc)
target_include_directories(benchmark_all PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# Configure optional dependencies for all benchmarks
set(all_benchmark_targets benchmark_writer benchmark_reader benchmark_crc32c benchmark_compress benchmark_all)
if(BFC_WITH_SODIUM)
    list(APPEND all_benchmark_targets benchmark_encrypt)
endif()

# Link ZSTD if enabled (avoid duplicates by handling all targets together)
if(BFC_WITH_ZSTD)
    foreach(target ${all_benchmark_targets})
        target_link_libraries(${target} ${ZSTD_LIBRARIES})
        target_link_directories(${target} PRIVATE ${ZSTD_LIBRARY_DIRS})
        target_compile_definitions(${target} PRIVATE BFC_WITH_ZSTD)
    endforeach()
endif()

# Link libsodium if enabled (avoid duplicates by handling all targets together)  
if(BFC_WITH_SODIUM)
    foreach(target ${all_benchmark_targets})
        target_link_libraries(${target} ${SODIUM_LIBRARIES})
        target_link_directories(${target} PRIVATE ${SODIUM_LIBRARY_DIRS})
        target_compile_definitions(${target} PRIVATE BFC_WITH_SODIUM)
    endforeach()
endif()

# Install benchmarks
set(benchmark_targets benchmark_writer benchmark_reader benchmark_crc32c benchmark_compress)
if(BFC_WITH_SODIUM)
    list(APPEND benchmark_targets benchmark_encrypt)
endif()
install(TARGETS 
        ${benchmark_targets}
        benchmark_all
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/benchmarks)

# Install benchmark source code and results
set(benchmark_sources benchmark_writer.c benchmark_reader.c benchmark_crc32c.c benchmark_compress.c)
if(BFC_WITH_SODIUM)
    list(APPEND benchmark_sources benchmark_encrypt.c)
endif()
install(FILES 
        ${benchmark_sources}
        benchmark_all.c
        benchmark_common.h
        CMakeLists.txt
        README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/benchmarks)

# Add custom targets for running benchmarks
add_custom_target(bench-writer
    COMMAND benchmark_writer
    DEPENDS benchmark_writer
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running writer performance benchmark")

add_custom_target(bench-reader
    COMMAND benchmark_reader
    DEPENDS benchmark_reader
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running reader performance benchmark")

add_custom_target(bench-crc32c
    COMMAND benchmark_crc32c
    DEPENDS benchmark_crc32c
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running CRC32C performance benchmark")

add_custom_target(bench-compress
    COMMAND benchmark_compress
    DEPENDS benchmark_compress
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running compression performance benchmark")

if(BFC_WITH_SODIUM)
    add_custom_target(bench-encrypt
        COMMAND benchmark_encrypt
        DEPENDS benchmark_encrypt
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running encryption performance benchmark")
endif()

set(bench_all_deps benchmark_all benchmark_writer benchmark_reader benchmark_crc32c benchmark_compress)
if(BFC_WITH_SODIUM)
    list(APPEND bench_all_deps benchmark_encrypt)
endif()
add_custom_target(bench-all
    COMMAND benchmark_all
    DEPENDS ${bench_all_deps}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running all performance benchmarks")

# Alias for convenience
add_custom_target(benchmarks DEPENDS bench-all)