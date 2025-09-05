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

# All benchmarks runner
add_executable(benchmark_all benchmark_all.c)
target_include_directories(benchmark_all PRIVATE 
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib)

# Install benchmarks
install(TARGETS 
        benchmark_writer 
        benchmark_reader 
        benchmark_crc32c
        benchmark_all
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/benchmarks)

# Install benchmark source code and results
install(FILES 
        benchmark_writer.c
        benchmark_reader.c
        benchmark_crc32c.c
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

add_custom_target(bench-all
    COMMAND benchmark_all
    DEPENDS benchmark_all benchmark_writer benchmark_reader benchmark_crc32c
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running all performance benchmarks")

# Alias for convenience
add_custom_target(benchmarks DEPENDS bench-all)