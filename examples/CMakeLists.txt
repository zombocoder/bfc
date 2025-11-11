# Copyright 2021 zombocoder (Taras Havryliak)
# Copyright 2024 Proxmox-LXCRI Contributors
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

# BFC Library Usage Examples

# Create example - demonstrates container creation
add_executable(create_example create_example.c)
target_link_libraries(create_example bfc)
target_include_directories(create_example PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Read example - demonstrates container reading and listing
add_executable(read_example read_example.c)  
target_link_libraries(read_example bfc)
target_include_directories(read_example PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Extract example - demonstrates file extraction
add_executable(extract_example extract_example.c)
target_link_libraries(extract_example bfc)
target_include_directories(extract_example PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Encrypt example - demonstrates encryption/decryption (requires libsodium)
if(BFC_WITH_SODIUM)
    add_executable(encrypt_example encrypt_example.c)
    target_link_libraries(encrypt_example bfc)
    target_include_directories(encrypt_example PRIVATE ${CMAKE_SOURCE_DIR}/include)
endif()

# OCI example - demonstrates OCI image storage with BFC (requires OCI support)
if(BFC_WITH_OCI)
    add_executable(bfc_oci_example oci_example.c)
    target_link_libraries(bfc_oci_example bfc)
    target_include_directories(bfc_oci_example PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_compile_definitions(bfc_oci_example PRIVATE BFC_WITH_OCI=1)
endif()

# Configure optional dependencies for all examples
set(all_example_targets create_example read_example extract_example)
if(BFC_WITH_SODIUM)
    list(APPEND all_example_targets encrypt_example)
endif()
if(BFC_WITH_OCI)
    list(APPEND all_example_targets bfc_oci_example)
endif()

# Link ZSTD if enabled (avoid duplicates by handling all targets together)
if(BFC_WITH_ZSTD)
    foreach(target ${all_example_targets})
        target_link_libraries(${target} ${ZSTD_LIBRARIES})
        target_link_directories(${target} PRIVATE ${ZSTD_LIBRARY_DIRS})
        target_compile_definitions(${target} PRIVATE BFC_WITH_ZSTD)
    endforeach()
endif()

# Link libsodium if enabled (avoid duplicates by handling all targets together)
if(BFC_WITH_SODIUM)
    foreach(target ${all_example_targets})
        target_link_libraries(${target} ${SODIUM_LIBRARIES})
        target_link_directories(${target} PRIVATE ${SODIUM_LIBRARY_DIRS})
        target_compile_definitions(${target} PRIVATE BFC_WITH_SODIUM)
    endforeach()
endif()

# Install examples
set(example_targets create_example read_example extract_example)
if(BFC_WITH_SODIUM)
    list(APPEND example_targets encrypt_example)
endif()
if(BFC_WITH_OCI)
    list(APPEND example_targets bfc_oci_example)
endif()
install(TARGETS ${example_targets}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples)

# Install example source code
set(example_sources create_example.c read_example.c extract_example.c)
if(BFC_WITH_SODIUM)
    list(APPEND example_sources encrypt_example.c)
endif()
if(BFC_WITH_OCI)
    list(APPEND example_sources oci_example.c)
endif()
install(FILES 
        ${example_sources}
        CMakeLists.txt
        README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)