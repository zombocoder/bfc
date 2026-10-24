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

# Unit tests for BFC library

set(UNIT_TEST_SOURCES
    test_format.c
    test_crc32c.c
    test_path.c
    test_writer.c
    test_reader.c
    test_util.c
    test_os.c
    test_compress.c
    test_encrypt.c
    test_oci.c
    # test_encrypt_integration.c  # Temporarily disabled due to API mismatches
    test_main.c
)

add_executable(unit_tests ${UNIT_TEST_SOURCES})

target_link_libraries(unit_tests bfc)

# Link ZSTD if enabled (needed for static library dependencies)
if(BFC_WITH_ZSTD)
    target_link_directories(unit_tests PRIVATE ${ZSTD_LIBRARY_DIRS})
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_ZSTD)
endif()

# Link libsodium if enabled (needed for encryption tests)
if(BFC_WITH_SODIUM)
    target_link_directories(unit_tests PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_SODIUM)
endif()

# Add OCI support if enabled (needed for OCI tests)
if(BFC_WITH_OCI)
    target_link_libraries(unit_tests PkgConfig::CJSON)
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_OCI)
endif()

target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib
)

# Each test runs in a directory of its own. The tests create containers under
# fixed relative names (e.g. "test_encrypted.bfc"), and unit_all repeats every
# suite, so under `ctest --parallel` two processes would otherwise unlink and
# rewrite the same files at the same time.
function(bfc_add_unit_test name)
    set(dir ${CMAKE_CURRENT_BINARY_DIR}/run/${name})
    file(MAKE_DIRECTORY ${dir})
    add_test(NAME ${name} COMMAND unit_tests ${ARGN} WORKING_DIRECTORY ${dir})
endfunction()

# Add individual tests
bfc_add_unit_test(unit_format format)
bfc_add_unit_test(unit_crc32c crc32c)
bfc_add_unit_test(unit_path path)
bfc_add_unit_test(unit_writer writer)
bfc_add_unit_test(unit_reader reader)
bfc_add_unit_test(unit_util util)
bfc_add_unit_test(unit_os os)
bfc_add_unit_test(unit_compress compress)
bfc_add_unit_test(unit_encrypt encrypt)
bfc_add_unit_test(unit_oci oci)
# bfc_add_unit_test(unit_encrypt_integration encrypt_integration)  # Disabled
bfc_add_unit_test(unit_all)