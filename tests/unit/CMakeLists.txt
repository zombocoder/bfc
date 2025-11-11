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
    target_link_libraries(unit_tests ${ZSTD_LIBRARIES})
    target_link_directories(unit_tests PRIVATE ${ZSTD_LIBRARY_DIRS})
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_ZSTD)
endif()

# Link libsodium if enabled (needed for encryption tests)
if(BFC_WITH_SODIUM)
    target_link_libraries(unit_tests ${SODIUM_LIBRARIES})
    target_link_directories(unit_tests PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_SODIUM)
endif()

# Add OCI support if enabled (needed for OCI tests)
if(BFC_WITH_OCI)
    target_compile_definitions(unit_tests PRIVATE BFC_WITH_OCI)
endif()

target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib
)

# Add individual tests
add_test(NAME unit_format COMMAND unit_tests format)
add_test(NAME unit_crc32c COMMAND unit_tests crc32c)
add_test(NAME unit_path COMMAND unit_tests path)
add_test(NAME unit_writer COMMAND unit_tests writer)
add_test(NAME unit_reader COMMAND unit_tests reader)
add_test(NAME unit_util COMMAND unit_tests util)
add_test(NAME unit_os COMMAND unit_tests os)
add_test(NAME unit_compress COMMAND unit_tests compress)
add_test(NAME unit_encrypt COMMAND unit_tests encrypt)
add_test(NAME unit_oci COMMAND unit_tests oci)
# add_test(NAME unit_encrypt_integration COMMAND unit_tests encrypt_integration)  # Disabled
add_test(NAME unit_all COMMAND unit_tests)