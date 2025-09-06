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

set(BFC_CLI_SOURCES
    main.c
    cmd_create.c
    cmd_list.c
    cmd_info.c
    cmd_extract.c
    cmd_verify.c
    cli_util.c
)

add_executable(bfc_cli ${BFC_CLI_SOURCES})

target_link_libraries(bfc_cli bfc)

# Link ZSTD if enabled (needed for static library dependencies)
if(BFC_WITH_ZSTD)
    target_link_libraries(bfc_cli ${ZSTD_LIBRARIES})
    target_link_directories(bfc_cli PRIVATE ${ZSTD_LIBRARY_DIRS})
endif()

# Link libsodium if enabled (needed for encryption support)
if(BFC_WITH_SODIUM)
    target_link_libraries(bfc_cli ${SODIUM_LIBRARIES})
    target_link_directories(bfc_cli PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_compile_definitions(bfc_cli PRIVATE BFC_WITH_SODIUM)
endif()

target_include_directories(bfc_cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/lib
)

# Set output name to 'bfc' and directory
set_target_properties(bfc_cli PROPERTIES 
    OUTPUT_NAME bfc
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install CLI tool
install(TARGETS bfc_cli
        RUNTIME DESTINATION bin
)