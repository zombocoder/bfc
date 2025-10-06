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

set(BFC_LIB_SOURCES
    bfc_format.c
    bfc_writer.c
    bfc_reader.c
    bfc_iter.c
    bfc_crc32c.c
    bfc_compress.c
    bfc_encrypt.c
    bfc_os.c
    bfc_util.c
)

set(BFC_LIB_HEADERS
    bfc_format.h
    bfc_crc32c.h
    bfc_compress.h
    bfc_encrypt.h
    bfc_os.h
    bfc_util.h
)

add_library(bfc STATIC ${BFC_LIB_SOURCES})
add_library(bfc_shared SHARED ${BFC_LIB_SOURCES})

# Enable SSE4.2 and CRC32 for hardware support on x86_64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    target_compile_options(bfc PRIVATE -msse4.2 -mcrc32)
    target_compile_options(bfc_shared PRIVATE -msse4.2 -mcrc32)
endif()

# Set properties for both libraries
foreach(target bfc bfc_shared)
    target_include_directories(${target}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        PUBLIC ${CMAKE_SOURCE_DIR}/include
    )
    
    # Link with math library if needed
    target_link_libraries(${target} m)
    
    # Optional dependencies
    if(BFC_WITH_FUSE)
        target_link_libraries(${target} ${FUSE_LIBRARIES})
        target_compile_definitions(${target} PRIVATE BFC_WITH_FUSE)
        target_include_directories(${target} PRIVATE ${FUSE_INCLUDE_DIRS})
    endif()
    
    if(BFC_WITH_ZSTD)
        target_link_libraries(${target} ${ZSTD_LIBRARIES})
        target_compile_definitions(${target} PRIVATE BFC_WITH_ZSTD)
        target_include_directories(${target} PRIVATE ${ZSTD_INCLUDE_DIRS})
        target_link_directories(${target} PRIVATE ${ZSTD_LIBRARY_DIRS})
    endif()
    
    if(BFC_WITH_SODIUM)
        target_link_libraries(${target} ${SODIUM_LIBRARIES})
        target_compile_definitions(${target} PRIVATE BFC_WITH_SODIUM)
        target_include_directories(${target} PRIVATE ${SODIUM_INCLUDE_DIRS})
        target_link_directories(${target} PRIVATE ${SODIUM_LIBRARY_DIRS})
    endif()
endforeach()

# Set shared library properties
set_target_properties(bfc_shared PROPERTIES
    OUTPUT_NAME bfc
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Install targets
install(TARGETS bfc bfc_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

# Set output directories for build
set_target_properties(bfc PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

set_target_properties(bfc_shared PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

install(FILES ${CMAKE_SOURCE_DIR}/include/bfc.h
        DESTINATION include
)