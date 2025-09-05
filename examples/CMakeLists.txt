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

# Install examples
install(TARGETS create_example read_example extract_example
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples)

# Install example source code
install(FILES 
        create_example.c
        read_example.c 
        extract_example.c
        CMakeLists.txt
        README.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)