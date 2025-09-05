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

include(CTest)

# Add unit tests
add_subdirectory(unit)

# Add fuzz tests if available
find_program(AFL_FUZZ afl-fuzz)
if(AFL_FUZZ AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz)
    add_subdirectory(fuzz)
endif()

# Add golden file tests
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/golden/CMakeLists.txt)
    add_subdirectory(golden)
endif()

# Custom test targets
add_custom_target(test-unit
    COMMAND ctest -R "unit"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running unit tests"
)

add_custom_target(test-golden
    COMMAND ctest -R "golden"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running golden file tests"
)

if(AFL_FUZZ)
    add_custom_target(test-fuzz
        COMMAND echo "Run fuzzing manually from build/tests/fuzz/"
        COMMENT "Fuzz testing setup complete"
    )
endif()