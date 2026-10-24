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

# End-to-end tests of the bfc command-line tool. They need a POSIX shell and
# symlinks, so they are not built on Windows.

add_executable(make_symlink_parent make_symlink_parent.c)
target_link_libraries(make_symlink_parent bfc)

# The static library's dependencies may live off the default linker path
if(BFC_WITH_ZSTD)
    target_link_directories(make_symlink_parent PRIVATE ${ZSTD_LIBRARY_DIRS})
endif()
if(BFC_WITH_SODIUM)
    target_link_directories(make_symlink_parent PRIVATE ${SODIUM_LIBRARY_DIRS})
endif()

add_test(NAME cli
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.sh
            $<TARGET_FILE:bfc_cli> $<TARGET_FILE:make_symlink_parent>
)
