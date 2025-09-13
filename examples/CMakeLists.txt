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

# Basic example
add_executable(bfc_basic_example basic_example.c)
target_link_libraries(bfc_basic_example bfc)

# OCI example (if OCI support is enabled)
if(BFC_WITH_OCI)
    add_executable(bfc_oci_example oci_example.c)
    target_link_libraries(bfc_oci_example bfc)
    
    # Install OCI example
    install(TARGETS bfc_oci_example
            RUNTIME DESTINATION bin
    )
endif()

# Install basic example
install(TARGETS bfc_basic_example
        RUNTIME DESTINATION bin
)