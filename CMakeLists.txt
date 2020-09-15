# If not stated otherwise in this file or this component's license file the
# following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the License);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an AS IS BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.3)

project(WideVine)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "WideVine")

set(CENC_VERSION 3 CACHE STRING "Defines version of CENC is used.")

find_package(WPEFramework)
find_package(${NAMESPACE}Core)
find_package(Widevine)

set(SOURCES
    HostImplementation.cpp
    MediaSession.cpp
    MediaSystem.cpp
)

if ((CENC_VERSION STREQUAL "14") OR (CENC_VERSION STREQUAL "15"))
   list(APPEND SOURCES Policy.cpp)
endif()

add_library(${DRM_PLUGIN_NAME} SHARED
    ${SOURCES}
)

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
    SUFFIX ".drm"
    PREFIX ""
)

target_compile_definitions(${DRM_PLUGIN_NAME}
    PRIVATE
        USE_CENC${CENC_VERSION}
)

target_link_libraries(${DRM_PLUGIN_NAME}
    PRIVATE
        ${NAMESPACE}Core::${NAMESPACE}Core
        ${WIDEVINE_LIBRARIES}
)

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
