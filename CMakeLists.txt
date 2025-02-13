# If not stated otherwise in this file or this component's license file the
# following copyright and licenses apply:
#
# Copyright 2020 Metrological
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

project(Widevine)

find_package(WPEFramework)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME Widevine)
set(MODULE_NAME ${NAMESPACE}${DRM_PLUGIN_NAME})

# This contains all kinds of plugins (publicely available, so they all need the plugin support library !!

find_package(PkgConfig REQUIRED)
find_package(${NAMESPACE}Core REQUIRED)
find_package(WideVine REQUIRED)
find_package(OpenSSL REQUIRED)

if(CMAKE_WIDEVINE_VERSION)
    message("CMAKE_WIDEVINE_VERSION is ${CMAKE_WIDEVINE_VERSION}")
    add_definitions(-DWIDEVINE_VERSION=${CMAKE_WIDEVINE_VERSION})
endif()

set(DRM_PLUGIN_SOURCES
    HostImplementation.cpp
    MediaSession.cpp
    MediaSystem.cpp
    Module.cpp)

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})

target_include_directories(${DRM_PLUGIN_NAME}
    PRIVATE
        ../widevine/include
        ../widevine/TATA_include
        ../widevine/util/include)

target_link_libraries(${DRM_PLUGIN_NAME}
            PRIVATE
            ${NAMESPACE}Core::${NAMESPACE}Core
            ${WIDEVINE_LIBRARIES}
            -lgstsvpext)

if(DEFINED WIDEVINE_REALTEK)
    target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE liboec_ref_shared.so crypto curl ssl rt pthread)
    message(STATUS "WIDEVINE_REALTEK is ON")
elseif(DEFINED WIDEVINE_AMLOGIC)
    target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE ${OPENSSL_LIBRARIES} curl)
    message(STATUS "WIDEVINE_AMLOGIC is ON")
elseif(DEFINED WIDEVINE_BROADCOM)
    #target_link_libraries(${DRM_PLUGIN_NAME} PRIVATE NEXUS::NEXUS NXCLIENT::NXCLIENT NexusWidevine::NexusWidevine)
    #message(STATUS "WIDEVINE_BROADCOM is ON")
endif()

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

# Enable SVP.
#if("${RDK_SVP}" STREQUAL "ENABLED")
    message(STATUS "Using RDK_SVP")
    add_definitions (-DUSE_SVP)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/gstreamer-1.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/include/glib-2.0)
    target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${CMAKE_SYSROOT}/usr/lib/glib-2.0/include)
#endif()

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
