cmake_minimum_required(VERSION 2.8)
project(DRMWideVine)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "WideVine")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(NOT CMAKE_CROSSCOMPILING)
   set(STAGING_DIR "${CMAKE_INSTALL_PREFIX}")
else()
   # TODO: this can be multiple directories
   set(STAGING_DIR "${CMAKE_FIND_ROOT_PATH}")
endif()

find_package(WideVine REQUIRED)
find_package(WPEFramework REQUIRED)

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_INCLUDES
    ${WPEFRAMEWORK_INCLUDE_DIRS})

set(DRM_PLUGIN_LIBS 
    ${WIDEVINE_LIBRARIES}
    ${WPEFRAMEWORK_LIBRARY_WPEFrameworkCore})

set(DRM_PLUGIN_SOURCES 
    HostImplementation.cpp 
    DeviceCertificate.cpp 
    MediaSession.cpp 
    MediaSystem.cpp)

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${WIDEVINE_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${WIDEVINE_INCLUDE_DIRS} ${DRM_PLUGIN_INCLUDES})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)

