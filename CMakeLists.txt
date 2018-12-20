cmake_minimum_required(VERSION 3.7)

include(${CMAKE_SYSROOT}/usr/include/cmake/WPEFramework.cmake)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(PLUGIN_NAME Widevine)
set(MODULE_NAME ${NAMESPACE}${PLUGIN_NAME})

message("Setting up ${PLUGIN_NAME}")

# This contains all kinds of plugins (publicely available, so they all need the plugin support library !!
find_package(Plugins REQUIRED)
find_package(WideVine REQUIRED)

set(PLUGIN_SOURCES
    HostImplementation.cpp
    DeviceCertificate.cpp
    MediaSession.cpp
    MediaSystem.cpp)

# add the library
add_library(${PLUGIN_NAME} SHARED ${PLUGIN_SOURCES} ${WIDEVINE_LIBRARIES})
target_compile_definitions(${PLUGIN_NAME} PRIVATE ${WIDEVINE_FLAGS})
target_include_directories(${PLUGIN_NAME} PRIVATE ${PLUGINS_INCLUDE_DIR} ${WIDEVINE_INCLUDE_DIRS})
target_link_libraries(${PLUGIN_NAME} ${PLUGIN_LIBS})
set_target_properties(${PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)