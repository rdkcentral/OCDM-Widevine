cmake_minimum_required(VERSION 3.7)

foreach(searchPath ${CMAKE_FIND_ROOT_PATH})
    if(EXISTS "${searchPath}/${CMAKE_INSTALL_PREFIX}/include/cmake/tools.cmake")
        include(${searchPath}/${CMAKE_INSTALL_PREFIX}/include/cmake/tools.cmake)
    endif()
endforeach()


# This contains all kinds of plugins (publicely available, so they all need the plugin support library !!
find_package(Plugins REQUIRED)
include_directories(${PLUGINS_INCLUDE_DIR})

# All packages that did not deliver a CMake Find script (and some deprecated scripts that need to be removed) 
# are located in the cmake directory. Include it in the search.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(DRM_PLUGIN_NAME Widevine)

find_package(WideVine REQUIRED)

set(DRM_PLUGIN_INCLUDES
    ${WIDEVINE_INCLUDE_DIRS}
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
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${DRM_PLUGIN_INCLUDES})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")


install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/WPEFramework/OCDM)

