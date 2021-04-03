# - Try to find openCDMi
# Once done this will define
#  WIDEVINE_FOUND - System has libocdmi
#  WIDEVINE_INCLUDE_DIRS - The libocdmi include directories
#  WIDEVINE_LIBRARIES - The libraries needed to use libcdmi
#
# Copyright (C) 2016 TATA ELXSI
# Copyright (C) 2016 Metrological.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND ITS CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR ITS
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
#

find_path(WIDEVINE_INCLUDE_DIRS NAMES wv_cdm_types.h PATH_SUFFIXES "widevine")

set(WV_LIBS  
    widevine_ce_cdm_static 
    ssl 
    metrics_proto 
    device_files 
    oec_level3_static 
    widevine_cdm_core 
    license_protocol 
    crypto
)

list(APPEND WIDEVINE_LIBRARIES "-Wl,--start-group")
foreach(_library ${WV_LIBS})
    message(STATUS "looking for ${_library}")
    
    find_library(_${_library}_location
        NAME ${_library} 
        PATH_SUFFIXES widevine
    )
    
    list(APPEND WIDEVINE_LIBRARIES "${_${_library}_location}")
endforeach()
list(APPEND WIDEVINE_LIBRARIES "-Wl,--end-group")


find_library(PROTO_BUF_LITE_LIBRARY NAME protobuf-lite PATH_SUFFIXES lib)
list(APPEND WIDEVINE_LIBRARIES ${PROTO_BUF_LITE_LIBRARY})

find_package(WPEFrameworkCore REQUIRED)
find_package(CompileSettingsDebug REQUIRED)
list(APPEND WIDEVINE_LIBRARIES ${NAMESPACE}Core::${NAMESPACE}Core)

find_package(deviceinfo REQUIRED)
list(APPEND WIDEVINE_LIBRARIES deviceinfo::deviceinfo)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(WIDEVINE DEFAULT_MSG WIDEVINE_INCLUDE_DIRS WIDEVINE_LIBRARIES)

mark_as_advanced(WIDEVINE_INCLUDE_DIRS WIDEVINE_LIBRARIES)
