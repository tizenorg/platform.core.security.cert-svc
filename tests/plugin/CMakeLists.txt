# Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# @file        CMakeLists.txt
# @author      Kyungwook Tak (k.tak@samsung.com)
# @brief
#

PKG_CHECK_MODULES(PLUGIN_SAMPLE_DEP REQUIRED dlog)

SET(PLUGIN_SAMPLE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/plugin-sample.cpp)

INCLUDE_DIRECTORIES(
    SYSTEM
    ${PLUGIN_SAMPLE_DEP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/vcore
    )

ADD_LIBRARY(${TARGET_PLUGIN_SAMPLE} SHARED ${PLUGIN_SAMPLE_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_PLUGIN_SAMPLE}
    ${PLUGIN_SAMPLE_DEP_LIBRARIES}
    ${TARGET_VCORE_LIB}
    )

INSTALL(TARGETS ${TARGET_PLUGIN_SAMPLE} DESTINATION ${LIBDIR})
