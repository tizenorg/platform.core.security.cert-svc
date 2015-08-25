# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

SET(TARGET_CAPI_TEST "cert-svc-tests-capi")
SET(TARGET_PKCS12_TEST "cert-svc-tests-pkcs12")
SET(TARGET_VCORE_TEST "cert-svc-tests-vcore")

PKG_CHECK_MODULES(TEST_DEP
    REQUIRED
    libpcrecpp
    )

SET(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

SET(DPL_TEST_SOURCES
    ${TEST_DIR}/dpl/src/assert.cpp
    ${TEST_DIR}/dpl/src/binary_queue.cpp
    ${TEST_DIR}/dpl/src/colors.cpp
    ${TEST_DIR}/dpl/src/errno_string.cpp
    ${TEST_DIR}/dpl/src/exception.cpp
    ${TEST_DIR}/dpl/src/noncopyable.cpp
    ${TEST_DIR}/dpl/src/singleton.cpp
    ${TEST_DIR}/dpl/src/test_results_collector.cpp
    ${TEST_DIR}/dpl/src/test_runner.cpp
    ${TEST_DIR}/dpl/src/test_runner_child.cpp
    ${TEST_DIR}/dpl/src/test_runner_multiprocess.cpp
    ${TEST_DIR}/dpl/src/value_separated_policies.cpp
    ${TEST_DIR}/dpl/src/value_separated_tokens.cpp

    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${TEST_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/vcore
    ${TEST_DIR}/dpl/include
    )

ADD_SUBDIRECTORY(capi)
ADD_SUBDIRECTORY(pkcs12)
ADD_SUBDIRECTORY(vcore)
