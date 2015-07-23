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
# @file        CMakeLists.txt
# @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
# @version     1.0
# @brief
#

SET(VCOREC_TESTS_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/capi/api_tests.cpp
    ${PROJECT_SOURCE_DIR}/tests/capi/test_suite_01.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${PROJECT_SOURCE_DIR}/tests/capi
    ${PROJECT_SOURCE_DIR}/include
    )

ADD_EXECUTABLE(${TARGET_VCOREC_TEST} ${VCOREC_TESTS_SOURCES} ${DPL_TEST_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_VCOREC_TEST}
    ${TARGET_VCORE_LIB}
    ${TEST_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_VCOREC_TEST}
    DESTINATION ${TZ_SYS_BIN}
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert_a.pem
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert_b.pem
    ${PROJECT_SOURCE_DIR}/tests/capi/data/pkey.pem
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/pkcs12/test1st
    PERMISSIONS OWNER_READ
                GROUP_READ
                WORLD_READ
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert0.pem
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert1.der
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert2fake.pem
    ${PROJECT_SOURCE_DIR}/tests/capi/data/cert3fake.der
    ${PROJECT_SOURCE_DIR}/tests/capi/data/root_cacert0.pem
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/cert-type/
    PERMISSIONS OWNER_READ
                GROUP_READ
                WORLD_READ
    )
