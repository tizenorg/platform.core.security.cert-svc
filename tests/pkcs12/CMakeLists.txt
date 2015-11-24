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
# @author      Jacek Migacz (j.migacz@samsung.com)
# @version     1.0
# @brief       This package provides bacis check of internal OpenSSL's PKCS#12 routines.
#

SET(PKCS12_TEST_SOURCES
    pkcs12_test.cpp
    new_test_cases.cpp
    test-common.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    .
    )

ADD_EXECUTABLE(${TARGET_PKCS12_TEST} ${PKCS12_TEST_SOURCES} ${DPL_TEST_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_PKCS12_TEST}
    ${TARGET_VCORE_LIB}
    ${TEST_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_PKCS12_TEST}
    DESTINATION ${TZ_SYS_BIN}
    PERMISSIONS OWNER_READ
                OWNER_WRITE
                OWNER_EXECUTE
                GROUP_READ
                GROUP_EXECUTE
                WORLD_READ
                WORLD_EXECUTE
    )

INSTALL(
    FILES
        without_pass.p12
        Invalidcrt.crt
        Testing.crt
        test.pfx
        wifi-server.pem
        wifiserver.pfx
        wifiuser.p12
    DESTINATION ${TZ_SYS_RO_APP}/cert-svc-tests/p12
)
