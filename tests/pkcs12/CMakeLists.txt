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
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/pkcs12_test.cpp
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/new_test_cases.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${PROJECT_SOURCE_DIR}/tests/pkcs12
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


INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/without_pass.p12
    DESTINATION ${TZ_SYS_RO_APP}/widget/tests/pkcs12/
)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/without_pass.p12
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/Invalidcrt.crt
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/Testing.crt
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/test.pfx
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/wifi-server.pem
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/wifiserver.pfx
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/wifiuser.p12
    DESTINATION ${TZ_SYS_SHARE}/cert-svc/tests/
)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/tests/pkcs12/8956b9bc.0
    DESTINATION ${TZ_SYS_ETC}/ssl/certs/
)
