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
# @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
# @author      Pawel Sikorski (p.sikorski@samsung.com)
# @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
# @author      Kyungwook Tak (k.tak@samsung.com)
# @version     1.0
# @brief
#
SET(CERT_SVC_VCORE_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

SET(VCORE_TESTS_SOURCES
    ${CERT_SVC_VCORE_TESTS_DIR}/main.cpp
    ${CERT_SVC_VCORE_TESTS_DIR}/test-common.cpp
    ${CERT_SVC_VCORE_TESTS_DIR}/test-signature-validator.cpp
    ${CERT_SVC_VCORE_TESTS_DIR}/test-ocsp-check.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/vcore/src
    ${CERT_SVC_VCORE_TESTS_DIR}
    )

ADD_EXECUTABLE(${TARGET_VCORE_TEST}
    ${VCORE_TESTS_SOURCES}
    ${DPL_TEST_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_VCORE_TEST}
    ${TARGET_VCORE_LIB}
    ${TEST_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_VCORE_TEST}
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
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget/signature22.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_hash/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_hash/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_hash/signature22.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_hash/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_hash/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_hash
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_signature/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_signature/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_signature/signature22.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_signature/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_signature/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_signature
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_certificate/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_certificate/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_certificate/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_negative_certificate/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_negative_certificate
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_partner
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner_operator/author-signature.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner_operator/signature1.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner_operator/config.xml
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/widget_partner_operator/index.html
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/vcore_widget_uncompressed_partner_operator
    )

INSTALL(FILES
    "${CERT_SVC_VCORE_TESTS_DIR}/test-cases/reference/encoding test.empty"
    DESTINATION
    ${TZ_SYS_RO_APP}/widget/tests/reference
    )

INSTALL(FILES
    ${CERT_SVC_VCORE_TESTS_DIR}/test-cases/root_cacert0.pem
    DESTINATION
    ${TZ_SYS_SHARE}/ca-certificates/tizen
    )
