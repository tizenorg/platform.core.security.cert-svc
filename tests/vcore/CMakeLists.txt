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
SET(VCORE_TESTS_SOURCES
    main.cpp
    test-common.cpp
    test-signature-validator.cpp
    test-certificate.cpp
    test-ocsp-check.cpp
    test-time-conversion.cpp
    )

INCLUDE_DIRECTORIES(
    .
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

INSTALL(
    DIRECTORY
        resource/wgt
        resource/wgt_dist22
        resource/wgt_negative_hash
        resource/wgt_negative_signature
        resource/wgt_negative_certificate
        resource/wgt_partner
        resource/wgt_platform
        resource/wgt_positive_link
        resource/wgt_negative_link
        resource/tpk
        resource/attacked-tpk
        resource/tpk-with-userdata
        resource/attacked-tpk-with-userdata

    DESTINATION
        ${CERT_SVC_TESTS}/apps
    )
