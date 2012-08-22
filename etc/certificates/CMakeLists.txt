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
# @author      Yunchan Cho (yunchan.cho@samsung.com)
# @version     1.0
# @brief
#

SET(CERT_DIR ${PROJECT_SOURCE_DIR}/etc/certificates)

INSTALL(FILES
    ${CERT_DIR}/wac0.root.preproduction.pem
    ${CERT_DIR}/wac0.root.production.pem
    ${CERT_DIR}/wac0.publisherid.pem
    ${CERT_DIR}/tizen0.root.preproduction.cert.pem
    DESTINATION /opt/share/cert-svc/certs/code-signing/wac/
    )
