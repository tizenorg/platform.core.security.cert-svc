#!/bin/sh
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
source /etc/tizen-platform.conf

LOCAL_VCORE_OCSP_WORKSPACE=${TZ_SYS_RO_APP}/widget/tests/vcore_certs

pkill -9 openssl # if previously it was launched and openssl didn't close sockets

OPENSSL_CONF=${LOCAL_VCORE_OCSP_WORKSPACE}/openssl.cnf openssl ocsp \
-nrequest 5 \
-index ${LOCAL_VCORE_OCSP_WORKSPACE}/demoCA/index.txt \
-port 8881 \
-rsigner ${LOCAL_VCORE_OCSP_WORKSPACE}/respcert.pem \
-rkey ${LOCAL_VCORE_OCSP_WORKSPACE}/respcert.key \
-CA ${LOCAL_VCORE_OCSP_WORKSPACE}/demoCA/cacert.pem

echo "--- OCSP server shutdown..."
