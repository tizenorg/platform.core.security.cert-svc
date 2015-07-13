#!/bin/sh
# Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

LOCAL_OCSP_WORKSPACE=${TZ_SYS_SHARE}/cert-svc/tests/orig_c/data/ocsp

pkill -9 openssl # if previously it was launched and openssl didn't close sockets

echo "starting OCSP server"
OPENSSL_CONF=${LOCAL_OCSP_WORKSPACE}/demoCA/openssl.cnf openssl ocsp \
-index ${LOCAL_OCSP_WORKSPACE}/demoCA/index.txt \
-port 8888 -rsigner ${LOCAL_OCSP_WORKSPACE}/ocsp_signer.crt \
-rkey ${LOCAL_OCSP_WORKSPACE}/ocsp_signer.key \
-CA ${LOCAL_OCSP_WORKSPACE}/demoCA/cacert.pem -text \
-out ${LOCAL_OCSP_WORKSPACE}/log.txt &

echo "--- OCSP server shutdown..."

