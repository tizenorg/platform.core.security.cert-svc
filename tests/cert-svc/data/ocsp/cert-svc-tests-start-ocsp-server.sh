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

pkill -9 openssl # if previously it was launched and openssl didn't close sockets

echo "starting OCSP server"
OPENSSL_CONF=/opt/share/cert-svc/tests/orig_c/data/ocsp/demoCA/openssl.cnf openssl ocsp -index /opt/share/cert-svc/tests/orig_c/data/ocsp/demoCA/index.txt -port 8888 -rsigner /opt/share/cert-svc/tests/orig_c/data/ocsp/ocsp_signer.crt -rkey /opt/share/cert-svc/tests/orig_c/data/ocsp/ocsp_signer.key -CA /opt/share/cert-svc/tests/orig_c/data/ocsp/demoCA/cacert.pem -text -out /opt/share/cert-svc/tests/orig_c/data/ocsp/log.txt & 

echo "--- OCSP server shutdown..."

