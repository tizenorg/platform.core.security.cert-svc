/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "test-common.h"

namespace TestData {

const std::string ServerPfxWithPassPath    = std::string(TESTAPP_RES_DIR) + "p12/wifiserver.pfx";
const std::string ServerPfxWithPass2Path   = std::string(TESTAPP_RES_DIR) + "p12/test.pfx";
const std::string ServerPfxWithoutPassPath = std::string(TESTAPP_RES_DIR) + "p12/without_pass.p12";
const std::string UserP12WithPassPath      = std::string(TESTAPP_RES_DIR) + "p12/wifiuser.p12";
const std::string ServerCertPemPath        = std::string(TESTAPP_RES_DIR) + "p12/wifi-server.pem";
const std::string CertCrtPath              = std::string(TESTAPP_RES_DIR) + "p12/Testing.crt";
const std::string InvalidCertCrtPath       = std::string(TESTAPP_RES_DIR) + "p12/InvalidCrt.crt";
const std::string ServerPfxPass            = "wifi";
const std::string ServerPfx2Pass           = "wifi";
const std::string UserP12Pass              = "wifi";

}
