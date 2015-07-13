/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <vcore/WrtSignatureValidator.h>

#include "TestEnv.h"

#define WRTSIGNATURE_ERRORDESCRIBE(name) case ValidationCore::WrtSignatureValidator::name: return #name
const char *wrtValidatorErrorToString(int error)
{
    switch (error) {
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_VALID);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_VERIFIED);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_DISREGARD);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_REVOKED);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_CERT_CHAIN);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_DISTRIBUTOR_CERT);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_SDK_DEFAULT_AUTHOR_CERT);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_CERT_TIME);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_NO_DEVICE_PROFILE);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_DEVICE_UNIQUE_ID);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_NO_HASH_FILE);
        WRTSIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_HASH_SIGNATURE);
    default:
        return "Invalid error code.";
    }
}
#undef WRTSIGNATURE_ERRORDESCRIBE

