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
#include "TestEnv.h"

#define SIGNATURE_ERRORDESCRIBE(name) case ValidationCore::SignatureValidator::name: return #name
const char *validatorErrorToString(ValidationCore::SignatureValidator::Result error)
{
    switch (error) {
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_VALID);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_VERIFIED);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_DISREGARD);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_REVOKED);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_CERT_CHAIN);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_DISTRIBUTOR_CERT);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_SDK_DEFAULT_AUTHOR_CERT);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_CERT_TIME);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_NO_DEVICE_PROFILE);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_DEVICE_UNIQUE_ID);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_NO_HASH_FILE);
        SIGNATURE_ERRORDESCRIBE(SIGNATURE_INVALID_HASH_SIGNATURE);
    default:
        return "Invalid error code.";
    }
}
#undef SIGNATURE_ERRORDESCRIBE

