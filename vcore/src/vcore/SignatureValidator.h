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
/*
 * @file        SignatureValidator.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.1
 * @brief       Implementatin of tizen signature validation protocol.
 */
#ifndef _VALIDATION_CORE_SIGNATUREVALIDATOR_H_
#define _VALIDATION_CORE_SIGNATUREVALIDATOR_H_

#include <string>
#include <list>
#include <vcore/SignatureData.h>
#include <vcore/SignatureFinder.h>

namespace ValidationCore {

class SignatureValidator {
public:
    enum Result
    {
        SIGNATURE_VALID,
        SIGNATURE_INVALID,
        SIGNATURE_VERIFIED,
        SIGNATURE_DISREGARD,
        SIGNATURE_REVOKED
    };

    SignatureValidator() = delete;
    SignatureValidator(const SignatureValidator &) = delete;
    const SignatureValidator &operator=(const SignatureValidator &) = delete;

    virtual ~SignatureValidator();

    static Result check(
        const SignatureFileInfo &fileInfo,
        const std::string &widgetContentPath,
        bool checkOcsp,
        bool checkReferences,
        SignatureData &outData);

    static Result checkList(
        const SignatureFileInfo &fileInfo,
        const std::string &widgetContentPath,
        const std::list<std::string> &uriList,
        bool checkOcsp,
        bool checkReferences,
        SignatureData &outData);
};

} // namespace ValidationCore

#endif // _VALIDATION_CORE_SIGNATUREVALIDATOR_H_
