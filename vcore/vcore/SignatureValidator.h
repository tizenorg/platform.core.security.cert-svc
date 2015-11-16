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
#include <memory>

#include <vcore/Certificate.h>
#include <vcore/SignatureData.h>
#include <vcore/SignatureFinder.h>
#include <vcore/Error.h>

namespace ValidationCore {

using UriList = std::list<std::string>;

/*
 *  Error code defined on vcore/Error.h
 */
class SignatureValidator {
public:
    SignatureValidator(const SignatureFileInfo &info);
    virtual ~SignatureValidator();

    SignatureValidator() = delete;
    SignatureValidator(const SignatureValidator &) = delete;
    const SignatureValidator &operator=(const SignatureValidator &) = delete;

    VCerr check(
        const std::string &contentPath,
        bool checkOcsp,
        bool checkReferences,
        SignatureData &outData);

    VCerr checkList(
        const std::string &contentPath,
        const UriList &uriList,
        bool checkOcsp,
        bool checkReferences,
        SignatureData &outData);

    /*
     *  @Remarks : cert list isn't completed with self-signed root CA system cert
     *             if completeWithSystemCert is false.
     */
    VCerr makeChainBySignature(
        bool completeWithSystemCert,
        CertificateList &certList);

    std::string errorToString(int code);

private:
    class Impl;
    std::unique_ptr<Impl> m_pImpl;
};

} // namespace ValidationCore

#endif // _VALIDATION_CORE_SIGNATUREVALIDATOR_H_
