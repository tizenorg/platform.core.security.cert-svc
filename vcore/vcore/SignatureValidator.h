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
 *  Types of Reference checking
 *
 *  1. XmlSec validate (default)
 *        - check reference based on Reference tag on signature xml.
 *        - Get URI from Reference tag, generate digest value and compare it with value written
 *        - If value with calculated and written isn't same, validate fail returned.
 *        * What if file doesn't exist which is written on Reference tag?
 *        * What if Reference tag doesn't exist for existing file? -> cannot checked.
 *
 *  2. checkObjectReferences (default on check function, not checkList)
 *        - check Reference of 'Object' tag.
 *        - it's mutual-exclusive check with  1. XmlSec validate.
 *
 *  3. ReferenceValidator (enabled when flag on)
 *        - check file based on content path from parameter
 *        - check is all existing file is on the Reference tag list on signature xml
 *        - If file path(URI) cannot found on reference set, validate fail returned.
 *
 *
 *  Signature validation disregarded case
 *
 *  1. author signature: store id contains TIZEN_DEVELOPER
 *
 *  2. distributor signature: signature number is 1
 *                            and doesn't contain visibility in store id set
 */

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
