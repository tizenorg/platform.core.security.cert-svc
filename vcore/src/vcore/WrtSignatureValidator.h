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
 * @file        WrtSignatureValidator.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementatin of tizen signature validation protocol.
 */
#ifndef _VALIDATION_CORE_TIZENSIGNATUREVALIDATOR_H_
#define _VALIDATION_CORE_TIZENSIGNATUREVALIDATOR_H_

#include <string>

#include <vcore/SignatureData.h>

namespace ValidationCore {

class WrtSignatureValidator {
public:

    class Impl;

    enum AppType
    {
        TIZEN,
        WAC20
    };

    enum Result
    {
        SIGNATURE_VALID,
        SIGNATURE_INVALID,
        SIGNATURE_VERIFIED,
        SIGNATURE_DISREGARD,    // no ocsp response or ocsp return unknown status
        SIGNATURE_REVOKED,
		SIGNATURE_INVALID_CERT_CHAIN, //5, from here, new error enum	 	
		SIGNATURE_INVALID_DISTRIBUTOR_CERT,
		SIGNATURE_INVALID_SDK_DEFAULT_AUTHOR_CERT,
		SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT,
		SIGNATURE_INVALID_CERT_TIME,	
		SIGNATURE_NO_DEVICE_PROFILE,
		SIGNATURE_INVALID_DEVICE_UNIQUE_ID,
		SIGNATURE_INVALID_NO_HASH_FILE,
		SIGNATURE_INVALID_HASH_SIGNATURE
    };

    WrtSignatureValidator() = delete;
    WrtSignatureValidator(const WrtSignatureValidator &) = delete;
    const WrtSignatureValidator &operator=(const WrtSignatureValidator &) = delete;

    explicit WrtSignatureValidator(
        AppType appType,
        bool ocspEnable,
        bool crlEnable,
        bool complianceMode);

    virtual ~WrtSignatureValidator();

    Result check(
        SignatureData &data,
        const std::string &widgetContentPath);

private:
    Impl *m_impl;

};

} // namespace ValidationCore

#endif // _VALIDATION_CORE_TIZENSIGNATUREVALIDATOR_H_

