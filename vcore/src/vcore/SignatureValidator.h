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
#ifndef _SIGNATUREVALIDATOR_H_
#define _SIGNATUREVALIDATOR_H_

#include <dpl/singleton.h>

#include "Certificate.h"
#include "OCSPCertMgrUtil.h"
#include "SignatureData.h"

#include "ValidatorCommon.h"
#include "VerificationStatus.h"

namespace ValidationCore {
// Todo nocopyable
class SignatureValidator
{
  public:
    enum Result
    {
        SIGNATURE_VALID,
        SIGNATURE_INVALID,
        SIGNATURE_VERIFIED,
        SIGNATURE_DISREGARD,    // no ocsp response or ocsp return unknown status
        SIGNATURE_REVOKED
    };

    /**
     * Validation of the signature.
     * If falidation succeed SignatureData will contains:
     *   list of validated references
     *   set selfSigned value
     *   root ca certificate
     *   end entity certificate
     */
    Result check(SignatureData &data,
            const std::string &widgetContentPath);

    static std::string FingerprintToColonHex(
            const Certificate::Fingerprint &fingerprint);

    explicit SignatureValidator(bool ocspEnable,
                                bool crlEnable,
                                bool complianceMode);
    virtual ~SignatureValidator();

  private:
    bool checkRoleURI(const SignatureData &data);
    bool checkProfileURI(const SignatureData &data);
    bool checkObjectReferences(const SignatureData &data);

    bool m_ocspEnable;
    bool m_crlEnable;
    bool m_complianceModeEnabled;
};

} // namespace ValidationCore

#endif // _SIGNATUREVALIDATOR_H_
