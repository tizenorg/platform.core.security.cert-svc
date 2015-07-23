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
#include <dpl/assert.h>
#include <openssl/x509v3.h>
#include <dpl/log/log.h>
#include <dpl/noncopyable.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <vcore/Base64.h>
#include <vcore/CertificateLoader.h>

namespace {
const int MIN_RSA_KEY_LENGTH = 1024;
} // namespace anonymous

namespace ValidationCore {
CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnExponentAndModulus(const std::string &m_modulus,
        const std::string &m_exponent)
{
    (void) m_modulus;
    (void) m_exponent;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::loadCertificate(
        const std::string &storageName,
        CertificateLoader::CertificateLoaderComparator *cmp)
{
    (void) storageName;
    (void) cmp;
    LogError("Not Implemented");
    return UNKNOWN_ERROR;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnSubjectName(const std::string &subjectName)
{
    (void) subjectName;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateWithECKEY(const std::string &curveName,
        const std::string &publicKey)
{
    (void) curveName;
    (void) publicKey;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::loadCertificateFromRawData(const std::string &rawData)
{
    VcoreTry {
        m_certificatePtr = CertificatePtr(new Certificate(rawData, Certificate::FORM_BASE64));
    } VcoreCatch(Certificate::Exception::Base) {
        LogWarning("Error reading certificate by openssl.");
        return UNKNOWN_ERROR;
    }

    // Check the key length if sig algorithm is RSA
    EVP_PKEY *pKey = X509_get_pubkey(m_certificatePtr->getX509());

    if (pKey != NULL) {
        if (pKey->type == EVP_PKEY_RSA) {
            RSA* pRSA = pKey->pkey.rsa;

            if (pRSA) {
                int keyLength = RSA_size(pRSA);

                // key Length (modulus) is in bytes
                keyLength <<= 3;
                LogDebug("RSA key length: " << keyLength << " bits");

                if (keyLength < MIN_RSA_KEY_LENGTH) {
                    LogError("RSA key too short! Has only " << keyLength << " bits");
                    return CERTIFICATE_SECURITY_ERROR;
                }
            }
        }
    }

    return NO_ERROR;
}

CertificateLoader::CertificateLoaderResult CertificateLoader::
    loadCertificateBasedOnDSAComponents(const std::string& strP,
        const std::string& strQ,
        const std::string& strG,
        const std::string& strY,
        const std::string& strJ,
        const std::string& strSeed,
        const std::string& strPGenCounter)
{
    (void) strP;
    (void) strQ;
    (void) strG;
    (void) strY;
    (void) strJ;
    (void) strSeed;
    (void) strPGenCounter;
    LogError("Not implemented.");
    return UNKNOWN_ERROR;
}

bool CertificateLoader::convertBase64NodeToBigNum(const std::string& strNode,
        BIGNUM** ppBigNum)
{
    (void) strNode;
    (void) ppBigNum;
    LogError("Not implemented.");
    return false;
}

} // namespace ValidationCore

