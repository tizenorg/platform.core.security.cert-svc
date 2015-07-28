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
 * @file        Certificate.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#include <vcore/Certificate.h>

#include <memory>
#include <sstream>
#include <iomanip>

#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include <dpl/assert.h>
#include <dpl/log/log.h>

#include <vcore/Base64.h>
#include <vcore/TimeConversion.h>

namespace ValidationCore {

Certificate::Certificate(X509 *cert)
{
    Assert(cert);
    m_x509 = X509_dup(cert);
    if (!m_x509)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Internal Openssl error in d2i_X509 function.");
}

Certificate::Certificate(cert_svc_mem_buff &buffer)
{
    Assert(buffer.data);
    const unsigned char *ptr = buffer.data;
    m_x509 = d2i_X509(NULL, &ptr, buffer.size);
    if (!m_x509)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Internal Openssl error in d2i_X509 function.");
}

Certificate::Certificate(const std::string &data,
                         Certificate::FormType form)
{
    Assert(data.size());

    int size;
    const unsigned char *ptr;
    std::string tmp = data;

    // transform to DER format
    if (FORM_BASE64 == form) {
        try {
            Base64Decoder base64;
            base64.reset();
            base64.append(data);
            if (!base64.finalize()) {
                LogWarning("Error during decoding");
            }
            tmp = base64.get();
        } catch (const Base64Decoder::Exception::Base &e) {
            LogError("Exception in Certificate constructor : " << e.DumpToString());
            VcoreThrowMsg(Certificate::Exception::Base64Error, "Failed to Base64Decoder");
        }
    }

    ptr = reinterpret_cast<const unsigned char*>(tmp.c_str());
    size = static_cast<int>(tmp.size());

    m_x509 = d2i_X509(NULL, &ptr, size);
    if (!m_x509)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Internal Openssl error in d2i_X509 function.");
}

Certificate::~Certificate()
{
    X509_free(m_x509);
}

X509* Certificate::getX509(void) const
{
    return m_x509;
}

std::string Certificate::getDER(void) const
{
    unsigned char *rawDer = NULL;
    int size = i2d_X509(m_x509, &rawDer);
    if (!rawDer || size <= 0)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "i2d_X509 failed");

    std::string output(reinterpret_cast<char*>(rawDer), size);
    OPENSSL_free(rawDer);
    return output;
}

std::string Certificate::getBase64(void) const
{
    Base64Encoder base64;
    try {
        base64.reset();
        base64.append(getDER());
        base64.finalize();
    } catch (const Base64Encoder::Exception::Base &e) {
        LogError("Exception in Certificate getBase64 : " << e.DumpToString());
        VcoreThrowMsg(Certificate::Exception::Base64Error, "Failed to Base64Encoder");
    }
    return base64.get();
}

bool Certificate::isSignedBy(const CertificatePtr &parent) const
{
    if (!parent) {
        LogDebug("Invalid certificate parameter.");
        return false;
    }
    return 0 == X509_NAME_cmp(X509_get_subject_name(parent->m_x509),
                              X509_get_issuer_name(m_x509));
}

Certificate::Fingerprint Certificate::getFingerprint(
        Certificate::FingerprintType type) const
{
    unsigned int fingerprintlength = EVP_MAX_MD_SIZE;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    Fingerprint raw;

    if (type == FINGERPRINT_MD5) {
        if (!X509_digest(m_x509, EVP_md5(), fingerprint, &fingerprintlength))
            VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                          "MD5 digest counting failed!");
    }

    if (type == FINGERPRINT_SHA1) {
        if (!X509_digest(m_x509, EVP_sha1(), fingerprint, &fingerprintlength))
            VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                          "SHA1 digest counting failed");
    }

    raw.resize(fingerprintlength); // improve performance
    std::copy(fingerprint, fingerprint + fingerprintlength, raw.begin());

    return raw;
}

X509_NAME *Certificate::getX509Name(FieldType type) const
{
    X509_NAME *name = NULL;

    switch (type) {
    case FIELD_ISSUER:
        name = X509_get_issuer_name(m_x509);
        break;
    case FIELD_SUBJECT:
        name = X509_get_subject_name(m_x509);
        break;
    default:
        Assert("Invalid field type.");
    }

    if (!name)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error during x509 name extraction.");

    return name;
}

std::string Certificate::getOneLine(FieldType type) const
{
    X509_NAME *name = getX509Name(type);
    static const int MAXB = 1024;
    char buffer[MAXB] = {0, };
    X509_NAME_oneline(name, buffer, MAXB);

    return std::string(buffer);
}

std::string Certificate::getField(FieldType type, int fieldNid) const
{
    X509_NAME *subjectName = getX509Name(type);
    X509_NAME_ENTRY *subjectEntry = NULL;
    std::string output;
    int entryCount = X509_NAME_entry_count(subjectName);

    for (int i = 0; i < entryCount; ++i) {
        subjectEntry = X509_NAME_get_entry(subjectName,
                                           i);

        if (!subjectEntry) {
            continue;
        }

        int nid = OBJ_obj2nid(
            static_cast<ASN1_OBJECT*>(
                    X509_NAME_ENTRY_get_object(subjectEntry)));

        if (nid != fieldNid) {
            continue;
        }

        ASN1_STRING* pASN1Str = subjectEntry->value;

        unsigned char* pData = NULL;
        int nLength = ASN1_STRING_to_UTF8(&pData,
                                          pASN1Str);

        if (nLength < 0)
            VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                          "Reading field error.");

        if (!pData) {
            output = std::string();
        }
        else {
            output = std::string(reinterpret_cast<char*>(pData), nLength);
            OPENSSL_free(pData);
        }
    }

    return output;
}

std::string Certificate::getCommonName(FieldType type) const
{
    return getField(type, NID_commonName);
}

std::string Certificate::getCountryName(FieldType type) const
{
    return getField(type, NID_countryName);
}

std::string Certificate::getStateOrProvinceName(FieldType type) const
{
    return getField(type, NID_stateOrProvinceName);
}

std::string Certificate::getLocalityName(FieldType type) const
{
    return getField(type, NID_localityName);
}

std::string Certificate::getOrganizationName(FieldType type) const
{
    return getField(type, NID_organizationName);
}

std::string Certificate::getOrganizationalUnitName(FieldType type) const
{
    return getField(type, NID_organizationalUnitName);
}

std::string Certificate::getEmailAddres(FieldType type) const
{
    return getField(type, NID_pkcs9_emailAddress);
}

std::string Certificate::getOCSPURL() const
{
    // TODO verify this code
    std::string retValue;
    AUTHORITY_INFO_ACCESS *aia = static_cast<AUTHORITY_INFO_ACCESS*>(
            X509_get_ext_d2i(m_x509,
                             NID_info_access,
                             NULL,
                             NULL));

    // no AIA extension in the cert
    if (NULL == aia) {
        return retValue;
    }

    int count = sk_ACCESS_DESCRIPTION_num(aia);

    for (int i = 0; i < count; ++i) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);

        if (OBJ_obj2nid(ad->method) == NID_ad_OCSP &&
            ad->location->type == GEN_URI)
        {
            void *data = ASN1_STRING_data(ad->location->d.ia5);
            if (!data)
                retValue = std::string();
            else
                retValue = std::string(static_cast<char *>(data));
            break;
        }
    }
    sk_ACCESS_DESCRIPTION_free(aia);
    return retValue;
}

Certificate::AltNameSet Certificate::getAlternativeNameDNS() const
{
    AltNameSet set;

    GENERAL_NAME *namePart = NULL;

    STACK_OF(GENERAL_NAME)* san =
        static_cast<STACK_OF(GENERAL_NAME)*>(
            X509_get_ext_d2i(m_x509,NID_subject_alt_name,NULL,NULL));

    while (sk_GENERAL_NAME_num(san) > 0) {
        namePart = sk_GENERAL_NAME_pop(san);
        if (GEN_DNS == namePart->type) {
            char *temp = reinterpret_cast<char *>(ASN1_STRING_data(namePart->d.dNSName));
            if (!temp) {
                set.insert(std::string());
            }
            else {
                set.insert(std::string(temp));
                LogDebug("FOUND GEN_DNS: " << temp);
            }
        } else {
            LogDebug("FOUND GEN TYPE ID: " << namePart->type);
        }
    }
    return set;
}

time_t Certificate::getNotAfter() const
{
    ASN1_TIME *time = X509_get_notAfter(m_x509);
    if (!time)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Reading Not After error.");

    time_t output;
    if (asn1TimeToTimeT(time, &output))
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Converting ASN1_time to time_t error.");

    return output;
}

time_t Certificate::getNotBefore() const
{
    ASN1_TIME *time = X509_get_notBefore(m_x509);
    if (!time)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Reading Not Before error.");

    time_t output;
    if (asn1TimeToTimeT(time, &output))
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Converting ASN1_time to time_t error.");

    return output;
}

ASN1_TIME* Certificate::getNotAfterTime() const
{
    ASN1_TIME *timeafter = X509_get_notAfter(m_x509);
    if (!timeafter)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Reading Not After error.");

    return timeafter;
}

ASN1_TIME* Certificate::getNotBeforeTime() const
{
    ASN1_TIME *timebefore = X509_get_notBefore(m_x509);
    if (!timebefore)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Reading Not Before error.");

    return timebefore;
}

bool Certificate::isRootCert()
{
    // based on that root certificate has the same subject as issuer name
    return isSignedBy(this->shared_from_this());
}

long Certificate::getVersion() const
{
    return X509_get_version(m_x509);
}

std::string Certificate::getSerialNumberString() const
{
    ASN1_INTEGER *ai = X509_get_serialNumber(m_x509);
    if (!ai)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in X509_get_serialNumber");

    std::stringstream stream;
    stream << std::hex << std::setfill('0');
    if (ai->type == V_ASN1_NEG_INTEGER) {
        stream << "(Negetive) ";
    }
    for (int i=0; i<ai->length; ++i) {
        stream << std::setw(2) << (int)ai->data[i] << ":";
    }
    std::string data = stream.str();
    if (!data.empty()) {
        data.erase(--data.end());
    }

    return data;
}

std::string Certificate::getKeyUsageString() const
{
    // Extensions were defined in RFC 3280
    const char *usage[] = {
        "digitalSignature",
        "nonRepudiation",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
        "decipherOnly"
    };
    int crit = -1;
    int idx = -1;
    ASN1_BIT_STRING *keyUsage = (ASN1_BIT_STRING*)
        X509_get_ext_d2i(m_x509, NID_key_usage, &crit, &idx);

    std::stringstream stream;
    for(int i=0; i<9; ++i) {
        if (ASN1_BIT_STRING_get_bit(keyUsage, i)) {
            stream << usage[i] << ",";
        }
    }
    std::string result = stream.str();
    if (!result.empty()) {
        result.erase(--result.end());
    }

    return result;
}

std::string Certificate::getSignatureAlgorithmString() const
{
    std::unique_ptr<BIO, std::function<int(BIO*)>>
        b(BIO_new(BIO_s_mem()),BIO_free);

    if (!b.get())
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in BIO_new");

    if (i2a_ASN1_OBJECT(b.get(), m_x509->cert_info->signature->algorithm) < 0)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in i2a_ASN1_OBJECT");

    BUF_MEM *bptr = 0;
    BIO_get_mem_ptr(b.get(), &bptr);
    if (bptr == 0)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in BIO_get_mem_ptr");

    std::string result(bptr->data, bptr->length);

    return result;
}

std::string Certificate::getPublicKeyString() const
{
    std::unique_ptr<BIO, std::function<int(BIO*)>>
        b(BIO_new(BIO_s_mem()),BIO_free);

    if (!b.get())
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in BIO_new");

    EVP_PKEY *pkey = X509_get_pubkey(m_x509);
    if (!pkey)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in X509_get_pubkey");

    EVP_PKEY_print_public(b.get(), pkey, 16, NULL);
    EVP_PKEY_free(pkey);

    BUF_MEM *bptr = 0;
    BIO_get_mem_ptr(b.get(), &bptr);
    if (bptr == 0)
        VcoreThrowMsg(Certificate::Exception::OpensslInternalError,
                      "Error in BIO_get_mem_ptr");

    std::string result(bptr->data, bptr->length);

    return result;
}

int Certificate::isCA() const
{
    return X509_check_ca(m_x509);
}

std::string Certificate::FingerprintToColonHex(
        const Certificate::Fingerprint &fingerprint)
{
    std::string outString;
    char buff[8];

    for (size_t i = 0; i < fingerprint.size(); ++i) {
        snprintf(buff,
                 sizeof(buff),
                 "%02X:",
                 static_cast<unsigned int>(fingerprint[i]));
        outString += buff;
    }

    // remove trailing ":"
    outString.erase(outString.end() - 1);
    return outString;
}

} //  namespace ValidationCore
