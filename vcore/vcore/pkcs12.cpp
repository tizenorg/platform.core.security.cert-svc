/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        pkcs12.cpp
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 container manipulation routines.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <memory>
#include <functional>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "dpl/log/log.h"
#include "cert-svc/cerror.h"

#include "vcore/Certificate.h"
#include "vcore/Client.h"
#include "vcore/pkcs12.h"

#define SYSCALL(call) while(((call) == -1) && (errno == EINTR))

namespace {

static const std::string START_CERT    = "-----BEGIN CERTIFICATE-----";
static const std::string END_CERT      = "-----END CERTIFICATE-----";
static const std::string START_TRUSTED = "-----BEGIN TRUSTED CERTIFICATE-----";
static const std::string END_TRUSTED   = "-----END TRUSTED CERTIFICATE-----";
static const std::string START_KEY     = "-----BEGIN PRIVATE KEY-----";
static const std::string END_KEY       = "-----END PRIVATE KEY-----";

using CertificatePtr = ValidationCore::CertificatePtr;
using Certificate = ValidationCore::Certificate;

using FileUniquePtr = std::unique_ptr<FILE, std::function<int(FILE*)>>;
using BioUniquePtr = std::unique_ptr<BIO, std::function<void(BIO*)>>;
using PKEYUniquePtr = std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>;
using X509UniquePtr = std::unique_ptr<X509, std::function<void(X509*)>>;
using X509StackUniquePtr = std::unique_ptr<STACK_OF(X509), std::function<void(STACK_OF(X509)*)>>;

void X509_stack_free(STACK_OF(X509) *stack)
{
    sk_X509_free(stack);
}

inline bool hasStore(CertStoreType types, CertStoreType type)
{
    return (types & type) != 0;
}

inline CertStoreType nextStore(CertStoreType type)
{
    switch (type) {
    case NONE_STORE:   return VPN_STORE;
    case VPN_STORE:    return WIFI_STORE;
    case WIFI_STORE:   return EMAIL_STORE;
    case EMAIL_STORE:  return SYSTEM_STORE;
    case SYSTEM_STORE: return NONE_STORE;
    default:           return NONE_STORE;
    }
}

std::string generateGname(void)
{
    int generator;
    int64_t random;
    SHA_CTX ctx;
    unsigned char d[SHA_DIGEST_LENGTH];
    int result;
    char *gname = NULL;

    SYSCALL(generator = open("/dev/urandom", O_RDONLY));
    if (generator == -1)
        return std::string();
    SYSCALL(result = read(generator, &random, sizeof(random)));
    if (result == -1) {
        SYSCALL(close(generator));
        return std::string();
    }
    SYSCALL(result = close(generator));
    if (result == -1)
        return std::string();

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, &random, sizeof(random));
    SHA1_Final(d, &ctx);

    result = asprintf(&gname,
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9],
             d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17], d[18], d[19]);

    if (result == -1)
        return std::string();

    std::string ret(gname);

    free(gname);

    return ret;
}

std::string getCommonName(CertType type, const std::string &cert)
{
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (bio.get() == NULL) {
        LogError("Failed to allocate memory.");
        return std::string();
    }

    auto readCount = BIO_write(bio.get(), (const void *)cert.data(), (int)cert.length());
    if (readCount < 1) {
        LogError("Failed to load cert into bio.");
        return std::string();
    }

    X509 *x509 = NULL;
    switch (type) {
    case P12_TRUSTED:
    case P12_INTERMEDIATE:
        x509 = PEM_read_bio_X509_AUX(bio.get(), NULL, 0, NULL);
        break;

    default:
        x509 = PEM_read_bio_X509(bio.get(), NULL, 0, NULL);
        break;
    }

    if (x509 == NULL) {
        LogError("Failed to create x509 structure.");
        return std::string();
    }

    X509UniquePtr x509Ptr(x509, X509_free);

    const char *subject_c = X509_NAME_oneline(x509->cert_info->subject, NULL, 0);
    if (subject_c == NULL) {
        LogError("Failed to parse x509 structure");
        return std::string();
    }

    return std::string(subject_c);
}

/*
 *  column           / common name / associated gname / prikey gname /
 *  PEM_CRT          : common name / gname            / none         /
 *  P12_END_USER     : alias       / gname            / prikey gname /
 *  P12_TRUSTED      : common name / end cert gname   / none         /
 *  P12_INTERMEDIATE : common name / end cert gname   / none         /
 */

int installPKEY(CertStoreType storeType,
                const std::string &key,
                const std::string &gname)
{
    return vcore_client_install_certificate_to_store(
            storeType,
            gname.c_str(),
            NULL,
            NULL,
            NULL,
            key.c_str(),
            key.length(),
            P12_PKEY);
}

int installEndCert(CertStoreType storeType,
                   const std::string &cert,
                   const std::string &alias,
                   const std::string &gname,
                   const std::string &prikeyGname)
{
    return vcore_client_install_certificate_to_store(
            storeType,
            gname.c_str(),
            alias.c_str(),
            prikeyGname.c_str(),
            gname.c_str(),
            cert.c_str(),
            cert.length(),
            P12_END_USER);
}

int installChainCert(CertStoreType storeType,
                     const std::string &cert,
                     const std::string &gname,
                     const std::string &endCertGname,
                     CertType type)
{
    std::string commonName = getCommonName(type, cert);

    return vcore_client_install_certificate_to_store(
            storeType,
            gname.c_str(),
            commonName.c_str(),
            NULL,
            endCertGname.c_str(),
            cert.c_str(),
            cert.length(),
            type);
}
int installCert(CertStoreType storeType,
                const std::string &cert,
                const std::string &gname)
{
    std::string commonName = getCommonName(PEM_CRT, cert);

    return vcore_client_install_certificate_to_store(
            storeType,
            gname.c_str(),
            commonName.c_str(),
            NULL,
            NULL,
            cert.c_str(),
            cert.length(),
            PEM_CRT);
}

std::string readFromFile(const std::string &path)
{
    FILE *fp = NULL;
    if ((fp = fopen(path.c_str(), "rb")) == NULL) {
        LogError("Fail to open file for reading : " << path);
        return std::string();
    }

    FileUniquePtr filePtr(fp, fclose);

    fseek(fp, 0L, SEEK_END);
    int len = ftell(fp);
    if (len <= 0) {
        LogError("Fail to get certificate length.");
        return std::string();
    }

    rewind(fp);

    char *content = (char *)malloc(sizeof(char) * (len + 1));
    if (content == NULL) {
        LogError("Fail to allocate memory");
        return std::string();
    }

    memset(content, 0x00, len + 1);
    size_t readLen = fread(content, sizeof(char), (size_t)len, fp);
    if (readLen != (size_t)len) {
        LogError("Fail to read file : " << path);
        free(content);
        return std::string();
    }

    content[len] = '\0';

    std::string ret(content);

    free(content);

    return ret;
}

std::string parseCRT(const std::string &cert)
{
    size_t from = 0;
    size_t to = 0;
    size_t tailLen = 0;

    from = cert.find(START_CERT);
    to = cert.find(END_CERT);
    tailLen = END_CERT.length();

    if (from == std::string::npos || to == std::string::npos || from > to) {
        from = cert.find(START_TRUSTED);
        to = cert.find(END_TRUSTED);
        tailLen = END_TRUSTED.length();
    }

    if (from == std::string::npos || to == std::string::npos || from > to)
        return std::string();

    return std::string(cert, from, to - from + tailLen);
}

#define _CERT_SVC_VERIFY_PKCS12
int verify_cert_details(X509 *cert, STACK_OF(X509) *certv)
{
    int result = CERTSVC_SUCCESS;
    char* pSubject = NULL;
    char* pIssuerName = NULL;
    X509_STORE_CTX *cert_ctx = NULL;
    X509_STORE *cert_store = NULL;
    int res = 0;

#ifdef _CERT_SVC_VERIFY_PKCS12
    if (certv == NULL) {
        pSubject = X509_NAME_oneline(cert->cert_info->subject, NULL, 0);
        if (!pSubject) {
            LogError("Failed to get subject name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        pIssuerName = X509_NAME_oneline(cert->cert_info->issuer, NULL, 0);
        if (!pIssuerName) {
            LogError("Failed to get issuer name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        if (strcmp((const char*)pSubject, (const char*)pIssuerName) == 0) {
            /*self signed.. */
            EVP_PKEY *pKey = NULL;
            pKey = X509_get_pubkey(cert);
            if (!pKey) {
                LogError("Failed to get public key");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            if (X509_verify(cert, pKey) <= 0) {
                LogError("P12 verification failed");
                EVP_PKEY_free(pKey);
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            LogDebug("P12 verification Success");
            EVP_PKEY_free(pKey);
        } else {
            cert_store = X509_STORE_new();
            if (!cert_store) {
                LogError("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_load_locations(cert_store, NULL, "/opt/etc/ssl/certs/");
            if (res != 1) {
                LogError("P12 load certificate store failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_set_default_paths(cert_store);
            if (res != 1) {
                LogError("P12 load certificate store path failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* initialise store and store context */
            cert_ctx = X509_STORE_CTX_new();
            if (cert_ctx == NULL) {
                LogError("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* construct store context */
            if (!X509_STORE_CTX_init(cert_ctx, cert_store, cert, NULL)) {
                LogError("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

#ifdef P12_VERIFICATION_NEEDED
            res = X509_verify_cert(cert_ctx);
            if (res != 1) {
                LogError("P12 verification failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            LogDebug("P12 verification Success");
#endif
        }
    } else if (certv != NULL) {
        /* Cert Chain */
        cert_store = X509_STORE_new();
        if (!cert_store) {
            LogError("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_load_locations(cert_store, NULL, SYSTEM_CERT_DIR);
        if (res != 1) {
            LogError("P12 load certificate store failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_set_default_paths(cert_store);
        if (res != 1) {
            LogError("P12 load certificate path failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* initialise store and store context */
        cert_ctx = X509_STORE_CTX_new();
        if (cert_ctx == NULL) {
            LogError("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* construct store context */
        if (!X509_STORE_CTX_init(cert_ctx, cert_store, cert, NULL)) {
            LogError("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        X509_STORE_CTX_trusted_stack(cert_ctx, certv);
#ifdef P12_VERIFICATION_NEEDED
        res = X509_verify_cert(cert_ctx);
        if (res != 1) {
            LogError("P12 verification failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }
        LogDebug("P12 verification Success");
#endif
    }
#endif //_CERT_SVC_VERIFY_PKCS12

free_memory:
    if (cert_store != NULL)
        X509_STORE_free(cert_store);
    if (cert_ctx)
        X509_STORE_CTX_free(cert_ctx);

    free(pSubject);
    free(pIssuerName);

    return result;
}

enum class OsslType : int {
    PKEY = 1,
    X509,
    X509AUX
};

std::string osslToPEM(OsslType type, void *data)
{
    std::vector<char> buf(4096);
    BioUniquePtr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (bio.get() == NULL)
        return std::string();

    switch (type) {
    case OsslType::PKEY:
        PEM_write_bio_PrivateKey(bio.get(), static_cast<EVP_PKEY *>(data), NULL, NULL, 0, NULL, NULL);
        break;

    case OsslType::X509:
        PEM_write_bio_X509(bio.get(), static_cast<X509 *>(data));
        break;

    case OsslType::X509AUX:
        PEM_write_bio_X509_AUX(bio.get(), static_cast<X509 *>(data));
        break;

    default:
        break;
    }

    int size = BIO_read(bio.get(), buf.data(), 4096);
    if (size <= 0)
        return std::string();

    buf[size] = '\0';

    return std::string(buf.data());
}

int extractPkcs12(const std::string &path,
                  const std::string &password,
                  PKEYUniquePtr &keyPtr,
                  X509UniquePtr &certPtr,
                  X509StackUniquePtr &certvPtr)
{
    FILE *stream = NULL;
    if ((stream = fopen(path.c_str(), "rb")) == NULL) {
        LogError("Unable to open the file for reading : " << path);
        return CERTSVC_IO_ERROR;
    }

    PKCS12 *container = d2i_PKCS12_fp(stream, NULL);
    fclose(stream);
    if (container == NULL) {
        LogError("Failed to parse the input file passed.");
        return CERTSVC_FAIL;
    }

    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *certv = NULL;
    int result = PKCS12_parse(container, password.c_str(), &key, &cert, &certv);
    PKCS12_free(container);
    if (result != 1) {
        LogError("Failed to parse the file passed. openssl err : " << ERR_get_error());
        return CERTSVC_FAIL;
    }

    keyPtr.reset(key);
    certPtr.reset(cert);
    certvPtr.reset(certv);

    return CERTSVC_SUCCESS;
}

void rollbackStore(CertStoreType storeTypes, const std::string &endCertName)
{
    for (CertStoreType storeType = VPN_STORE; storeType < SYSTEM_STORE; storeType = nextStore(storeType)) {
        if (!hasStore(storeTypes, storeType))
            continue;

        char **certChainName = NULL;
        size_t ncerts = 0;

        int result = vcore_client_load_certificates_from_store(storeType, endCertName.c_str(), &certChainName, &ncerts);
        if (result != CERTSVC_SUCCESS) {
            LogError("Unable to load certificates from store. result : " << result);
            continue;
        }

        for (size_t i = 0; i < ncerts; i++) {
            if (certChainName[i] == NULL)
                continue;

            vcore_client_delete_certificate_from_store(storeType, certChainName[i]);
            free(certChainName[i]);
        }

        vcore_client_delete_certificate_from_store(storeType, endCertName.c_str());
    }
}

int insertToStore(CertStoreType storeTypes,
                  const std::string &alias,
                  const std::string &prikeyName,
                  const std::string &prikeyBuffer,
                  const std::string &endCertName,
                  const std::string &endCertBuffer,
                  const std::vector<std::string> &certChainName,
                  const std::vector<std::string> &certChainBuffer)
{
    size_t ncerts = certChainName.size();

    for (CertStoreType storeType = VPN_STORE; storeType < SYSTEM_STORE; storeType = nextStore(storeType)) {
        if (!hasStore(storeTypes, storeType))
            continue;

        LogDebug("Processing store type : " << storeType);

        int result = installPKEY(storeType, prikeyBuffer, prikeyName);
        if (result != CERTSVC_SUCCESS) {
            LogError("Failed to store the private key contents. result : " << result);
            return result;
        }

        result = installEndCert(storeType, endCertBuffer, alias, endCertName, prikeyName);
        if (result != CERTSVC_SUCCESS) {
            LogError("Failed to install the end user certificate. result : " << result);
            return result;
        }

        for (size_t i = 0; i < ncerts; i++) {
            if (i == ncerts - 1)
                result = installChainCert(storeType, certChainBuffer[i], certChainName[i], endCertName, P12_INTERMEDIATE);
            else
                result = installChainCert(storeType, certChainBuffer[i], certChainName[i], endCertName, P12_TRUSTED);

            if (result != CERTSVC_SUCCESS) {
                LogError("Failed to install the ca certificates. result : " << result);
                return result;
            }
        }
    }

    LogDebug("Success to insert extracted pkcs12 data to db");

    return CERTSVC_SUCCESS;
}

int insertToStorePEM(CertStoreType storeTypes, const std::string &path, const std::string &gname)
{
    std::string content = readFromFile(path);
    if (content.empty()) {
        LogError("Failed to read the file : " << path);
        return CERTSVC_IO_ERROR;
    }

    std::string parsed = parseCRT(content);
    if (parsed.empty()) {
        LogError("Failed to parse CRT : " << path);
        return CERTSVC_FAIL;
    }

    for (CertStoreType storeType = VPN_STORE; storeType < SYSTEM_STORE; storeType = nextStore(storeType)) {
        if (!hasStore(storeTypes, storeType))
            continue;

        int result = installCert(storeType, parsed, gname);
        if (result != CERTSVC_SUCCESS) {
            LogError("Failed to install PEM/CRT to db store : " << storeType << " result : " << result);
            rollbackStore(storeTypes, gname);
            return result;
        }

        LogDebug("Success to install PEM/CRT to db store : " << storeType);
    }

    LogDebug("Success to install PEM/CRT to db stores : " << storeTypes);

    return CERTSVC_SUCCESS;
}

} // namespace anonymous


int pkcs12_import_from_file_to_store(CertStoreType storeTypes,
                                     const char *_path,
                                     const char *_password,
                                     const char *_alias)
{

    int result = 0;

    if (_alias == NULL || _path == NULL || strlen(_path) < 4) {
        LogError("Invalid input parameter.");
        return CERTSVC_WRONG_ARGUMENT;
    }

    std::string path(_path);
    std::string alias(_alias);
    std::string password;
    if (_password != NULL)
        password = std::string(_password);

    LogDebug("pkcs12_import_from_file_to_store start. path[" << path << "] password[" << password << "] alias[" << alias << "]");

    if (storeTypes & SYSTEM_STORE) {
        LogError("User should not install any form of certificates in SYSTEM_STORE.");
        return CERTSVC_INVALID_STORE_TYPE;
    }

    /*
     * Installs CRT and PEM files.
     * We will passing NULL for private_key_gname and associated_gname parameter
     * in installFilePEM(). Which means that there is no private key involved
     * in the certificate which we are installing and there are no other
     * certificates related with the current certificate which is installed
     */
    std::string suffix = path.substr(path.length() - 4, 4);
    if (strcasecmp(suffix.c_str(), ".pem") == 0 || strcasecmp(suffix.c_str(), ".crt") == 0) {
        std::string gnamePEM = generateGname();
        result = insertToStorePEM(storeTypes, path, gnamePEM);
        if (result != CERTSVC_SUCCESS)
            LogError("Failed to install PEM/CRT file to store. gname : " << gnamePEM << " result : " << result);

        return result;;
    }

    LogDebug("Convert ossl type to string start");

    /* 0. extract pkcs12 data from file */
    PKEYUniquePtr key(nullptr, EVP_PKEY_free);
    X509UniquePtr cert(nullptr, X509_free);
    X509StackUniquePtr certv(nullptr, X509_stack_free);
    result = extractPkcs12(path, password, key, cert, certv);
    if (result != CERTSVC_SUCCESS) {
        LogError("Failed to extract pkcs12 file. result : " << result);
        return result;
    }

    LogDebug("extract pkcs12 to unique ptr success");

    result = verify_cert_details(cert.get(), certv.get());
    if (result != CERTSVC_SUCCESS) {
        LogError("Failed to verify p12 certificate. result : " << result);
        return result;
    }

    /* 1. handling private key */
    std::string prikeyName = generateGname();
    std::string prikeyBuffer = osslToPEM(OsslType::PKEY, key.get());
    if (prikeyName.empty() || prikeyBuffer.empty()) {
        LogError("Failed to transform pkey to PEM. result : " << result);
        return CERTSVC_FAIL;
    }

    LogDebug("Convert pkey to string success");

    /* 2. handling end user certificate */
    std::string endCertName = generateGname();
    std::string endCertBuffer = osslToPEM(OsslType::X509, cert.get());
    if (endCertName.empty() || endCertBuffer.empty()) {
        LogError("Failed to transform x509 to PEM. result : " << result);
        return CERTSVC_FAIL;
    }

    LogDebug("Convert end cert to string success");

    /* 3. handling certificate chain */
    std::vector<std::string> certChainName;
    std::vector<std::string> certChainBuffer;
    int ncerts = certv ? sk_X509_num(certv.get()) : 0;
    for (int i = 0; i < ncerts; i++) {
        std::string tempName = generateGname();
        std::string tempBuffer = osslToPEM(OsslType::X509AUX, sk_X509_value(certv.get(), i));
        if (tempName.empty() || tempBuffer.empty()) {
            LogError("Failed to transform x509 AUX to PEM");
            return CERTSVC_FAIL;
        }

        certChainName.push_back(std::move(tempName));
        certChainBuffer.push_back(std::move(tempBuffer));
    }

    LogDebug("Convert cert chain to string success");

    /* 4. insert extracted pkcs12 data to db */
    result = insertToStore(storeTypes,
                           alias,
                           prikeyName,
                           prikeyBuffer,
                           endCertName,
                           endCertBuffer,
                           certChainName,
                           certChainBuffer);

    if (result != CERTSVC_SUCCESS)
        rollbackStore(storeTypes, endCertName);

    LogDebug("Success to import pkcs12 to store");

    return result;
}

int pkcs12_has_password(const char *filepath, int *passworded)
{
    if (filepath == NULL || passworded == NULL)
        return CERTSVC_WRONG_ARGUMENT;

    FILE *stream;
    if ((stream = fopen(filepath, "rb")) == NULL)
        return CERTSVC_IO_ERROR;

    PKCS12 *container = d2i_PKCS12_fp(stream, NULL);
    fclose(stream);

    if (container == NULL)
        return CERTSVC_FAIL;

    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    int result = PKCS12_parse(container, NULL, &pkey, &cert, NULL);

    PKCS12_free(container);

    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (cert != NULL)
        X509_free(cert);

    if (result != 1 && ERR_GET_REASON(ERR_peek_last_error()) != PKCS12_R_MAC_VERIFY_FAILURE)
        return CERTSVC_FAIL;

    *passworded = (result == 1) ? 1 : 0;

    return CERTSVC_SUCCESS;
}
