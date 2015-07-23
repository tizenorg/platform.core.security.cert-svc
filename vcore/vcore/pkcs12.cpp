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
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <cert-service.h>
#include <cert-service-debug.h>
#include <cert-svc/cerror.h>

#include <vcore/cert-svc-client.h>
#include <vcore/utils.h>

#include <vcore/pkcs12.h>

#define SYSCALL(call) while(((call) == -1) && (errno == EINTR))

#define START_CERT      "-----BEGIN CERTIFICATE-----"
#define END_CERT        "-----END CERTIFICATE-----"
#define START_TRUSTED   "-----BEGIN TRUSTED CERTIFICATE-----"
#define END_TRUSTED     "-----END TRUSTED CERTIFICATE-----"
#define START_KEY       "-----BEGIN PRIVATE KEY-----"
#define END_KEY         "-----END PRIVATE KEY-----"

#define _CERT_SVC_VERIFY_PKCS12

static int generate_random_filepath(char **filepath)
{
  int generator;
  int64_t random;
  SHA_CTX ctx;
  unsigned char d[SHA_DIGEST_LENGTH];
  int result;

  if(!filepath)
    return CERTSVC_WRONG_ARGUMENT;

  SYSCALL(generator = open("/dev/urandom", O_RDONLY));
  if(generator == -1)
    return CERTSVC_FAIL;
  SYSCALL(result = read(generator, &random, sizeof(random)));
  if(result == -1) {
    SYSCALL(close(generator));
    return CERTSVC_FAIL;
  }
  SYSCALL(result = close(generator));
  if(result == -1)
    return CERTSVC_FAIL;

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, &random, sizeof(random));
  SHA1_Final(d, &ctx);

  result = asprintf(filepath, "%s/"                            \
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" \
                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    CERTSVC_PKCS12_STORAGE_DIR,
                    d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9],
                    d[10], d[11], d[12], d[13], d[14], d[15], d[16], d[17], d[18], d[19]);
  return (result != -1) ? CERTSVC_SUCCESS : CERTSVC_BAD_ALLOC;
}

static int unique_filename(char **filepath)
{
  int result;

  for (unsigned trial = 0x00U; trial < 0xFFU; ++trial) {
    result = generate_random_filepath(filepath);
    if (result != CERTSVC_SUCCESS)
        return result;

    result = access(*filepath, F_OK);
    if (result != 0)
        return CERTSVC_SUCCESS;

    free(*filepath);
  }

  return CERTSVC_FAIL;
}

static char *bare_filename(char *filepath)
{
  char *needle;
  if(!filepath)
    return NULL;
  needle = strrchr(filepath, '/');
  if(!needle)
    return NULL;
  return *(++needle) ? needle : NULL;
}

int read_from_file(const char *fileName, char **certBuffer, int *length)
{
    int result = CERTSVC_SUCCESS;
    FILE *fp_out = NULL;
    int certLength = 0;
    struct stat st;

    if (stat(fileName, &st) == -1) {
        SLOGE("Certificate does not exist in disable folder.");
        result = CERTSVC_FAIL;
        goto err;
    }

    if (!(fp_out = fopen(fileName, "rb"))) {
        SLOGE("Fail to open file for reading, [%s].", fileName);
        result = CERTSVC_FAIL;
        goto err;
    }

    fseek(fp_out, 0L, SEEK_END);
    certLength = ftell(fp_out);
    if (certLength < 1) {
        SLOGE("Fail to get certificate length.");
        result = CERT_SVC_ERR_FILE_IO;
        goto err;
    }

    *certBuffer = (char*)malloc(sizeof(char) * ((int)certLength + 1));
    if (*certBuffer == NULL) {
        SLOGE("Fail to allocate memory");
        result = CERTSVC_BAD_ALLOC;
        goto err;
    }

    memset(*certBuffer, 0x00, certLength+1);
    rewind (fp_out);
    if (fread(*certBuffer, sizeof(char), (size_t)certLength, fp_out) != (size_t)certLength) {
        SLOGE("Fail to read file, [%s]", fileName);
        result = CERTSVC_IO_ERROR;
        goto err;
    }
    *length = certLength;

err:
    if (fp_out != NULL) {
        fclose(fp_out);
        fp_out = NULL;
    }
    return result;
}

int c_certsvc_pkcs12_set_certificate_status_to_store(CertStoreType storeType, int is_root_app, char* gname, CertStatus status)
{
	return vcore_client_set_certificate_status_to_store(storeType, is_root_app, gname, status);
}

int c_certsvc_pkcs12_get_certificate_buffer_from_store(CertStoreType storeType, char* gname, char** certBuffer, size_t* certSize)
{
    return vcore_client_get_certificate_from_store(storeType, gname, certBuffer, certSize, PEM_CRT);
}

int c_certsvc_pkcs12_get_certificate_status_from_store(CertStoreType storeType, const char *gname, CertStatus *status)
{
    return vcore_client_get_certificate_status_from_store(storeType, gname, status);
}

int c_certsvc_pkcs12_alias_exists_in_store(CertStoreType storeType, const char *alias, int *exists)
{
    return vcore_client_check_alias_exist_in_store(storeType, alias, exists);
}

int c_certsvc_pkcs12_private_key_load_from_store(CertStoreType storeType, const char *gname, char **certBuffer, size_t *certSize)
{
    return vcore_client_get_certificate_from_store(storeType, gname, certBuffer, certSize, (CertType)P12_PKEY);
}

int c_certsvc_pkcs12_delete_certificate_from_store(CertStoreType storeType, const char* gname)
{
	return vcore_client_delete_certificate_from_store(storeType, gname);
}

int c_certsvc_pkcs12_get_certificate_alias_from_store(CertStoreType storeType, const char *gname, char **alias)
{
    return vcore_client_get_certificate_alias_from_store(storeType, gname, alias);
}

int c_certsvc_pkcs12_load_certificates_from_store(CertStoreType storeType, const char *gname, char ***certs, int *ncerts)
{
    return vcore_client_load_certificates_from_store(storeType, gname, certs, ncerts);
}

int c_certsvc_pkcs12_free_aliases_loaded_from_store(CertSvcStoreCertList** certList)
{
    int result = CERTSVC_SUCCESS;
    CertSvcStoreCertList* tmpNode = NULL;

    while (*certList) {
        tmpNode = *certList;
        if (tmpNode->title)
            free(tmpNode->title);
        if (tmpNode->gname)
            free(tmpNode->gname);
        *certList = (*certList)->next;
        free(tmpNode);
    }
    return result;
}

int c_certsvc_pkcs12_get_root_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length)
{
    return vcore_client_get_root_certificate_list_from_store(storeType, certList, length);
}

int c_certsvc_pkcs12_get_end_user_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList** certList, int* length)
{
    return vcore_client_get_end_user_certificate_list_from_store(storeType, certList, length);
}

int c_certsvc_pkcs12_get_certificate_list_from_store(CertStoreType storeType, int is_root_app, CertSvcStoreCertList** certList, int* length)
{
    return vcore_client_get_certificate_list_from_store(storeType, is_root_app, certList, length);
}

int install_pem_file_format_to_store(CertStoreType storeType, const char* certBuffer, int certLength,
		const char *alias, const char* path, char *private_key_gname, char *associated_gname, CertType decideCert)
{
    int result = CERTSVC_SUCCESS;
    int readCount = 0;
    char* fileName = NULL;
    char* commonName = NULL;
    char *unique = NULL;
    BIO* pBio = NULL;
    X509* x509Struct = NULL;
    struct stat dirST;

    if (!certBuffer || !certLength) {
        SLOGE("Invalid argument. certBuffer is input cert.");
        return CERTSVC_WRONG_ARGUMENT;
    }

    if (decideCert == PEM_CRT) {
        result = unique_filename(&unique);
        if (result != CERTSVC_SUCCESS) {
            SLOGE("Fail to generate unique filename.");
            return result;
        }
    }
    else
        unique = (char*)path;

    if (unique == NULL)	{
        SLOGE("Failed to get unique file name.");
        return result;
    }

    /* Get common name from buffer or from file */
    if (stat(path, &dirST) != -1) {
        result = get_common_name(path, NULL, &commonName);
        if (result != CERTSVC_SUCCESS) {
            pBio = BIO_new(BIO_s_mem());
            if (pBio == NULL) {
                SLOGE("Failed to allocate memory.");
                result = CERTSVC_BAD_ALLOC;
                goto error;
            }

            readCount = BIO_write(pBio, (const void*) certBuffer, certLength);
            if (readCount < 1) {
                SLOGE("Failed to load cert into bio.");
                result = CERTSVC_BAD_ALLOC;
                goto error;
            }

            x509Struct = PEM_read_bio_X509(pBio, NULL, 0, NULL);
            if (x509Struct == NULL) {
                SLOGE("Failed to create x509 structure.");
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = get_common_name(NULL, x509Struct, &commonName);
            if (result != CERTSVC_SUCCESS) {
                SLOGE("CommonName is NULL");
                result = CERTSVC_FAIL;
                goto error;
            }
        }
    }

    /* storing the certificate to key-manager */
    fileName = bare_filename(unique);
    if ((decideCert == P12_END_USER) && (private_key_gname != NULL))
        result =  vcore_client_install_certificate_to_store(storeType, fileName, alias, private_key_gname, fileName, certBuffer, certLength, decideCert);
    else if ((decideCert == P12_TRUSTED) || (decideCert == P12_INTERMEDIATE))
        result =  vcore_client_install_certificate_to_store(storeType, fileName, commonName, NULL, associated_gname, certBuffer, certLength, decideCert);
    else
        result =  vcore_client_install_certificate_to_store(storeType, fileName, commonName, NULL, fileName, certBuffer, certLength, decideCert);

    if (result != CERTSVC_SUCCESS) {
        SLOGE("Failed to intall certificate. result[%d]", result);
        result = CERTSVC_FAIL;
        goto error;
     }

    SLOGD("Success to add certificate in store.");

error:
    if (commonName)
        free(commonName);
    return result;
}

int install_crt_file(
        const char *path,
        CertStoreType storeType,
        const char *alias,
		char *private_key_gname,
        char *associated_gname,
        CertType decideCert)
{
    int result = CERTSVC_SUCCESS;
    int fileSize = 0;
    int certLength = 0;
    const char* header = NULL;
    const char* trailer = NULL;
    char* fileContent = NULL;
    const char* tmpBuffer = NULL;
    char* certBuffer = NULL;
    const char* tailEnd = NULL;

    if (read_from_file(path, &fileContent, &fileSize)!=CERTSVC_SUCCESS)
    {
    	SLOGE("Failed to read the file. [%s]",path);
        result = CERTSVC_IO_ERROR;
    	goto error;
    }

    tmpBuffer = fileContent;
    if (decideCert == PEM_CRT)
        header = strstr(tmpBuffer, START_CERT);
    else if (decideCert == P12_END_USER)
        header = strstr(tmpBuffer, START_CERT);
    else if ((decideCert == P12_TRUSTED)||(decideCert == P12_INTERMEDIATE))
        header = strstr(tmpBuffer, START_TRUSTED);
    else {
        SLOGE("Invalid cert.");
        result = CERTSVC_IO_ERROR;
        goto error;
    }

    if (header != NULL)	{
        /* Supports installation of only one certificate present in a CRT file */
        if (decideCert == PEM_CRT) {
            trailer = strstr(header, END_CERT);
            tailEnd = END_CERT;
        }
        else if (decideCert == P12_END_USER) {
            trailer = strstr(header, END_CERT);
            tailEnd = END_CERT;
        }
        else if ((decideCert == P12_TRUSTED)||(decideCert == P12_INTERMEDIATE)) {
            trailer = strstr(header, END_TRUSTED);
            tailEnd = END_TRUSTED;
        }
        else {
            SLOGE("Invalid certificate passed.");
            result = CERTSVC_IO_ERROR;
            goto error;
        }

        if (trailer != NULL) {
            tmpBuffer = trailer;
            certLength = ((int)(trailer - header) + strlen(tailEnd));
            certBuffer = (char*) malloc(sizeof(char) * (certLength+2));
            if (certBuffer == NULL) {
                result = CERTSVC_BAD_ALLOC;
                SLOGE("Fail to allocate memory.");
                goto error;
            }

            memset(certBuffer, 0x00, certLength+2);
            memcpy(certBuffer, header, certLength);
            certBuffer[certLength] = '\0';

            result = install_pem_file_format_to_store(storeType, certBuffer, certLength, alias, \
                                                      path, private_key_gname, associated_gname, decideCert);
            if (result != CERTSVC_SUCCESS) {
                result = CERTSVC_FAIL;
                SLOGE("Fail to install certificate[%s]", path);
            }
        }
    }
    else {
        SLOGE("Invalid file type passed.");
        result = CERT_SVC_ERR_INVALID_CERTIFICATE;
    }

error:
    if (certBuffer)
        free(certBuffer);
    if (fileContent)
        free(fileContent);
    return result;
}

int handle_crt_pem_file_installation(CertStoreType storeType, const char *path, const char *alias)
{
    int result = CERTSVC_SUCCESS;

    if ((strstr(path, ".crt")) != NULL || (strstr(path, ".pem")) != NULL) {
        SLOGD("certificate extention is .crt/.pem file");

        /* Installs CRT and PEM files. We will passing NULL for private_key_gname and associated_gname parameter in
         * install_crt_file(). Which means that there is no private key involved in the certificate which we are
         * installing and there are no other certificates related with the current certificate which is installed */
        result = install_crt_file(path, storeType, alias, NULL, NULL, PEM_CRT);
        if (result != CERTSVC_SUCCESS) {
            SLOGE("Failed to install the certificate.");
            result = CERTSVC_FAIL;
            goto error;
        }
    }
    else {
        SLOGE("Invalid certificate passed.");
        result = CERTSVC_FAIL;
        goto error;
    }
    SLOGD("Success to install the certificate.");

error:
    return result;
}

int verify_cert_details(X509** cert, STACK_OF(X509) **certv)
{
    int result = CERTSVC_SUCCESS;
    char* pSubject = NULL;
    char* pIssuerName = NULL;
    X509_STORE_CTX *cert_ctx = NULL;
    X509_STORE *cert_store = NULL;
    int res = 0;

#ifdef _CERT_SVC_VERIFY_PKCS12
    if (*certv == NULL) {
        pSubject = X509_NAME_oneline((*cert)->cert_info->subject, NULL, 0);
        if (!pSubject) {
            SLOGE("Failed to get subject name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        pIssuerName = X509_NAME_oneline((*cert)->cert_info->issuer, NULL, 0);
        if (!pIssuerName) {
            SLOGE("Failed to get issuer name");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        if (strcmp((const char*)pSubject, (const char*)pIssuerName) == 0) {
            /*self signed.. */
            EVP_PKEY* pKey = NULL;
            pKey = X509_get_pubkey(*cert);
            if (!pKey) {
                SLOGE("Failed to get public key");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            if (X509_verify(*cert, pKey) <= 0) {
                SLOGE("P12 verification failed");
                EVP_PKEY_free(pKey);
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            SLOGD("P12 verification Success");
            EVP_PKEY_free(pKey);
        }
        else {
            cert_store = X509_STORE_new();
            if (!cert_store) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_load_locations(cert_store, NULL, "/opt/etc/ssl/certs/");
            if (res != 1) {
                SLOGE("P12 load certificate store failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            res = X509_STORE_set_default_paths(cert_store);
            if (res != 1) {
                SLOGE("P12 load certificate store path failed");
                X509_STORE_free(cert_store);
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* initialise store and store context */
            cert_ctx = X509_STORE_CTX_new();
            if (cert_ctx == NULL) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

            /* construct store context */
            if (!X509_STORE_CTX_init(cert_ctx, cert_store, *cert, NULL)) {
                SLOGE("Memory allocation failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }

#ifdef P12_VERIFICATION_NEEDED
            res = X509_verify_cert(cert_ctx);
            if (res != 1) {
                SLOGE("P12 verification failed");
                result = CERTSVC_FAIL;
                goto free_memory;
            }
            SLOGD("P12 verification Success");
#endif
        }
    }
    else if (*certv != NULL) {
        /* Cert Chain */
        cert_store = X509_STORE_new();
        if (!cert_store) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_load_locations(cert_store, NULL, CERTSVC_SSL_CERTS_DIR);
        if (res != 1) {
            SLOGE("P12 load certificate store failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        res = X509_STORE_set_default_paths(cert_store);
        if (res != 1) {
            SLOGE("P12 load certificate path failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* initialise store and store context */
        cert_ctx = X509_STORE_CTX_new();
        if (cert_ctx == NULL) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        /* construct store context */
        if (!X509_STORE_CTX_init(cert_ctx, cert_store, *cert, NULL)) {
            SLOGE("Memory allocation failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }

        X509_STORE_CTX_trusted_stack(cert_ctx, *certv);
#ifdef P12_VERIFICATION_NEEDED
        res = X509_verify_cert(cert_ctx);
        if (res != 1) {
            SLOGE("P12 verification failed");
            result = CERTSVC_FAIL;
            goto free_memory;
        }
        SLOGD("P12 verification Success");
#endif
    }
#endif //_CERT_SVC_VERIFY_PKCS12

free_memory:
    if (pSubject != NULL) { free(pSubject); }
    if (pIssuerName != NULL) { free(pIssuerName); }
    if (cert_store != NULL) { X509_STORE_free(cert_store); }
    if (cert_ctx) { X509_STORE_CTX_free(cert_ctx); }
    return result;
}

int c_certsvc_pkcs12_import_from_file_to_store(CertStoreType storeTypes, const char *path, const char *password, const char *alias)
{
    int	result = CERTSVC_SUCCESS;
    int readLen = 0;
    int tmpLen = 0;
    int nicerts = 0, i = 0, n = 0, ncerts = 0, wr_res;
    CertStoreType storeType = NONE_STORE;
    FILE* stream = NULL;
    PKCS12* container = NULL;
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    STACK_OF(X509) *certv = NULL;
    char* bare = NULL;
    char* pkvalue = NULL;
    char** cvaluev = NULL;
    char **certs = NULL;
    char* tmpPkValue = NULL;
    char* unique = NULL;
    char fileBuffer[4096] = {0,};
    int loopCount = 0;
    CertType decideCert = INVALID_DATA;
    int exists = 0;

    if ((!alias) || (strlen(alias) < 1) || (!path) || (strlen(path) < 1)) {
        SLOGE("Invalid input parameter.");
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
        return CERTSVC_WRONG_ARGUMENT;
    }

    while(1) {
        /* Iteration only possible from VPN_STORE till SYSTEM_STORE */
        if (loopCount == (MAX_STORE_ENUMS-1)) break;

        /* User should not install any form of certificates inside SYSTEM_STORE */
        if (((1 << loopCount) & storeTypes) == SYSTEM_STORE) {
            SLOGE("Not a valid store type installing certificate, store type passed [%d].", (1 << loopCount));
			SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
            return CERTSVC_INVALID_STORE_TYPE;
        }

        /* Iterating over all the stores */
        if ((1 << loopCount) & storeTypes) {
            storeType = NONE_STORE;
            storeType = (CertStoreType) (1 << loopCount);
            SLOGD("Processing store type : [%s]", (storeType == VPN_STORE)? "VPN" : (storeType == WIFI_STORE)? "WIFI" : "EMAIL");

            /* check if the alias exists before installing certificate */
            result = c_certsvc_pkcs12_alias_exists_in_store(storeType, alias, &exists);
            if (result != CERTSVC_SUCCESS) {
                SLOGE("Failure to access database.");
                result = CERTSVC_FAIL;
                goto error;
            }

            if (exists!=CERTSVC_TRUE) {
                SLOGE("Alias exist in store [%s].", (storeType == VPN_STORE)? "VPN" : (storeType == WIFI_STORE)? "WIFI" : "EMAIL");
                result = CERTSVC_DUPLICATED_ALIAS;
                goto error;
            }

            /* Logic for handling crt/pem cert installation */
            /* Check if the input file is a PEM/CRT, since a PFX cert can also be opened without a password */
            if (password == NULL && ((strstr(path, ".pfx") == NULL) || (strstr(path, ".p12")))) {
                result = handle_crt_pem_file_installation(storeType, path, alias);
                if (result != CERTSVC_SUCCESS) {
                    SLOGE("Failed to install PEM/CRT file to store.");
                    result = CERTSVC_FAIL;
                }
                loopCount++;
                continue;
            }

            /* Logic for handling .pfx/.p12 cert installation */
            if ((stream = fopen(path, "rb")) == NULL) {
                SLOGE("Unable to open the file for reading [%s].", path);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            if (container == NULL) {
                container = d2i_PKCS12_fp(stream, NULL);
                fclose(stream);
                if (container == NULL) {
                    SLOGE("Failed to parse the input file passed.");
                    result = CERTSVC_FAIL;
                    goto error;
                }
            }

            /* To ensure when the code re-enters, we should clean up */
            if (key==NULL && cert==NULL && certv==NULL) {
                result = PKCS12_parse(container, password, &key, &cert, &certv);
                PKCS12_free(container);
                if (result == CERTSVC_FAIL) {
                    SLOGE("Failed to parse the file passed.");
                    result = CERTSVC_FAIL;
                    goto error;
                }

                result = verify_cert_details(&cert, &certv);
                if (result == CERTSVC_FAIL) {
                    SLOGE("Failed to verify p12 certificate.");
                    goto error;
                }
            }

            nicerts = 0;
            nicerts = certv ? sk_X509_num(certv) : 0;
            if (cvaluev != NULL) {
            for (i = 0; i < n; i++)
                 free(cvaluev[i]);
                 if (cvaluev) free(cvaluev);
                     cvaluev = NULL;
            }

            n = 0;
            cvaluev = (char **)calloc(1 + nicerts, sizeof(char *));
            if (unique != NULL) { free(unique); unique = NULL; }
            result = unique_filename(&unique);
            if (result != CERTSVC_SUCCESS || !unique) {
                SLOGE("Unique filename generation failed.");
                goto error;
            }

            if ((stream = fopen(unique, "w+")) == NULL) {
                SLOGE("Unable to open the file for writing [%s].",unique);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = PEM_write_PrivateKey(stream, key, NULL, NULL, 0, NULL, NULL);
            if (result == 0) {
                SLOGE("Writing the private key contents failed.");
                result = CERTSVC_FAIL;
                fclose(stream);
                goto error;
            }

            fseek(stream, 0, SEEK_SET);
            memset(fileBuffer, 0, (sizeof(char)*4096));
            readLen=0;
            readLen = fread(fileBuffer, sizeof(char), 4096, stream);
            fclose(stream);
            if (readLen <= 0){
				SLOGE("Failed to read key file");
                result = CERTSVC_FAIL;
                goto error;
            }

            bare = bare_filename(unique);
            if (bare) {
                pkvalue = strdup(bare);
                tmpLen = strlen((const char*)pkvalue);
                tmpPkValue = (char*)malloc(sizeof(char) * (tmpLen + 1));
                memset(tmpPkValue, 0x00, tmpLen+1);
                memcpy(tmpPkValue, pkvalue, tmpLen);
            }

            decideCert = P12_PKEY;
            result = vcore_client_install_certificate_to_store(storeType, tmpPkValue, NULL, NULL, NULL, fileBuffer, readLen, decideCert);
            if (result != CERTSVC_SUCCESS) {
                SLOGD("Failed to store the private key contents.");
                result = CERTSVC_FAIL;
                goto error;
            }

            unlink(unique);
            if (unique!=NULL) { free(unique); unique=NULL; }
            result = unique_filename(&unique);
            if (result != CERTSVC_SUCCESS || !unique) {
                SLOGE("Unique filename generation failed.");
                goto error;
            }

            if ((stream = fopen(unique, "w")) == NULL) {
                SLOGE("Unable to open the file for writing [%s].", unique);
                result = CERTSVC_IO_ERROR;
                goto error;
            }

            result = PEM_write_X509(stream, cert);
            fclose(stream);
            if (result == 0) {
                SLOGE("Failed to write contents to file.");
                result = CERTSVC_FAIL;
                goto error;
            }

            bare = bare_filename(unique);
            if (bare)
                cvaluev[n++] = strdup(bare);

            wr_res = -1;
            decideCert = P12_END_USER;
            wr_res = install_crt_file(unique, storeType, alias, tmpPkValue, NULL, decideCert);
            if (wr_res != CERTSVC_SUCCESS) {
                result = CERTSVC_FAIL;
                SLOGE("Failed to install the end user certificate.");
                goto error;
            }

            unlink(unique);
            for (i=nicerts; i>0; i--) {
                 result = unique_filename(&unique);
                 if (result != CERTSVC_SUCCESS || !unique) {
                     SLOGE("Unique filename generation failed.");
                     goto error;
                 }

                 if ((stream = fopen(unique, "w")) == NULL) {
                      result = CERTSVC_IO_ERROR;
                      SLOGE("Unable to open the file for writing.");
                      goto error;
                 }

                 result = PEM_write_X509_AUX(stream, sk_X509_value(certv, i-1));
                 fclose(stream);
                 if (result == 0) {
                     result = CERTSVC_FAIL;
                     SLOGE("Unable to extract the certificates.");
                     goto error;
                 }

                 wr_res = -1;
                 if (i==nicerts)
                     decideCert = P12_INTERMEDIATE;
                 else
                     decideCert = P12_TRUSTED;
                 wr_res = install_crt_file(unique, storeType, alias, NULL, cvaluev[0], decideCert);
                 if (wr_res != CERTSVC_SUCCESS) {
                     result = CERTSVC_FAIL;
                     goto error;
                 }

                 unlink(unique);
                 bare = bare_filename(unique);
                 if (bare)
                     cvaluev[n++] = strdup(bare);
            }
        }
        loopCount++;
    }

error:
    /* if any certificate parsing/installation fails in middle,
     * the below logic will delete the chain installed in DB */
    if (result != CERTSVC_SUCCESS) {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Failed");
        if (nicerts > 0) {
        	nicerts = 0; i = 0;
        	/* cvaluev[0] holds the end user certificate identifier which will be associated
        	 * to chain certs. Pull the cert chain based on end user cert and delete one by one. */
            if (c_certsvc_pkcs12_load_certificates_from_store(storeType, cvaluev[0], &certs, &ncerts) != CERTSVC_SUCCESS) {
                SLOGE("Unable to load certificates from store.");
                return result;
            }

            for (i=0; i<ncerts; i++) {
            	 if (certs[i] != NULL) {
    	             SLOGD("file to delete : %s",certs[i]);
                     c_certsvc_pkcs12_delete_certificate_from_store(storeType, (char *)certs[i]);
            	 }
            }

            if (certs[i] != NULL) {
                for (i=0; i<ncerts; i++)
                     free(certs[i]);
            }
        }
    }
	else
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=certificate, AccessType=Install, Result=Succeed");

    if (key != NULL) EVP_PKEY_free(key);
    if (cert != NULL) X509_free(cert);
    if (certv != NULL) sk_X509_free(certv);
    if (pkvalue != NULL) free(pkvalue);
    if (tmpPkValue != NULL) free(tmpPkValue);
    if (unique != NULL) free(unique);
    return result;
}

int c_certsvc_pkcs12_has_password(const char *filepath, int *passworded)
{
  FILE *stream;
  EVP_PKEY *pkey;
  X509 *cert;
  PKCS12 *container;
  int result;

  if(passworded == NULL)
    return CERTSVC_WRONG_ARGUMENT;
  if((stream = fopen(filepath, "rb")) == NULL)
    return CERTSVC_IO_ERROR;
  container = d2i_PKCS12_fp(stream, NULL);
  fclose(stream);
  if(container == NULL)
    return CERTSVC_FAIL;
  result = PKCS12_parse(container, NULL, &pkey, &cert, NULL);
  PKCS12_free(container);
  if(result == 1) {
    EVP_PKEY_free(pkey);
    X509_free(cert);
    *passworded = 0;
    return CERTSVC_SUCCESS;
  }
  else {
    if(ERR_GET_REASON(ERR_peek_last_error()) == PKCS12_R_MAC_VERIFY_FAILURE) {
      *passworded = 1;
      return CERTSVC_SUCCESS;
    }
    else
      return CERTSVC_FAIL;
  }
}

void c_certsvc_pkcs12_free_certificates(char **certs)
{
  size_t i = 0;
  if (!certs)
    return;
  while (certs[i])
    free(certs[i++]);
  free(certs);
}
