/**
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cprimitives.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       cert-svc capi primitives
 */
#ifndef _CERTSVC_C_API_EXTENDED_H_
#define _CERTSVC_C_API_EXTENDED_H_

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cert-svc/ccert.h>
#include <cert-svc/cstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Duplicate @a CertSvcCertificate structure to openssl X509 structure.
 * openssl X509 structure should be freed by certsvc_certificate_free_x509().
 * @a CertSvcInstance isn't free duplicated openssl X509 structure.
 *
 * @param[in]  certificate  Certificate
 * @param[out] x509         Duplicated @a certificate
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_certificate_free_x509()
 */
int certsvc_certificate_dup_x509(CertSvcCertificate certificate, X509 **x509);

/**
 * Free openssl x509 structure duplicated by certsvc_certificate_dup_x509().
 *
 * @param[in] x509  openssl X509 structure to free
 *
 * @see certsvc_certificate_dup_x509()
 */
void certsvc_certificate_free_x509(X509 *x509);

/**
 * Duplicate pubkey in DER form from CertSvcCertificate.
 * Remarks: Free returned pubkey after use by free()
 *
 * @param[in]  certificate  Pointer to certificate.
 * @param[out] pubkey       Duplicated certificate in DER form which must be
 *                          freed after use
 * @param[out] len          Duplicated certificate length
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 */
int certsvc_certificate_dup_pubkey_der(CertSvcCertificate certificate, unsigned char **pubkey, size_t *len);

/**
 * Get private key from cert-svc store in openssl EVP_PKEY structure.
 * openssl EVP_PKEY structure should be freed by certsvc_pkcs12_free_evp_pkey().
 * @a CertSvcInstance isn't free duplicated openssl EVP_PKEY structure.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[in]  gname      Single certificate identifier which is associated with
 *                        private key
 * @param[out] pkey       private key from storage which must be freed after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_pkcs12_free_evp_pkey()
 */
int certsvc_pkcs12_dup_evp_pkey_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname,
		EVP_PKEY **pkey);

/**
 * Free openssl EVP_PKEY structure duplicated by certsvc_pkcs12_dup_ev_pkey()
 * or certsvc_pkcs12_dup_evp_pkey_from_store().
 *
 * @param[in] x509  openssl EVP_PKEY structure to free
 *
 * @see certsvc_pkcs12_dup_evp_pkey()
 * @see certsvc_pkcs12_dup_evp_pkey_from_store()
 */
void certsvc_pkcs12_free_evp_pkey(EVP_PKEY *pkey);

#ifdef __cplusplus
}
#endif

#endif
