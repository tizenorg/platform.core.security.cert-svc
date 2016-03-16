/**
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cpkcs12.h
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @brief       This is part of C api for PKCS#12/PFX storage routines.
 */
#ifndef _CERTSVC_CPKCS12_H_
#define _CERTSVC_CPKCS12_H_

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>
#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check whenever PKCS#12 container is password protected.
 *
 * @param[in]  instance      CertSvcInstance object
 * @param[in]  filepath      File path to check
 * @param[out] has_password  #1 if password protectedm, else #0
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 */
int certsvc_pkcs12_has_password(CertSvcInstance instance,
								CertSvcString filepath,
								int *has_password);

/**
 * Couter-routine for certsvc_pkcs12_private_key_dup.
 *
 * @param[in] buffer   Memory claimed by private key
 */
void certsvc_pkcs12_private_key_free(char *buffer);

/**
 * Load to memory of private key in cert-svc store with @a gname.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[in]  gname      Single certificate identifier. It has to be end user's
 *                        to extract private key
 * @param[out] buffer     Private key buffer which must be freed after use
 * @param[out] size       Size of the returned buffer. Zero when no key is found
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_private_key_dup_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname,
		char **buffer,
		size_t *size);

/**
 * Set the status for the specified certificate in cert-svc store.
 *
 * @param[in] instance     CertSvcInstance object
 * @param[in] storeType    cert-svc store type to query
 * @param[in] is_root_app  Should be #ENABLED if master application is changing the status,
 *                         else #DISABLED for other applications
 * @param[in] gname        Single certificate identifier
 * @param[in] status       Status of the certificate to set. [#ENABLED | #DISABLED]
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 * @see #CertStatus
 */
int certsvc_pkcs12_set_certificate_status_to_store(CertSvcInstance instance,
		CertStoreType storeType,
		int is_root_app,
		CertSvcString gname,
		CertStatus status);

/**
 * Get the status for the specified certificate in cert-svc store.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[in[  gname      Single certificate identifier
 * @param[out] status     Status of the certificate. Enabled:1, Disabled:0, Fail:-1
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStroeType
 */
int certsvc_pkcs12_get_certificate_status_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname,
		CertStatus *status);

/**
 * Get the certificates in cert-svc store.
 *
 * @param[in]  instance     CertSvcInstance object
 * @param[in]  storeType    cert-svc store type to query
 * @param[in]  is_root_app  Should be #ENABLED if master application is changing the
 *                          status, else #DISABLED for other applications
 * @param[out] certList     cert list in store returned in linked list. Free by
 *                          certsvc_pkcs12_free_certificate_list_loaded_from_store()
 *                          after use
 * @param[out] length       length of output @a certList
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see #CertStoreType
 * @see #CertSvcStoreCertList
 */
int certsvc_pkcs12_get_certificate_list_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		int is_root_app,
		CertSvcStoreCertList **certList,
		size_t *length);

/**
 * Get the end user certificates in cert-svc store.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[out] certList   cert list in store returned in linked list. Free by
 *                        certsvc_pkcs12_free_certificate_list_loaded_from_store() after use
 * @param[out] length     length of output @a certList
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see #CertStoreType
 * @see #CertSvcStoreCertList
 */
int certsvc_pkcs12_get_end_user_certificate_list_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcStoreCertList **certList,
		size_t *length);

/**
 * Get the root/trusted certificates in cert-svc store.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[out] certList   cert list in store returned in linked list. Free by
 *                        certsvc_pkcs12_free_certificate_list_loaded_from_store() after use
 * @param[out] length     length of output @a certList
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_pkcs12_free_certificate_list_loaded_from_store()
 * @see #CertStoreType
 * @see #CertSvcStoreCertList
 */
int certsvc_pkcs12_get_root_certificate_list_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcStoreCertList **certList,
		size_t *length);

/**
 * Free all @a CertSvcStoreCertList in linked list of data structure.
 *
 * @param[in] instance  CertSvcInstance object
 * @param[in] certList  The structure which need to be freed
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_pkcs12_get_certificate_list_from_store()
 * @see certsvc_pkcs12_get_end_user_certificate_list_from_store()
 * @see certsvc_pkcs12_get_root_certificate_list_from_store()
 * @see #CertSvcStoreCertList
 */
int certsvc_pkcs12_free_certificate_list_loaded_from_store(CertSvcInstance instance,
		CertSvcStoreCertList **certList);

/**
 * Get the certificate with the gname provided from cert-svc store.
 *
 * @param[in]  instance     CertSvcInstance object
 * @param[in]  storeType    cert-svc store type to query
 * @param[in]  gname        Single certificate identifier
 * @param[out] certificate  output in @a CertSvcCertificate format
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_certificate_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_get_certificate_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		const char *gname,
		CertSvcCertificate *certificate);

/**
 * Get the encoded certificate buffer with the gname provided from cert-svc store.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[in]  gname      Single certificate identifier
 * @param[out] buffer     The base64 encoded certificate which must be freed after
 *                        use
 * @param[out] size       Size of the buffer
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_get_certificate_info_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname,
		char **buffer,
		size_t *size);

/**
 * Import PKCS#12 bundle(with .pfx or .p12) or certificate(base64 form with .crt
 * or .pem suffix) from file to specified store. If password isn't needed, create
 * CertSvcString @a password with null input on certsvc_string_new(). Refer
 * certsvc_string_new() API description
 *
 * @param[in] instance   CertSvcInstance object
 * @param[in] storeType  cert-svc store type to query
 * @param[in] path       Path of the certificate which needs to be imported
 * @param[in] password   Password if the file to import is password-protected which can be
 *                       empty CertSvcString in case of not-password-protected
 * @param[in] alias      Primary key for certificate bundle identification (can't be empty)
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_import_from_file_to_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString path,
		CertSvcString password,
		CertSvcString alias);

/**
 * Delete the certificate with gname provided from cert-svc store.
 *
 * @param[in] instance   CertSvcInstance object
 * @param[in] storeType  cert-svc store type to query
 * @param[in] gname      Single certificate identifier
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_delete_certificate_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname);

/**
 * Check the uniqueness of the alias in cert-svc store.
 *
 * @param[in]  instance   CertSvcInstance object
 * @param[in]  storeType  cert-svc store type to query
 * @param[in]  alias      Certificates bundle identifier used when importing
 * @param[out] is_unique  #CERTSVC_TRUE if the alias is unique, else #CERTSVC_FALSE
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_check_alias_exists_in_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString alias,
		int *is_unique);

/**
 * Get list of certificates from PKCS#12 bundle or single certificate which
 * is saved in cert-svc store with the alias.
 *
 * @param[in]  instance         CertSvcInstance object
 * @param[in]  alias            Certificates bundle identifier used when importing
 * @param[out] certificateList  List of certificates. Free by
 *                              certsvc_certificate_list_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see certsvc_certificate_free()
 * @see certsvc_certificate_list_free()
 * @see #CertStoreType
 * @see #CertSvcStoreCertList
 */
int certsvc_pkcs12_load_certificate_list_from_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString alias,
		CertSvcCertificateList *certificateList);

/**
 * Get the alias name with the gname provided.
 *
 * @param[in]  instance  CertSvcInstance object
 * @param[in]  gname     Single certificate identifier which is associated with alias
 * @param[out] alias     Certificates bundle identifier used when importing which must
 *                       be freed after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 * @see #CertStoreType
 */
int certsvc_pkcs12_get_alias_name_for_certificate_in_store(CertSvcInstance instance,
		CertStoreType storeType,
		CertSvcString gname,
		char **alias);

#ifdef __cplusplus
}
#endif

#endif
