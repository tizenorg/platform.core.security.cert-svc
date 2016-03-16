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
 * @file        ccert.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CCERT_H_
#define _CERTSVC_CCERT_H_

#include <time.h>

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CertSvcCertificate_t {
	size_t privateHandler;
	CertSvcInstance privateInstance;
} CertSvcCertificate;

typedef struct CertSvcCertificateList_t {
	size_t privateHandler;
	CertSvcInstance privateInstance;
} CertSvcCertificateList;

#define MAX_STORE_ENUMS 5
typedef enum certImportType_t {
	NONE_STORE   =  0,
	VPN_STORE    =  1 << 0,
	WIFI_STORE   =  1 << 1,
	EMAIL_STORE  =  1 << 2,
	SYSTEM_STORE =  1 << 3,
	ALL_STORE    =  VPN_STORE | WIFI_STORE | EMAIL_STORE | SYSTEM_STORE
} CertStoreType;

typedef enum certStatus_t {
	DISABLED     =  0,
	ENABLED      =  1
} CertStatus;

typedef struct CertSvcStoreCertList_t {
	char *gname;            // keyfile group name
	char *title;            // common Name / Alias provided by the user
	CertStatus status;
	CertStoreType storeType;
	struct CertSvcStoreCertList_t *next;
} CertSvcStoreCertList;

typedef enum certType_t {
	PEM_CRT          = 1 << 0,
	P12_END_USER     = 1 << 1,
	P12_INTERMEDIATE = 1 << 2,
	P12_TRUSTED      = 1 << 3,
	P12_PKEY         = 1 << 4,
	INVALID_DATA     = 1 << 5
} CertType;

typedef enum CertSvcCertificateForm_t {
	/*    CERTSVC_FORM_PEM, */
	CERTSVC_FORM_DER,
	CERTSVC_FORM_DER_BASE64
} CertSvcCertificateForm;

typedef enum CertSvcCertificateField_t {
	CERTSVC_SUBJECT,
	CERTSVC_SUBJECT_COMMON_NAME,
	CERTSVC_SUBJECT_COUNTRY_NAME,
	CERTSVC_SUBJECT_STATE_NAME,
	CERTSVC_SUBJECT_LOCALITY_NAME,
	CERTSVC_SUBJECT_ORGANIZATION_NAME,
	CERTSVC_SUBJECT_ORGANIZATION_UNIT_NAME,
	CERTSVC_SUBJECT_EMAIL_ADDRESS,
	/*    CERTSVC_SUBJECT_UID, */
	CERTSVC_ISSUER,
	CERTSVC_ISSUER_COMMON_NAME,
	CERTSVC_ISSUER_COUNTRY_NAME,
	CERTSVC_ISSUER_STATE_NAME,
	CERTSVC_ISSUER_LOCALITY_NAME,
	CERTSVC_ISSUER_ORGANIZATION_NAME,
	CERTSVC_ISSUER_ORGANIZATION_UNIT_NAME,
	CERTSVC_ISSUER_EMAIL_ADDRESS,
	/*    CERTSVC_ISSUER_UID, */
	CERTSVC_VERSION,
	CERTSVC_SERIAL_NUMBER,
	CERTSVC_KEY_USAGE,
	CERTSVC_KEY,
	CERTSVC_KEY_ALGO,
	CERTSVC_SIGNATURE_ALGORITHM
} CertSvcCertificateField;

typedef enum CertSvcVisibility_t {
	CERTSVC_VISIBILITY_DEVELOPER            = 1,
	CERTSVC_VISIBILITY_PUBLIC               = 1 << 6,
	CERTSVC_VISIBILITY_PARTNER              = 1 << 7,
	CERTSVC_VISIBILITY_PLATFORM             = 1 << 10
} CertSvcVisibility;

/**
 * Get certificate with gname provided.
 *
 * @param[in]  instance     CertSvcInstance object
 * @param[in]  storeType    cert-svc store type to query
 * @oaran[in]  gname        Single certificate identifier
 * @param[out] certificate  Must be freed by certsvc_certificate_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_certificate_free()
 * @see #CertStoreType
 * @see #CertSvcCertificate
 */
int certsvc_get_certificate(CertSvcInstance instance,
							CertStoreType storeType,
							const char *gname,
							CertSvcCertificate *certificate);

/**
 * Load certificate to @a CertSvcCertificate from file.
 * Certificate must be in PEM/CER/DER format.
 *
 * @param[in]  instance     CertSvcInstance object
 * @param[in]  location     Path of file to load
 * @param[out] certificate  Certificate id assigned to loaded certificate
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_certificate_free()
 * @see #CertSvcCertificate
 */
int certsvc_certificate_new_from_file(CertSvcInstance instance,
									  const char *location,
									  CertSvcCertificate *certificate);

/**
 * Load certificate to @a CertSvcCertificate from memory.
 *
 * @param[in]  instance     CertSvcInstance object
 * @param[in]  memory       Pointer to memory with certificate data
 * @param[in]  len          Size of certificate in @a memory
 * @param[in]  form         Certificate format in @a memory
 * @param[out] certificate  Must be freed by certsvc_certificate_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_certificate_free()
 * @see #CertSvcCertificate
 * @see #CertSvcCertificateForm
 */
int certsvc_certificate_new_from_memory(CertSvcInstance instance,
										const unsigned char *memory,
										size_t len,
										CertSvcCertificateForm form,
										CertSvcCertificate *certificate);

/**
 * Free structures connected with certificate.
 *
 * @param[in] certificate  Certificate to free
 */
void certsvc_certificate_free(CertSvcCertificate certificate);

/**
 * Save certificate to file in @a location in DER format.
 *
 * @param[in] certificate  Certificate
 * @param[in] location     Location
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcCertificate
 */
int certsvc_certificate_save_file(CertSvcCertificate certificate, const char *location);

/**
 * Search certificate with specific data. Result is stored in CertSvcInstance.
 * This function will erase all preverious results stored in CertSvcInstance but
 * it will not erase any CertSvcCertificate.
 *
 * You can search by fields: CERTSVC_SUBJECT, CERTSVC_ISSUER, CERTSVC_SUBJECT_COMMON_NAME
 *
 * @param[in]  instance  CertSvcInstance object
 * @param[in]  field     Certificate field to find with
 * @param[in]  value     Value to search for
 * @param[out] handler   Handler to search result. Must be freed by
 *                       certsvc_certificate_list_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_certificate_list_free()
 * @see certsvc_certificate_list_get_one()
 * @see certsvc_certificate_list_get_length()
 * @see #CertSvcCertificateField
 * @see #CertSvcCertificateList
 */
int certsvc_certificate_search(CertSvcInstance instance,
							   CertSvcCertificateField field,
							   const char *value,
							   CertSvcCertificateList *handler);

/**
 * Get certificate from list founded by certsvc_certificate_search().
 * Can be called multiple times to get all results.
 * Returned certificate can be freed. certsvc_certificate_list_free() doesn't
 * free certificates in the list.
 *
 * @param[in]  hadler      Hander to search results.
 * @param[in]  position    List index start from 0
 * @param[out] certificate Certficate i
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_certificate_search()
 * @see certsvc_certificate_free()
 * @see #CertSvcCertificate
 * @see #CertSvcCertificateList
 */
int certsvc_certificate_list_get_one(CertSvcCertificateList handler,
									 size_t position,
									 CertSvcCertificate *certificate);

/**
 * Return number of elements on the list.
 *
 * @param[in]  handler  Handler to certifiacte list
 * @param[out] length   Size of list
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_certificate_search()
 * @see #CertSvcCertificateList
 */
int certsvc_certificate_list_get_length(CertSvcCertificateList handler,
										size_t *size);

/**
 * Free @a CertSvcCertificateList. It will not free certificates on the list.
 * You may free each certificate with certsvc_certificate_free().
 *
 * @param[in] handler  Handler to search result
 *
 * @see certsvc_certificate_search()
 * @see certsvc_certificate_list_get_one()
 * @see certsvc_certificate_free()
 * @see #CertSvcCertificateList
 */
void certsvc_certificate_list_free(CertSvcCertificateList handler);

/**
 * This function will free list. It will free all certificates on the list.
 * You should ""NOT"" free each certificate with certsvc_certificate_free.
 *
 * @param[in] handler Handler to search result.
 */
void certsvc_certificate_list_all_free(CertSvcCertificateList handler);

/**
 * Compare parent certificate subject with child issuer field.
 *
 * @param[in]  child   Child certificate. Issuer field will be used
 * @param[in]  parent  Parent certificate. Subject field will be used
 * @param[out] status  #CERTSVC_TRUE if @a child is signed by @a parent,
 *                     else #CERTSVC_FALSE
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcCertificate
 */
int certsvc_certificate_is_signed_by(CertSvcCertificate child,
									 CertSvcCertificate parent,
									 int *status);

/**
 * Extract data field from certificate. Data in buffer could be free by
 * certsvc_string_free() function or by certsvc_instance_free or vcore_instance_reset.
 *
 * @param[in]  certificate  Certificate
 * @param[in]  field        Certificate field to get
 * @param[out] buffer       output string. Must be freed by certsvc_string_free()
 *                          or certsvc_instance_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_free()
 * @see certsvc_string_free()
 * @see #CertSvcCertificate
 * @see #CertSvcCertificateField
 */
int certsvc_certificate_get_string_field(CertSvcCertificate certificate,
		CertSvcCertificateField field,
		CertSvcString *buffer);

/**
 * Extract NOT AFTER field from certificate.
 *
 * @param[in]  certificate  Certificate
 * @param[out] result       not after time_t
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcCertificate
 */
int certsvc_certificate_get_not_after(CertSvcCertificate certificate, time_t *result);

/**
 * Extract NOT BEFORE field from certificate.
 *
 * @param[in]   certificate  Certificate
 * @param[out]  result       not before time_t
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 */
int certsvc_certificate_get_not_before(CertSvcCertificate certificate, time_t *result);

/**
 * Check whether the certificate is root ca by checking self-signedness.
 * TODO: This fuction should also check ROOTCA field in certificate.
 *
 * @param[in]   certificate  Certificate
 * @param[out]  status       #CERTSVC_TRUE or #CERTSVC_FALSE
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcCertificate
 */
int certsvc_certificate_is_root_ca(CertSvcCertificate certificate, int *status);

/**
 * Sort certificates chain. This fuction modifies certificate_array.
 *
 * @param[in/out] unsortedChain  unsorted chain in form of @a CertSvcCertificate array
 *                               which will be sorted from end entity certificate on
 *                               the first position and (root) CA certificate on the
 *                               last position
 * @param[in]     size           Size of @a unsortedChain
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcCertificate
 */
int certsvc_certificate_chain_sort(CertSvcCertificate *unsortedChain, size_t size);

/**
 * Base64 string will be connected with same instance as message.
 *
 * @param[in]  message  Buffer with input data
 * @param[out] base64   Buffer with output data which must be freed by
 *                      certsvc_string_free() or certsvc_instance_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_free()
 * @see certsvc_string_free()
 */
int certsvc_base64_encode(CertSvcString message, CertSvcString *base64);

/**
 * Message string will be connected with same certsvc instance as base64.
 *
 * @param[in]  base64   Buffer with input data
 * @param[out] message  Buffer with output data which must be freed by
 *                      certsvc_string_free() or certsvc_instance_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_free()
 * @see certsvc_string_free()
 */
int certsvc_base64_decode(CertSvcString base64, CertSvcString *message);

/**
 * Verify signature with given arguments.
 *
 * @param[in]  certificate  Certificate
 * @param[in]  message      Message
 * @param[in]  signature    Signature to verify
 * @param[in]  algorithm    May be set to NULL
 * @param[out] status       #CERTSVC_SUCCESS if success, else #CERTSVC_INVALID_SIGNATURE
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 */
int certsvc_message_verify(
	CertSvcCertificate certificate,
	CertSvcString message,
	CertSvcString signature,
	const char *algorithm,
	int *status);

/**
 * Verify certificate. Root CA certificate should be stored in @a trusted.
 *
 * @param[in]  certificate    Certificate
 * @param[in]  trusted        Array with trusted certificates
 * @param[in]  trustedSize    Array size of @a trusted
 * @param[in]  untrusted      Array with untrusted certificates
 * @param[in]  untrustedSize  Array size of @a untrusted
 * @param[out] status         #CERTSVC_SUCCESS if success, else #CERTSVC_FAIL
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 */
int certsvc_certificate_verify(
	CertSvcCertificate certificate,
	const CertSvcCertificate *trusted,
	size_t trustedSize,
	const CertSvcCertificate *untrusted,
	size_t untrustedSize,
	int *status);

/**
 * Verify certificate with strict check of CA flag. Root CA certificate should
 * be stored in @a trusted.
 *
 * @param[in]  certificate    Certificate
 * @param[in]  trusted        Array with trusted certificates
 * @param[in]  trustedSize    Array size of @a trusted
 * @param[in]  untrusted      Array with untrusted certificates
 * @param[in]  untrustedSize  Array size of @a untrusted
 * @param[out] status         #CERTSVC_SUCCESS if success, else #CERTSVC_FAIL
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 */
int certsvc_certificate_verify_with_caflag(
	CertSvcCertificate certificate,
	const CertSvcCertificate *trusted,
	size_t trustedSize,
	const CertSvcCertificate *untrusted,
	size_t untrustedSize,
	int *status);

/**
 * Get visibility from Tizen app signing root certificate.
 *
 * @param[in]  certificate  Tizen app signing root certificate to get visibility
 * @param[out] visibility   Visibilitay level of @a certificate
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see #CertSvcVisibility
 */
int certsvc_certificate_get_visibility(CertSvcCertificate certificate, CertSvcVisibility *visibility);


#ifdef __cplusplus
}
#endif

#endif

