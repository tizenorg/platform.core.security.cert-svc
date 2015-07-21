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
 * @file        pkcs12.c
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 container manipulation routines.
 */
#ifndef _PKCS12_H_
#define _PKCS12_H_

#include <cert-svc/ccert.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * To import the p12/pfx/crt/pem file to specified store (WIFI_STORE/VPN_STORE/EMAIL_STORE).
 *
 * @param[in] storeType Refers to WIFI_STORE / VPN_STORE / EMAIL_STORE / ALL_STORE.
 * @param[in] path Path to file.
 * @param[in] password Password for opening the file.
 * @param[in] alias Logical name for certificate bundle identification (can't be empty).
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_DUPLICATED_ALIAS, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_BAD_ALLOC.
 */
int  c_certsvc_pkcs12_import_from_file_to_store(CertStoreType storeType, const char *path, const char *password, const char *alias);

/**
 * To get the list of certificate information present in a store. User will be getting
 * the information in a linked list where every list will contain Alias, Path to certificate,
 * Certificate status of all the certificates present in the specified store.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] is_root_app If set to ENABLED, can get all the certs without any restriction (should be used only by master application).
 *                        If set to DISABLED, only certs which are enabled by master application can only be retrieved.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int  c_certsvc_pkcs12_get_certificate_list_from_store(CertStoreType storeType, int is_root_app, CertSvcStoreCertList **certList, size_t *length);

/**
 * To set the status for a specified certificate in a particular store to enabled / disabled.
 * The gname is the key for accessing the certificate.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[in] is_root_app Set as ENABLED/DISABLED. Enabled, if used by master application is changing the status. Disabled, should be used by other applications.
 * @param[in] status Allows to set the status of the certificate to enabled / disabled.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int  c_certsvc_pkcs12_set_certificate_status_to_store(CertStoreType storeType, int is_root_app, const char *gname, CertStatus status);

/**
 * To get the status (enabled/disabled) for the specified certificate in a particular store.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[out] status Returns the status of the certificate. It will be set Disable=0, Enable=1, Fail=-1.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_ALIAS_DOES_NOT_EXIST, CERTSVC_IO_ERROR
 */
int  c_certsvc_pkcs12_get_certificate_status_from_store(CertStoreType storeType, const char *gname, CertStatus *status);

/**
 * To get the encoded form of the specified certificate from the specified store.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @param[out] certBuffer Which will be having the encoded value of the certificate requested.
 * @param[out] certSize Which will be having the size of the buffer.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int  c_certsvc_pkcs12_get_certificate_buffer_from_store(CertStoreType storeType, const char *gname, char **certBuffer, size_t *certSize);

/**
 * To delete the certificate from the specified store (VPN_STORE, WIFI_STORE, EMAIL_STORE, SYSTEM_STORE, ALL_STORE).
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Referred as group name, is the key for accessing the certificate.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_INVALID_STORE_TYPE.
 */
int  c_certsvc_pkcs12_delete_certificate_from_store(CertStoreType storeType, const char* gname);

/**
 * To free the certificate list which got generated from
 * c_certsvc_pkcs12_get_certificate_list_from_store() function.
 *
 * @param[in] certList Linked-list having all the information about each certificate present in a store.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL.
 */
int  c_certsvc_pkcs12_free_aliases_loaded_from_store(CertSvcStoreCertList **certList);

/**
 * Checks if the alias exist in the user store or not.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] Alias Logical name for certificate bundle identification (can't be empty).
 * @param[out] isUnique A Boolean value which states if the alias is unique or not.
 * @return CERTSVC_SUCCESS, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT.
 */
int  c_certsvc_pkcs12_alias_exists_in_store(CertStoreType storeType, const char *alias, int *isUnique);

/**
 * Function to get the size of the file passed.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[in] gname Refers to unique name referring to the certificate.
 * @param[out] certs Provides the list of certificates matching the unique name provided.
 * @param[out] ncerts Provides the number of certs in certs.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int c_certsvc_pkcs12_load_certificates_from_store(CertStoreType storeType, const char *gname, char ***certs, size_t *ncerts);

/**
 * To load the private key for the specified certificate mapped by an Alias.
 *
 * @param[in] alias Logical name for certificate bundle identification (can't be empty).
 * @param[out] pkey Will hold the private key value of the certificate.
 * @param[out] count Will hold the siz of the private key buffer.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_BAD_ALLOC.
 */
int  c_certsvc_pkcs12_private_key_load_from_store(CertStoreType storeType, const char *gname, char **pkey, size_t *count);

/**
 * Gets the alias name for the gname passed.
 *
 * @param[in] instance CertSvcInstance object.
 * @param[in] gname Certificate identification of pfx/pkcs file.
 * @param[out] alias Alias name for the given gname.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_WRONG_ARGUMENT
 */
int c_certsvc_pkcs12_get_certificate_alias_from_store(CertStoreType storeType, const char *gname, char **alias);

/**
 * To get the list of only end user certificate information present in a store. User will be getting
 * the information in a linked list where every list will contain Alias, Path to certificate,
 * Certificate status of all the certificates present in the specified store.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int c_certsvc_pkcs12_get_end_user_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList **certList, size_t *length);

/**
 * To get the list of only root/trusted certificate information present in a store. User will be getting
 * the information in a linked list where every list will contain Alias, Path to certificate,
 * Certificate status of all the certificates present in the specified store.
 *
 * @param[in] storeType Refers to VPN_STORE / WIFI_STORE / EMAIL_STORE / SYSTEM_STORE / ALL_STORE.
 * @param[out] certList Linked-list having all the information about each certificate present in a store.
 * @param[out] length provides the length of the linked list.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_INVALID_STORE_TYPE.
 */
int c_certsvc_pkcs12_get_root_certificate_list_from_store(CertStoreType storeType, CertSvcStoreCertList **certList, size_t *length);

/**
 * TO check if the p12/pfx file is protected by password or not.
 *
 * @param[in] filePath Where the file is located.
 * @param[out] passworded A boolean value to state if the file is protected by password or not.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT.
 */
int  c_certsvc_pkcs12_has_password(const char *filepath, int *passworded);

/**
 * To free the certificates from memory which was loaded by
 * c_certsvc_pkcs12_load_certificates() functon.
 *
 * @param[in] certs A pointer holding all the certificates in memory.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR.
 */
void c_certsvc_pkcs12_free_certificates(char **certs);

#ifdef __cplusplus
}
#endif

#endif
