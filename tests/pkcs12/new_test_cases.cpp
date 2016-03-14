/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        new_test_cases.cpp
 * @author      Madhan A K (madhan.ak@samsung.com)
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     2.0
 * @brief       PKCS#12 test cases.
 */

#include <unistd.h>
#include <cstring>
#include <new>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <tzplatform_config.h>

#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cerror.h>
#include <cert-svc/cprimitives.h>

#include <dpl/test/test_runner.h>

#include "test-common.h"

static CertSvcInstance instance;

static CertSvcString wrapper_certsvc_string_new(const char *cStr)
{
	CertSvcString certsvcStr;
	int retval;

	if (cStr == NULL)
		retval = certsvc_string_new(instance, NULL, 0, &certsvcStr);
	else
		retval = certsvc_string_new(instance, cStr, strlen(cStr), &certsvcStr);

	RUNNER_ASSERT_MSG(retval == CERTSVC_SUCCESS,
		"Failed to certsvc_string_new with retval: " << retval);

	return certsvcStr;
}

const CertStoreType allStoreType = (CertStoreType)(WIFI_STORE | VPN_STORE | EMAIL_STORE);

#define CREATE_INSTANCE \
  certsvc_instance_new(&instance);
#define FREE_INSTANCE  \
  certsvc_instance_free(instance);

RUNNER_TEST(CERTSVC_PKCS12_1001_certsvc_get_root_cert_list)
{
	CREATE_INSTANCE

	CertSvcStoreCertList* certList = NULL;
	size_t length = 0;
	int result = certsvc_pkcs12_get_certificate_list_from_store(instance, SYSTEM_STORE, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1002_certsvc_set_cert_to_disabled_and_get_status_for_system_store)
{
	CertStatus status = ENABLED;
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("24ad0b63.0");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, SYSTEM_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");

	// if status is already disabled, roll it back to enable and go on
	if (status == DISABLED) {
		result = certsvc_pkcs12_set_certificate_status_to_store(instance, SYSTEM_STORE, DISABLED, Alias, ENABLED);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Roll back certificate status to system store failed.");
	}

	result = certsvc_pkcs12_set_certificate_status_to_store(instance, SYSTEM_STORE, DISABLED, Alias, DISABLED);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, SYSTEM_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");
	RUNNER_ASSERT_MSG(status == DISABLED, "invalid status from system store cert");

	result = certsvc_pkcs12_set_certificate_status_to_store(instance, SYSTEM_STORE, DISABLED, Alias, ENABLED);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to system store failed.");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, SYSTEM_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");
	RUNNER_ASSERT_MSG(status == ENABLED, "invalid status from system store cert");

	certsvc_string_free(Alias);

	FREE_INSTANCE
}

/* Install a CRT file to individual stores */
RUNNER_TEST(CERTSVC_PKCS12_1003_add_pem_file_in_individual_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerCertPemPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	CertSvcString Alias = wrapper_certsvc_string_new("PEM-wifi-server-1");
	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PEM file to WIFI store failed.");
	certsvc_string_free(Alias);

	Alias = wrapper_certsvc_string_new("PEM-wifi-server-2");
	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PEM file to VPN store failed.");
	certsvc_string_free(Alias);

	Alias = wrapper_certsvc_string_new("PEM-wifi-server-3");
	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PEM file to EMAIL store failed.");
	certsvc_string_free(Alias);

	certsvc_string_free(Path);

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");

	CertSvcStoreCertList *certListOrig = certList;
	int count = 0;
	CertSvcString strSubject;
	CertSvcString strIssuer;
	CertSvcCertificate certificate;
	while (certList) {
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &strSubject);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &strIssuer);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_free(strSubject);
		certsvc_string_free(strIssuer);
		certsvc_certificate_free(certificate);
		certList = certList->next;
		count++;
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1004_add_pem_file_in_all_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PEM-wifi-server-all-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerCertPemPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PEM file to all store failed.");

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1005_add_crt_file_in_individual_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("CRT-TestingCRT1");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::CertCrtPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing CRT file to WIFI store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing CRT file to VPN store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing CRT file to EMAIL store failed.");

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");

	CertSvcStoreCertList *certListOrig = certList;
	int count = 0;
	CertSvcString strSubject;
	CertSvcString strIssuer;
	CertSvcCertificate certificate;
	while (certList) {
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &strSubject);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &strIssuer);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_free(strSubject);
		certsvc_string_free(strIssuer);
		certsvc_certificate_free(certificate);
		certList = certList->next;
		count++;
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1006_add_crt_file_in_all_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("CRT-TestingCRT1-all-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::CertCrtPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing CRT file to all store failed.");

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1007_install_p12_file_to_individual_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("P12-WifiUser");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::UserP12WithPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::UserP12Pass.c_str());

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing p12 file to WIFI store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing p12 file to VPN store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing p12 file to EMAIL store failed.");

	CertSvcStoreCertList* certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1008_install_p12_file_to_all_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("P12-WifiUser-all-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::UserP12WithPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::UserP12Pass.c_str());

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing p12 file to WIFI store failed.");

	CertSvcStoreCertList* certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1009_install_pfx_file_to_individual_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerPfxWithPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::ServerPfxPass.c_str());

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to VPN store failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to EMAIL store failed.");

	CertSvcStoreCertList* certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1010_install_pfx_file_to_all_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer-all-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerPfxWithPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::ServerPfxPass.c_str());

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to WIFI store failed.");

	CertSvcStoreCertList* certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from system store failed");

	result = certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Freeing certificate list from system store failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

/* Getting all end user & root certificate list from WIFI,VPN,EMAIL store */
RUNNER_TEST(CERTSVC_PKCS12_1011_get_all_end_user_certificate_from_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length;
	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, WIFI_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting end user certificate list from WIFI_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, VPN_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting end user certificate list from VPN_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	result = certsvc_pkcs12_get_end_user_certificate_list_from_store(instance, EMAIL_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting end user certificate list from EMAIL_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, WIFI_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting root certificate list from WIFI_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, VPN_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting root certificate list from VPN_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	result = certsvc_pkcs12_get_root_certificate_list_from_store(instance, EMAIL_STORE, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting root certificate list from EMAIL_STORE failed.");
	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1012_delete_all_cert_from_multiple_store)
{
	int result;
	CertSvcString gname;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");

	CertSvcStoreCertList *certListOrig = certList;
	while (certList) {
		gname = wrapper_certsvc_string_new(certList->gname);
		result = certsvc_pkcs12_delete_certificate_from_store(instance, certList->storeType, gname);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Deleting certificate from store failed.");

		certsvc_string_free(gname);

		certList = certList->next;
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1013_install_pfx_file_to_one_store_and_get_list_from_multiple_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer-one-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerPfxWithPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::ServerPfxPass.c_str());

	int isUnique = 0;
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, allStoreType, Alias, &isUnique);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "check alias exists in store failed. result : " << result);

	if (!isUnique) {
		/* TODO: remove certificate which already exists and test continue */
		RUNNER_ASSERT_MSG(0, "Remove certificate which already exists and test continue");
	}

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to EMAIL_STORE failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to WIFI_STORE failed.");

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from all store failed");

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certList);

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1014_installing_pfx_without_password_to_individual_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer-without-password");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerPfxWithoutPassPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new("");

	int isUnique = 0;
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, allStoreType, Alias, &isUnique);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "check alias exists in store failed. result : " << result);

	if (!isUnique) {
		/* TODO: remove certificate which already exists and test continue */
		RUNNER_ASSERT_MSG(0, "Remove certificate which already exists and test continue");
	}

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Importing PFX file to all store failed. result : " << result );

	certsvc_string_free(Alias);
	certsvc_string_free(Path);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1015_get_certificate_from_store) {

	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, allStoreType, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from all store failed.");
	if (length == 0 || !certList) {
		/* TODO: add any cert to store for testing */
		RUNNER_ASSERT_MSG(0, "add any cert in store for testing");
	}

	CertSvcStoreCertList *certListOrig = certList;
	CertSvcString strSubject;
	CertSvcString strIssuer;
	CertSvcCertificate certificate;
	while (certList) {
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &strSubject);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &strIssuer);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_free(strSubject);
		certsvc_string_free(strIssuer);
		certsvc_certificate_free(certificate);
		certList = certList->next;
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1016_get_certificate_from_system_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, SYSTEM_STORE, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	if (length == 0 || !certList) {
		/* TODO: add any cert to store for testing */
		RUNNER_ASSERT_MSG(0, "add any cert in store for testing");
	}

	CertSvcStoreCertList *certListOrig = certList;
	CertSvcString strSubject;
	CertSvcString strIssuer;
	CertSvcCertificate certificate;
	while (certList) {
		result = certsvc_pkcs12_get_certificate_from_store(instance, certList->storeType, certList->gname, &certificate);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get certificate from store.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_SUBJECT, &strSubject);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(certificate, CERTSVC_ISSUER_COMMON_NAME, &strIssuer);
		RUNNER_ASSERT_MSG(result==CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_free(strSubject);
		certsvc_string_free(strIssuer);
		certsvc_certificate_free(certificate);
		certList = certList->next;
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1017_load_cert_list_from_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certListTemp = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, VPN_STORE, DISABLED, &certListTemp, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from VPN_STORE failed.");
	if (length == 0 || !certListTemp) {
		/* TODO: add any cert to store for testing */
		RUNNER_ASSERT_MSG(0, "add any cert in store for testing");
	}

	CertSvcString strSubject;
	CertSvcString strIssuer;
	CertSvcCertificate cert;
	CertSvcString gname = wrapper_certsvc_string_new(certListTemp->gname);

	CertSvcCertificateList certList;
	result = certsvc_pkcs12_load_certificate_list_from_store(instance, VPN_STORE, gname, &certList);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Load certificate list form VPN_STORE failed.");
	certsvc_string_free(gname);

	length = 0;
	result = certsvc_certificate_list_get_length(certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate list get length failed.");
	RUNNER_ASSERT_MSG(length > 0, "No certificate loaded.");

	for (size_t i = 0; i < length; i++) {
		result = certsvc_certificate_list_get_one(certList, i, &cert);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_certificate_list_get_one failed.");

		result = certsvc_certificate_get_string_field(cert, CERTSVC_SUBJECT, &strSubject);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get string field.");

		result = certsvc_certificate_get_string_field(cert, CERTSVC_ISSUER_COMMON_NAME, &strIssuer);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to get string field.");

		certsvc_string_free(strSubject);
		certsvc_string_free(strIssuer);
		certsvc_certificate_free(cert);
	}

	certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListTemp);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1018_get_duplicate_private_key)
{
	const char *privatekey_path = tzplatform_mkpath(TZ_SYS_SHARE, "cert-svc/pkcs12/temp.txt");

	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certListTemp = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, VPN_STORE, DISABLED, &certListTemp, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from VPN_STORE failed.");
	if (length == 0 || !certListTemp) {
		/* TODO: add any cert to store for testing */
		RUNNER_ASSERT_MSG(0, "add any cert in store for testing");
	}

	CertSvcString gname = wrapper_certsvc_string_new(certListTemp->gname);
	EVP_PKEY *privatekey = NULL;
	result = certsvc_pkcs12_dup_evp_pkey_from_store(instance, VPN_STORE, gname, &privatekey);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting duplicate private key from store failed.");
	certsvc_string_free(gname);

	FILE *fp = NULL;
	if (!(fp = fopen(privatekey_path, "w")))
		RUNNER_ASSERT_MSG(0, "Failed to open file for writing.");

	result = PEM_write_PrivateKey(fp, privatekey, NULL, NULL, 0, NULL, NULL);
	fclose(fp);
	unlink(privatekey_path);

	RUNNER_ASSERT_MSG(result != 0, "Failed to write private key onto file.");

	certsvc_pkcs12_free_evp_pkey(privatekey);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1019_check_alias_exists)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer-without-password");

	int isUnique = 0;
	result = certsvc_pkcs12_check_alias_exists_in_store(instance, allStoreType, Alias, &isUnique);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from all store failed.");

	certsvc_string_free(Alias);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1020_certsvc_set_cert_to_disabled_and_get_status_for_individual_store)
{
	CertStoreType storeTypeArr[3] = {VPN_STORE, WIFI_STORE, EMAIL_STORE};
	int result;

	CREATE_INSTANCE

	for (size_t j = 0; j < 3; j++) {
		CertStoreType storeType = storeTypeArr[j];

		CertSvcStoreCertList *certList = NULL;
		size_t length = 0;
		result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, DISABLED, &certList, &length);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");

		CertSvcStoreCertList *certListOrig = certList;
		while (certList) {
			CertSvcString Alias = wrapper_certsvc_string_new(certList->gname);

			CertStatus status;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");

			result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, DISABLED);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to system store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");
			RUNNER_ASSERT_MSG(status == DISABLED, "certificate status should be disabled");

			result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, DISABLED, Alias, ENABLED);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to system store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from system store failed.");
			RUNNER_ASSERT_MSG(status == ENABLED, "certificate status should be enabled");

			certsvc_string_free(Alias);

			certList = certList->next;
		}

		certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);
	}

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1021_add_pem_file_to_invalid_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("PFX-WifiServer-one-store");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerCertPemPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	result = certsvc_pkcs12_import_from_file_to_store(instance, (CertStoreType)-1, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result == CERTSVC_INVALID_STORE_TYPE, "Importing certifcate should be failed with invalid store type");

	result = certsvc_pkcs12_import_from_file_to_store(instance, SYSTEM_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing PEM file to SYSTEM_STORE should be failed");

	result = certsvc_pkcs12_delete_certificate_from_store(instance, SYSTEM_STORE, Alias);
	RUNNER_ASSERT_MSG(result!=CERTSVC_SUCCESS, "Deleting certificate from SYSTEM_STORE should be failed");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1022_certsvc_set_cert_to_disabled_and_get_status_for_invalid_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("eb375c3e.0");

	CertStatus status;
	result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status with invalid store type should be failed");

	result = certsvc_pkcs12_set_certificate_status_to_store(instance, NONE_STORE, DISABLED, Alias, DISABLED);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Set certificate status with invalid store type should be failed");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status with invalid store type should be failed");

	result = certsvc_pkcs12_set_certificate_status_to_store(instance, NONE_STORE, DISABLED, Alias, ENABLED);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Set certificate status with invalid store type should be failed");

	result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status with invalid store type should be failed");

	certsvc_string_free(Alias);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1023_certsvc_set_cert_to_disabled_and_get_status_for_invalid_store)
{
	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	int result = certsvc_pkcs12_get_certificate_list_from_store(instance, NONE_STORE, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Getting certificate list from invalid store should be failed");
	RUNNER_ASSERT_MSG((length == 0 && certList == NULL), "no output should be returned with invalid store");

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1024_certsvc_set_and_get_for_invalid_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("TestingCRT1");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::InvalidCertCrtPath.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(NULL);

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid CRT file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid CRT file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid CRT file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, NONE_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid CRT file should be failed.");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1025_install_invalid_pfx_file_to_individual_and_all_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcString Alias = wrapper_certsvc_string_new("WifiServer-123");
	CertSvcString Path = wrapper_certsvc_string_new(TestData::ServerPfxWithPass2Path.c_str());
	CertSvcString Pass = wrapper_certsvc_string_new(TestData::ServerPfx2Pass.c_str());

	result = certsvc_pkcs12_import_from_file_to_store(instance, SYSTEM_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid PFX file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, WIFI_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid PFX file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, VPN_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid PFX file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, EMAIL_STORE, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid PFX file should be failed.");

	result = certsvc_pkcs12_import_from_file_to_store(instance, allStoreType, Path, Pass, Alias);
	RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Importing invalid PFX file should be failed.");

	certsvc_string_free(Alias);
	certsvc_string_free(Path);
	certsvc_string_free(Pass);

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1026_enable_disable_status_certificate_from_invalid_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, WIFI_STORE, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list from store failed.");
	if (length == 0 || !certList) {
		/* TODO: add any cert to store for testing */
		RUNNER_ASSERT_MSG(0, "add any cert in store for testing");
	}

	while (certList) {
		CertSvcString Alias = wrapper_certsvc_string_new(certList->gname);

		CertStatus status;
		result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
		RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status from invalid store should be failed.");

		result = certsvc_pkcs12_set_certificate_status_to_store(instance, NONE_STORE, DISABLED, Alias, DISABLED);
		RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Set certificate status to invalid store should be failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
		RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status from invalid store should be failed.");

		result = certsvc_pkcs12_set_certificate_status_to_store(instance, NONE_STORE, DISABLED, Alias, ENABLED);
		RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Set certificate status to invalid store should be failed.");

		result = certsvc_pkcs12_get_certificate_status_from_store(instance, NONE_STORE, Alias, &status);
		RUNNER_ASSERT_MSG(result != CERTSVC_SUCCESS, "Get certificate status from invalid store should be failed.");

		certsvc_string_free(Alias);

		certList = certList->next;
	}

	FREE_INSTANCE
}

#define EAP_TLS_USER_CERT_PATH   "user_cert.pem"
#define EAP_TLS_PATH			 "/tmp/"
#define EAP_TLS_CA_CERT_PATH	 "ca_cert.pem"
#define EAP_TLS_PRIVATEKEY_PATH  "privatekey.pem"

RUNNER_TEST(CERTSVC_PKCS12_1027_get_alias_name_from_gname_from_store)
{
	int result;

	CREATE_INSTANCE

	CertSvcStoreCertList *certList = NULL;
	size_t length = 0;
	result = certsvc_pkcs12_get_certificate_list_from_store(instance, WIFI_STORE, DISABLED, &certList, &length);
	RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list failed.");

	int count = 1;
	while (certList) {
		CertSvcString Alias = wrapper_certsvc_string_new(certList->gname);

		char *alias = NULL;
		result = certsvc_pkcs12_get_alias_name_for_certificate_in_store(instance, certList->storeType, Alias, &alias);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting alias name from gname failed.");

		CertSvcCertificateList cert_list;
		result = certsvc_pkcs12_load_certificate_list_from_store(instance, certList->storeType, Alias, &cert_list);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_load_certificate_list failed");

		size_t cert_counts = 0;
		result = certsvc_certificate_list_get_length(cert_list, &cert_counts);
		RUNNER_ASSERT_MSG(cert_counts > 0, "there is no certificates");

		CertSvcCertificate *selected_certificate = new CertSvcCertificate[cert_counts];
		RUNNER_ASSERT_MSG(selected_certificate != NULL, "failed to allocate memory");

		CertSvcCertificate user_certificate;
		result = certsvc_certificate_list_get_one(cert_list, 0, &user_certificate);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_certificate_list_get_one failed");

		X509 *x509 = NULL;
		result = certsvc_certificate_dup_x509(user_certificate, &x509);

		char user_cert_path[512];

		const char *output_template = tzplatform_mkpath(TZ_SYS_SHARE, "cert-svc/pkcs12/file_%d");

		snprintf(user_cert_path, sizeof(user_cert_path), output_template, count++);
		FILE *fp = fopen(user_cert_path, "w");
		RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

		if (count == 5)
			break;

		result = PEM_write_X509(fp, x509);
		fclose(fp);

		certsvc_certificate_free_x509(x509);
		certList = certList->next;

		int cert_index = cert_counts - 1;
		selected_certificate[0] = user_certificate;

		char ca_cert_path[512];
		snprintf(ca_cert_path, sizeof(ca_cert_path), "%s%s_%s", EAP_TLS_PATH, certList->gname, EAP_TLS_CA_CERT_PATH);
		while (cert_index) {
			CertSvcCertificate ca_certificate;
			result = certsvc_certificate_list_get_one(cert_list, cert_index, &ca_certificate);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to certsvc_certificate_list_get_one");

			selected_certificate[cert_counts-cert_index] = ca_certificate;
			cert_index--;

			result = certsvc_certificate_dup_x509(ca_certificate, &x509);

			fp = fopen(ca_cert_path, "a");
			RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

			result = PEM_write_X509(fp, x509);
			fclose(fp);

			certsvc_certificate_free_x509(x509);
		}

		int validity = 0;
		result = certsvc_certificate_verify(selected_certificate[0], selected_certificate, cert_counts, NULL, 0, &validity);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to verify ca_certificate");
		RUNNER_ASSERT_MSG(validity != 0, "Invalid certificate");

		EVP_PKEY *privatekey = NULL;
		result = certsvc_pkcs12_dup_evp_pkey_from_store(instance, WIFI_STORE, Alias, &privatekey);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Failed to duplicate the private key for a certificate from wifi store");

		char privatekey_path[512];
		snprintf(privatekey_path, sizeof(privatekey_path), "%s%s_%s", EAP_TLS_PATH, certList->gname, EAP_TLS_PRIVATEKEY_PATH);
		fp = fopen(privatekey_path, "w");
		RUNNER_ASSERT_MSG(fp != NULL, "Failed to open the file for writing");

		result = PEM_write_PrivateKey(fp, privatekey, NULL, NULL, 0, NULL, NULL);
		fclose(fp);

		certsvc_pkcs12_free_evp_pkey(privatekey);

		certsvc_string_free(Alias);
		delete []selected_certificate;
	}

	FREE_INSTANCE
}

RUNNER_TEST(CERTSVC_PKCS12_1028_certsvc_set_cert_to_disabled_and_get_status_for_individual_store)
{
	CertStoreType array[3] = {VPN_STORE, WIFI_STORE, EMAIL_STORE};
	int result;

	CREATE_INSTANCE

	for (size_t j = 0; j < 3; j++) {
		CertStoreType storeType = array[j];

		CertSvcStoreCertList *certList = NULL;
		size_t length = 0;
		result = certsvc_pkcs12_get_certificate_list_from_store(instance, storeType, ENABLED, &certList, &length);
		RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Getting certificate list failed.");

		CertSvcStoreCertList *certListOrig = certList;
		while (certList) {
			CertSvcString Alias = wrapper_certsvc_string_new(certList->gname);

			CertStatus status;
			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from store failed.");

			result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, ENABLED, Alias, DISABLED);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from store failed.");

			result = certsvc_pkcs12_set_certificate_status_to_store(instance, storeType, ENABLED, Alias, ENABLED);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Set certificate status to store failed.");

			result = certsvc_pkcs12_get_certificate_status_from_store(instance, storeType, Alias, &status);
			RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "Get certificate status from store failed.");

			certsvc_string_free(Alias);

			certList = certList->next;
		}

		certsvc_pkcs12_free_certificate_list_loaded_from_store(instance, &certListOrig);
	}

	FREE_INSTANCE
}
