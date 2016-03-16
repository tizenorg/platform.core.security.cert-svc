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

#include <string>
#include <openssl/x509.h>

#include <dpl/test/test_runner.h>

#include <cert-svc/ccert.h>
#include <cert-svc/cprimitives.h>

#include "common-res.h"

RUNNER_TEST_GROUP_INIT(T0300_CAPI_PRIMITIVES)

RUNNER_TEST(T0301_dup_x509)
{
	const int MAXB = 1024;

	CertSvcCertificate certificate;

	int result = certsvc_certificate_new_from_memory(
					 vinstance,
					 reinterpret_cast<const unsigned char *>(TestData::googleCA.c_str()),
					 TestData::googleCA.size(),
					 CERTSVC_FORM_DER_BASE64,
					 &certificate);

	X509 *x509 = NULL;
	result = certsvc_certificate_dup_x509(certificate, &x509);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certsvc_certificate_dup_x509.");
	RUNNER_ASSERT_MSG(x509 != NULL, "Error in certsvc_certificate_dup_x509.");

	X509_NAME *name = X509_get_subject_name(x509);
	char buffer[MAXB];
	X509_NAME_oneline(name, buffer, MAXB);

	RUNNER_ASSERT_MSG(buffer == TestData::subjectGoogleCA, "Content does not match");

	certsvc_certificate_free_x509(x509);
}

RUNNER_TEST(T0302_dup_pubkey_der)
{
	CertSvcCertificate cert;

	int result = certsvc_certificate_new_from_memory(
					 vinstance,
					 reinterpret_cast<const unsigned char *>(TestData::googleCA.c_str()),
					 TestData::googleCA.size(),
					 CERTSVC_FORM_DER_BASE64,
					 &cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	unsigned char *pubkey = NULL;
	size_t len = 0;
	result = certsvc_certificate_dup_pubkey_der(cert, &pubkey, &len);

	RUNNER_ASSERT_MSG(
		CERTSVC_SUCCESS == result,
		"Error in certsvc_certificate_dup_pubkey_der. result : " << result);

	RUNNER_ASSERT_MSG(
		d2i_PUBKEY(NULL, const_cast<const unsigned char **>(&pubkey), static_cast<long>(len)) != NULL,
		"Error in converting returned der pubkey to internal.");
}
