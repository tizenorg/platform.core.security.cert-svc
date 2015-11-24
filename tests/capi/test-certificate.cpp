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

#include <iostream>

#include <string>
#include <cstring>
#include <openssl/x509.h>
#include <dpl/test/test_runner.h>

#include <cert-svc/ccert.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cprimitives.h>

#include "common-res.h"

void _get_string_field_and_check(
	CertSvcCertificate cert,
	CertSvcCertificateField field,
	const char *expected)
{
	CertSvcString fieldStr;
	int result = certsvc_certificate_get_string_field(
			cert,
			field,
			&fieldStr);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result,
		"Error in certsvc_certificate_get_string_field. "
		"field : " << field << " expected : " << expected);

	size_t size;
	const char *ptr;

	certsvc_string_to_cstring(fieldStr, &ptr, &size);

	if (ptr != NULL) {
		std::cout << "filed[" << field << "] str[" << ptr << "]" << std::endl;
		RUNNER_ASSERT_MSG(strncmp(ptr, expected, size) == 0,
			"extracted field isn't match to expected value");
	} else {
		std::cout << "field[" << field << "] is empty." << std::endl;
	}
}

RUNNER_TEST_GROUP_INIT(T0100_CAPI_CERTIFICATE)

RUNNER_TEST(T0101_certificate_new_from_file)
{
	CertSvcCertificate cert;
	int result = certsvc_certificate_new_from_file(
			vinstance,
			TestData::SelfSignedCAPath.c_str(),
			&cert);
	RUNNER_ASSERT_MSG(CERTSVC_TRUE == result, "Error reading certificate");

	CertSvcString string;

	certsvc_certificate_get_string_field(
		cert,
		CERTSVC_SUBJECT_COMMON_NAME,
		&string);

	const char *ptr = "Samsung";

	const char *buffer;
	size_t len;

	certsvc_string_to_cstring(string, &buffer, &len);

	result = strncmp(buffer, ptr, strlen(ptr));

	RUNNER_ASSERT_MSG(0 == result, "Error reading common name");

	certsvc_certificate_free(cert);
}

RUNNER_TEST(T0103_is_signed_by)
{
	CertSvcCertificate cert1, cert2;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::googleCA.c_str()),
			TestData::googleCA.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert1);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::google2nd.c_str()),
			TestData::google2nd.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert2);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

	int status;
	result = certsvc_certificate_is_signed_by(cert2, cert1, &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Chain verification failed");
	RUNNER_ASSERT_MSG(CERTSVC_TRUE == status, "Chain verification failed");
}

RUNNER_TEST(T0104_not_before_not_after)
{
	CertSvcCertificate cert;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::google2nd.c_str()),
			TestData::google2nd.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

	time_t before, after;
	result = certsvc_certificate_get_not_before(cert, &before);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error extracting NOT_BEFORE");
	RUNNER_ASSERT_MSG(before == 1084406400, "TODO");

	result = certsvc_certificate_get_not_after(cert, &after);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error extracting NOT_AFTER");
	//extracted: date --date="May 12 23:59:59 2014 GMT" +%s
	RUNNER_ASSERT_MSG(after == 1399939199, "TODO");
}

RUNNER_TEST(T01051_cert_get_field_subject)
{
	CertSvcCertificate cert;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::certFullField.c_str()),
			TestData::certFullField.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT,
		"/C=PO/ST=SeoulState/L=Seoul/O=SamsungSecond/OU=SoftwareCenterSecond/CN=TizenSecuritySecond/emailAddress=kyungwook.tak@gmail.com");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_COMMON_NAME,
		"TizenSecuritySecond");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_COUNTRY_NAME,
		"PO");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_STATE_NAME,
		"SeoulState");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_LOCALITY_NAME,
		"Seoul");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_ORGANIZATION_NAME,
		"SamsungSecond");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_ORGANIZATION_UNIT_NAME,
		"SoftwareCenterSecond");

	_get_string_field_and_check(
		cert,
		CERTSVC_SUBJECT_EMAIL_ADDRESS,
		"kyungwook.tak@gmail.com");
}

RUNNER_TEST(T01052_cert_get_field_issuer)
{
	CertSvcCertificate cert;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::certFullField.c_str()),
			TestData::certFullField.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER,
		"/C=KO/ST=Kyeongkido/L=Suwon/O=Samsung/OU=SoftwareCenter/CN=TizenSecurity/emailAddress=k.tak@samsung.com");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_COMMON_NAME,
		"TizenSecurity");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_COUNTRY_NAME,
		"KO");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_STATE_NAME,
		"Kyeongkido");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_LOCALITY_NAME,
		"Suwon");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_ORGANIZATION_NAME,
		"Samsung");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_ORGANIZATION_UNIT_NAME,
		"SoftwareCenter");

	_get_string_field_and_check(
		cert,
		CERTSVC_ISSUER_EMAIL_ADDRESS,
		"k.tak@samsung.com");
}

RUNNER_TEST(T01053_cert_get_field_other)
{
	CertSvcCertificate cert;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::certFullField.c_str()),
			TestData::certFullField.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	_get_string_field_and_check(
		cert,
		CERTSVC_VERSION,
		"1");

	_get_string_field_and_check(
		cert,
		CERTSVC_SERIAL_NUMBER,
		"a9:76:e0:81:e5:37:2b:98");

	_get_string_field_and_check(
		cert,
		CERTSVC_KEY_ALGO,
		"rsaEncryption");

	_get_string_field_and_check(
		cert,
		CERTSVC_SIGNATURE_ALGORITHM,
		"sha256WithRSAEncryption");

	_get_string_field_and_check(
		cert,
		CERTSVC_KEY,
		"                Public-Key: (1024 bit)\n"
		"                Modulus:\n"
		"                    00:d8:08:a3:a3:05:fb:e2:df:36:cd:e3:48:2f:3b:\n"
		"                    59:17:ce:e3:32:bf:9f:ef:f1:7c:fb:27:f9:7c:32:\n"
		"                    8b:88:ed:b0:cc:64:da:ff:f2:7b:f4:86:11:20:00:\n"
		"                    09:d0:85:14:12:ff:11:9f:63:01:db:bf:ea:4c:ee:\n"
		"                    28:32:79:4a:9a:61:5b:ef:97:a1:43:36:61:d3:71:\n"
		"                    1f:37:fa:fb:3f:09:2b:d2:0f:56:68:72:dd:bf:e1:\n"
		"                    42:55:5b:b4:18:85:00:cb:8b:3a:7d:43:0b:48:1f:\n"
		"                    4c:49:d8:46:06:41:b3:7b:f9:67:f3:77:e5:93:b5:\n"
		"                    16:80:b3:f3:2f:70:1e:60:17\n"
		"                Exponent: 65537 (0x10001)\n");
}

RUNNER_TEST(T0106_chain_sort)
{
	CertSvcCertificate cert1, cert2, cert3;

	int result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::certEE.c_str()),
			TestData::certEE.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert1);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::google2nd.c_str()),
			TestData::google2nd.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert2);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::googleCA.c_str()),
			TestData::googleCA.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert3);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	CertSvcCertificate collection[3];
	collection[0] = cert1;
	collection[1] = cert3;
	collection[2] = cert2;

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == certsvc_certificate_chain_sort(collection, 3), "FAIL TO SORT CERTIFICATE");

	RUNNER_ASSERT_MSG(collection[2].privateHandler == cert3.privateHandler, "certsvc_certificate_chain_sort failed");

	collection[0] = cert1;
	collection[1] = cert3;

	RUNNER_ASSERT_MSG(CERTSVC_FAIL == certsvc_certificate_chain_sort(collection, 2), "certsvc_certificate_chain_sort failed");
}

RUNNER_TEST_GROUP_INIT(T0200_CAPI_CERTIFICATE_VERIFY)

RUNNER_TEST(T0201_message_verify_dsa_sha1)
{
	CertSvcString msgb64, sigb64, msg, sig;

	int result = certsvc_string_new(
			vinstance,
			TestData::magda.message.c_str(),
			TestData::magda.message.size(),
			&msgb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

	result = certsvc_string_new(vinstance,
			TestData::magda.signature.c_str(),
			TestData::magda.signature.size(),
			&sigb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

	CertSvcCertificate cert;

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::magda.certificate.c_str()),
			TestData::magda.certificate.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	result = certsvc_base64_decode(msgb64, &msg);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");
	result = certsvc_base64_decode(sigb64, &sig);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	int status;
	result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
	RUNNER_ASSERT_MSG(status == CERTSVC_TRUE, "Error in verify message.");
}

RUNNER_TEST(T0202_message_verify_rsa_sha1)
{
	CertSvcString msgb64, sigb64, msg, sig;

	int result = certsvc_string_new(
			vinstance,
			TestData::filipSHA1.message.c_str(),
			TestData::filipSHA1.message.size(),
			&msgb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

	result = certsvc_string_new(
			vinstance,
			TestData::filipSHA1.signature.c_str(),
			TestData::filipSHA1.signature.size(),
			&sigb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

	CertSvcCertificate cert;

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::filipSHA1.certificate.c_str()),
			TestData::filipSHA1.certificate.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	result = certsvc_base64_decode(msgb64, &msg);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	result = certsvc_base64_decode(sigb64, &sig);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	int status;
	result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
	RUNNER_ASSERT_MSG(status == CERTSVC_SUCCESS, "Error in verify message.");

	std::string invalidMessage("q3plZ28gdHUgc3p1a2Fzej8K");

	result = certsvc_string_new(
			vinstance,
			invalidMessage.c_str(),
			invalidMessage.size(),
			&msgb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

	result = certsvc_base64_decode(msgb64, &msg);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
	RUNNER_ASSERT_MSG(status == CERTSVC_INVALID_SIGNATURE, "Error in verify message.");
}

RUNNER_TEST(T0203_message_verify_rsa_sha256)
{
	CertSvcString msgb64, sigb64, msg, sig;

	int result = certsvc_string_new(
			vinstance,
			TestData::filipSHA256.message.c_str(),
			TestData::filipSHA256.message.size(),
			&msgb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

	result = certsvc_string_new(
			vinstance,
			TestData::filipSHA256.signature.c_str(),
			TestData::filipSHA256.signature.size(),
			&sigb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

	CertSvcCertificate cert;

	result = certsvc_certificate_new_from_memory(
			vinstance,
			reinterpret_cast<const unsigned char *>(TestData::filipSHA256.certificate.c_str()),
			TestData::filipSHA256.certificate.size(),
			CERTSVC_FORM_DER_BASE64,
			&cert);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

	result = certsvc_base64_decode(msgb64, &msg);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	result = certsvc_base64_decode(sigb64, &sig);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	int status;
	result = certsvc_message_verify(cert, msg, sig, "sha256", &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
	RUNNER_ASSERT_MSG(status == CERTSVC_SUCCESS, "Error in verify message.");

	std::string invalidMessage("q3plZ28gdHUgc3p1a2Fzej8K");

	result = certsvc_string_new(
			vinstance,
			invalidMessage.c_str(),
			invalidMessage.size(),
			&msgb64);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

	result = certsvc_base64_decode(msgb64, &msg);
	RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

	result = certsvc_message_verify(cert, msg, sig, "sha256", &status);

	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
	RUNNER_ASSERT_MSG(status == CERTSVC_INVALID_SIGNATURE, "Error in verify message.");
}

RUNNER_TEST(T0204_certificate_verify)
{
	const int MAXC = 3;
	CertSvcCertificate certificate[MAXC];

	size_t certCount = 0;
	for (auto &cert : TestData::certChain)
		RUNNER_ASSERT_MSG(
			CERTSVC_SUCCESS ==
				certsvc_certificate_new_from_memory(
					vinstance,
					reinterpret_cast<const unsigned char *>(cert.c_str()),
					cert.size(),
					CERTSVC_FORM_DER_BASE64,
					&certificate[certCount++]),
			"Error reading certificate");

	int status;
	int result = certsvc_certificate_verify(certificate[0], &certificate[1], MAXC-1, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify(certificate[0], certificate, MAXC-1, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify(certificate[0], certificate, 1, certificate, MAXC, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify(certificate[0], &certificate[2], 1, certificate, MAXC, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

	// certsvc_certificate_verify_with_caflag
	result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC-1, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, 1, certificate, MAXC, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify_with_caflag(certificate[0], &certificate[2], 1, certificate, MAXC, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");
}

RUNNER_TEST(T0205_certificate_verify_with_caflag_selfsign_root)
{
	const int MAXC = 2;
	CertSvcCertificate certificate[MAXC];

	size_t certCount = 0;
	for (auto &cert : TestData::certChainSelfSigned)
		RUNNER_ASSERT_MSG(
			CERTSVC_SUCCESS ==
				certsvc_certificate_new_from_memory(
					vinstance,
					reinterpret_cast<const unsigned char *>(cert.c_str()),
					cert.size(),
					CERTSVC_FORM_DER_BASE64,
					&certificate[certCount++]),
			"Error reading certificate");

	int status;
	int result = certsvc_certificate_verify(certificate[0], certificate, MAXC, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

	result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC, NULL, 0, &status);
	RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
	RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");
}
