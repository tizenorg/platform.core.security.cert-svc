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
#include <dpl/test/test_runner.h>
#include <vcore/Certificate.h>

#include "test-common.h"

using namespace ValidationCore;

RUNNER_TEST_GROUP_INIT(T0030_Certificate)

/*
 * test: class Certificate
 * description: Certificate should parse data passed to object constructor.
 * expected: Getters should be able to return certificate information.
 */
RUNNER_TEST(T0031_Certificate)
{
	Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);
	std::string result;

	result = cert.getCommonName(Certificate::FIELD_SUBJECT);
	RUNNER_ASSERT_MSG(!result.empty(), "No common name");
	RUNNER_ASSERT_MSG(!result.compare("www.verisign.com"), "CommonName mismatch");

	result = cert.getCommonName(Certificate::FIELD_ISSUER);
	RUNNER_ASSERT_MSG(!result.empty(), "No common name");
	RUNNER_ASSERT_MSG(!result.compare("VeriSign Class 3 Extended Validation SSL SGC CA"),
					  "CommonName mismatch");

	result = cert.getCountryName();
	RUNNER_ASSERT_MSG(!result.empty(), "No country");
	RUNNER_ASSERT_MSG(!result.compare("US"), "Country mismatch");
}

/*
 * test: Certificate::getFingerprint
 * description: Certificate should parse data passed to object constructor.
 * expected: Function fingerprint should return valid fingerprint.
 */
RUNNER_TEST(T0032_Certificate)
{
	Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);

	Certificate::Fingerprint fin =
		cert.getFingerprint(Certificate::FINGERPRINT_SHA1);

	unsigned char buff[20] = {
		0xb9, 0x72, 0x1e, 0xd5, 0x49,
		0xed, 0xbf, 0x31, 0x84, 0xd8,
		0x27, 0x0c, 0xfe, 0x03, 0x11,
		0x19, 0xdf, 0xc2, 0x2b, 0x0a
	};
	RUNNER_ASSERT_MSG(fin.size() == 20, "Wrong size of fingerprint");

	for (size_t i = 0; i < 20; ++i) {
		RUNNER_ASSERT_MSG(fin[i] == buff[i], "Fingerprint mismatch");
	}
}

/*
 * test: Certificate::getAlternativeNameDNS
 * description: Certificate should parse data passed to object constructor.
 * expected: Function getAlternativeNameDNS should return list of
 * alternativeNames hardcoded in certificate.
 */
RUNNER_TEST(T0033_Certificate)
{
	Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);

	Certificate::AltNameSet nameSet = cert.getAlternativeNameDNS();

	RUNNER_ASSERT(nameSet.size() == 8);

	std::string str("verisign.com");
	RUNNER_ASSERT(nameSet.find(str) != nameSet.end());

	str = std::string("fake.com");
	RUNNER_ASSERT(nameSet.find(str) == nameSet.end());

}

/*
 * test: Certificate::isCA
 * description: Certificate should parse data passed to object constructor.
 * expected: 1st and 2nd certificate should be identified as CA.
 */
RUNNER_TEST(T0034_Certificate_isCA)
{
	Certificate cert1(TestData::googleCA, Certificate::FORM_BASE64);
	RUNNER_ASSERT(cert1.isCA() > 0);

	Certificate cert2(TestData::google2nd, Certificate::FORM_BASE64);
	RUNNER_ASSERT(cert2.isCA() > 0);

	Certificate cert3(TestData::google3rd, Certificate::FORM_BASE64);
	RUNNER_ASSERT(cert3.isCA() == 0);
}
