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
 *  This is internal test. ocsp.h isn't included in devel package
 */
#include <vcore/Ocsp.h>

#include <vcore/SignatureData.h>

#include <dpl/test/test_runner.h>

#include "test-common.h"

using namespace ValidationCore;

RUNNER_TEST_GROUP_INIT(T0030_OCSP_CHECK)

/*
 *  Precondition
 *   1) cert chain should be constructed
 *   2) cert chain should be sorted
 *   3) cert chain length >= 3
 */
RUNNER_TEST(T0031_check_positive)
{
	try {
		SignatureData data;
		CertificateList certList;

		certList.push_back(CertificatePtr(new Certificate(TestData::certEE, Certificate::FORM_BASE64)));
		certList.push_back(CertificatePtr(new Certificate(TestData::certIM, Certificate::FORM_BASE64)));
		certList.push_back(CertificatePtr(new Certificate(TestData::certRoot, Certificate::FORM_BASE64)));

		data.setSortedCertificateList(certList);

		Ocsp::Result result = Ocsp::check(data);

		RUNNER_ASSERT_MSG(
			result == Ocsp::Result::GOOD,
			"verisign cert shouldn't be revoked");

	} catch (Ocsp::Exception::Base &e) {
		RUNNER_ASSERT_MSG(0, "Exception occured in T0031 : " << e.DumpToString());
	}
}
