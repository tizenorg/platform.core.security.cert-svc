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
 * @file        test-time-conversion.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Internal class unit test : TimeConversion
 */

#include <cstring>
#include <openssl/asn1.h>

#include <dpl/test/test_runner.h>

#include "test-common.h"

#include <vcore/TimeConversion.h>

static void UnitWrapper(const char *str, int type, int expected)
{
	ASN1_TIME asn1Time;

	memset(&asn1Time, 0, sizeof(ASN1_TIME));

	ASN1_STRING_set(&asn1Time, str, strlen(str));
	asn1Time.type = type;

	time_t t = 0;
	int ret = ValidationCore::asn1TimeToTimeT(&asn1Time, &t);
	RUNNER_ASSERT_MSG(ret == expected,
					  "ret: " << ret
					  << " expected: " << expected
					  << " time t: " << t);
}

RUNNER_TEST_GROUP_INIT(T0040_TIME_CONVERSION)

RUNNER_TEST(T004101_utctime_positive_sec_and_Z_terminated)
{
	UnitWrapper("991231235959Z", V_ASN1_UTCTIME, 1);
}

RUNNER_TEST(T004102_utctime_positive_no_sec_and_Z_terminated)
{
	UnitWrapper("9912312359Z", V_ASN1_UTCTIME, 1);
}

RUNNER_TEST(T004103_utctime_positive_sec_and_plus)
{
	UnitWrapper("991231235959+1259", V_ASN1_UTCTIME, 1);
}

RUNNER_TEST(T004104_utctime_positive_sec_and_minus)
{
	UnitWrapper("991231235959-1259", V_ASN1_UTCTIME, 1);
}

RUNNER_TEST(T004105_utctime_positive_no_sec_and_plus)
{
	UnitWrapper("9912312359+1259", V_ASN1_UTCTIME, 1);
}

RUNNER_TEST(T004106_utctime_positive_no_sec_and_minus)
{
	UnitWrapper("9912312359-1259", V_ASN1_UTCTIME, 1);
}



RUNNER_TEST(T004201_utctime_negative_invalid_format_no_Z)
{
	UnitWrapper("9912312359", V_ASN1_UTCTIME, 0);
}

RUNNER_TEST(T004202_utctime_negative_invalid_format_no_minute)
{
	UnitWrapper("991231235Z", V_ASN1_UTCTIME, 0);
}

RUNNER_TEST(T004203_utctime_negative_invalid_format_too_long)
{
	UnitWrapper("9912312359+12590", V_ASN1_UTCTIME, 0);
}



RUNNER_TEST(T004301_gentime_positive_full_local_only)
{
	UnitWrapper("20001231235959.999", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004302_gentime_positive_full_utc_only)
{
	UnitWrapper("20001231235959.999Z", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004303_gentime_positive_full_local_and_utc_plus)
{
	UnitWrapper("20001231235959.999+1259", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004304_gentime_positive_full_local_and_utc_minus)
{
	UnitWrapper("20001231235959.999-1259", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004305_gentime_positive_no_fff_local_only)
{
	UnitWrapper("20001231235959", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004306_gentime_positive_no_fff_utc_only)
{
	UnitWrapper("20001231235959Z", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004307_gentime_positive_no_fff_local_and_utc_plus)
{
	UnitWrapper("20001231235959+1259", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004308_gentime_positive_no_fff_local_and_utc_minus)
{
	UnitWrapper("20001231235959-1259", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004309_gentime_positive_no_sec_utc_only)
{
	UnitWrapper("200012312359Z", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004310_gentime_positive_no_sec_local_and_utc_plus)
{
	UnitWrapper("200012312359+1259", V_ASN1_GENERALIZEDTIME, 1);
}

RUNNER_TEST(T004311_gentime_positive_no_sec_local_and_utc_minus)
{
	UnitWrapper("200012312359-1259", V_ASN1_GENERALIZEDTIME, 1);
}



RUNNER_TEST(T004401_gentime_negative_invalid_format)
{
	UnitWrapper("200012312359599999", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004402_gentime_negative_invalid_format)
{
	UnitWrapper("200012312359591", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004403_gentime_negative_invalid_format)
{
	UnitWrapper("2000123123595A", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004404_gentime_negative_invalid_format)
{
	UnitWrapper("20001231235959A", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004405_gentime_negative_invalid_format)
{
	UnitWrapper("2000123123595", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004406_gentime_negative_invalid_format)
{
	UnitWrapper("20001231235959+-", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004407_gentime_negative_invalid_format)
{
	UnitWrapper("20001231235959+12599", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004408_gentime_negative_invalid_format)
{
	UnitWrapper("20001231235959+1359", V_ASN1_GENERALIZEDTIME, 0);
}

RUNNER_TEST(T004409_gentime_negative_invalid_format)
{
	UnitWrapper("20000031235959", V_ASN1_GENERALIZEDTIME, 0);
}

/* k.tak : From openssl source, it's negative case for now */
RUNNER_TEST(T004410_gentime_negative_no_sec_local_only)
{
	UnitWrapper("200012312359", V_ASN1_GENERALIZEDTIME, 0);
}

