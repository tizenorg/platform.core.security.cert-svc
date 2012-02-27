/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

#include <cert-service.h>
#include <tet_api.h>

#define CERT_PATH	"./data/Broot.pem"

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_SecurityFW_cert_svc_delete_certificate_from_store_func_01(void);
static void utc_SecurityFW_cert_svc_delete_certificate_from_store_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_SecurityFW_cert_svc_delete_certificate_from_store_func_01, POSITIVE_TC_IDX },
	{ utc_SecurityFW_cert_svc_delete_certificate_from_store_func_02, NEGATIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
}

static void cleanup(void)
{
}

/**
 * @brief Positive test case of cert_svc_delete_certificate_from_store()
 */
static void utc_SecurityFW_cert_svc_delete_certificate_from_store_func_01(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_add_certificate_to_store(CERT_PATH, "code-signing_java_operator");

	ret = cert_svc_delete_certificate_from_store("Broot.pem", "code-signing_java_operator");

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		tetResult = TET_FAIL;
		printf("[ERR] ret = [%d]\n", ret);
	}
	else
		tetResult = TET_PASS;

	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}

/**
 * @brief Negative test case of cert_svc_delete_certificate_from_store()
 */
static void utc_SecurityFW_cert_svc_delete_certificate_from_store_func_02(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_add_certificate_to_store(CERT_PATH, "code-signing_java_operator");

	ret = cert_svc_delete_certificate_from_store(NULL, NULL);

	if(ret != CERT_SVC_ERR_INVALID_PARAMETER) {
		tetResult = TET_FAIL;
		printf("[ERR] ret = [%d]\n", ret);
	}
	else
		tetResult = TET_PASS;

	cert_svc_delete_certificate_from_store("Broot.pem", "code-signing_java_operator");
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}
