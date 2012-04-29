/*
 * certification service
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
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

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_SecurityFW_cert_svc_search_certificate_func_01(void);
static void utc_SecurityFW_cert_svc_search_certificate_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_SecurityFW_cert_svc_search_certificate_func_01, POSITIVE_TC_IDX },
	{ utc_SecurityFW_cert_svc_search_certificate_func_02, NEGATIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
	cert_svc_add_certificate_to_store("./data/Broot.pem", "ssl");
}

static void cleanup(void)
{
	cert_svc_delete_certificate_from_store("Broot.pem", "ssl");
}

/**
 * @brief Positive test case of cert_svc_search_certificate()
 */
static void utc_SecurityFW_cert_svc_search_certificate_func_01(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	search_field fldNo = ISSUER_EMAILADDRESS;
	char* fldData = "EmailR";
	CERT_CONTEXT* ctx = NULL;
	cert_svc_filename_list* start = NULL;

	ctx = cert_svc_cert_context_init();

	ret = cert_svc_search_certificate(ctx, fldNo, fldData);
	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_FAIL;
	}
	else {
		start = ctx->fileNames;
		printf("[LOG] path: [%s]\n", start->filename);
		tetResult = TET_PASS;
	}

	cert_svc_cert_context_final(ctx);
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}

/**
 * @brief Negative test case of cert_svc_search_certificate()
 */
static void utc_SecurityFW_cert_svc_search_certificate_func_02(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	search_field fldNo = ISSUER_EMAILADDRESS;
	char* fldData = "EmailR";
	CERT_CONTEXT* ctx = NULL;
	cert_svc_filename_list* start = NULL;

	ctx = cert_svc_cert_context_init();

	ret = cert_svc_search_certificate(ctx, -1, fldData);
	if(ret != CERT_SVC_ERR_INVALID_PARAMETER) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_FAIL;
	}
	else 
		tetResult = TET_PASS;

	cert_svc_cert_context_final(ctx);
	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}
