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

#define CERT_PATH	"./data/signing/chain1.crt"
#define MSG_PATH	"./data/signing/msg"
#define SIG_PATH	"./data/signing/msg.sig.enc"

static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_SecurityFW_cert_svc_verify_signature_func_01(void);
static void utc_SecurityFW_cert_svc_verify_signature_func_02(void);

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

struct tet_testlist tet_testlist[] = {
	{ utc_SecurityFW_cert_svc_verify_signature_func_01, POSITIVE_TC_IDX },
	{ utc_SecurityFW_cert_svc_verify_signature_func_02, NEGATIVE_TC_IDX },
	{ NULL, 0 }
};

static void startup(void)
{
}

static void cleanup(void)
{
}

/**
 * @brief Positive test case of cert_svc_verify_signature()
 */
static void utc_SecurityFW_cert_svc_verify_signature_func_01(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	int validity = 0, i =0, j = 0;
	CERT_CONTEXT* ctx = NULL;
	unsigned char *msg = NULL, *sig = NULL, *tmpsig = NULL;
	int msgLen = 0, sigLen = 0;
	FILE *fp_msg = NULL, *fp_sig = NULL;

	ctx = cert_svc_cert_context_init();

	if((ret = cert_svc_load_file_to_context(ctx, CERT_PATH)) != CERT_SVC_ERR_NO_ERROR) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_UNINITIATED;
		goto err;
	}

	fp_msg = fopen(MSG_PATH, "rb");
	fseek(fp_msg, 0L, SEEK_END);
	msgLen = ftell(fp_msg);
	fseek(fp_msg, 0L, SEEK_SET);
	msg = (unsigned char*)malloc(sizeof(unsigned char) * (msgLen + 1));
	memset(msg, 0x00, (msgLen + 1));
	fread(msg, sizeof(unsigned char), msgLen, fp_msg);

	fp_sig = fopen(SIG_PATH, "rb");
	fseek(fp_sig, 0L, SEEK_END);
	sigLen = ftell(fp_sig);
	fseek(fp_sig, 0L, SEEK_SET);
	sig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	memset(sig, 0x00, (sigLen + 1));
	tmpsig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	memset(tmpsig, 0x00, (sigLen + 1));
	fread(sig, sizeof(unsigned char), sigLen, fp_sig);

	for(i = 0; i < sigLen; i++) {
		if(sig[i] != '\n') {
			tmpsig[j] = sig[i];
			j++;
		}
	}

	ret = cert_svc_verify_signature(ctx, msg, msgLen, tmpsig, NULL, &validity);

	if(ret != CERT_SVC_ERR_NO_ERROR) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_FAIL;
	}
	else {
		printf("[LOG] verify_signature, validity: [%d]\n", validity);
		tetResult = TET_PASS;
	}

err:
	if(msg != NULL) free(msg);
	if(sig != NULL) free(sig);
	if(tmpsig != NULL) free(tmpsig);
	if(fp_msg != NULL) fclose(fp_msg);
	if(fp_sig != NULL) fclose(fp_sig);
	cert_svc_cert_context_final(ctx);

	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}

/**
 * @brief Negative test case of cert_svc_verify_signature()
 */
static void utc_SecurityFW_cert_svc_verify_signature_func_02(void)
{
	int tetResult = TET_FAIL;
	int ret = CERT_SVC_ERR_NO_ERROR;
	int validity = 0, i =0, j = 0;
	CERT_CONTEXT* ctx = NULL;
	unsigned char *msg = NULL, *sig = NULL, *tmpsig = NULL;
	int msgLen = 0, sigLen = 0;
	FILE *fp_msg = NULL, *fp_sig = NULL;

	ctx = cert_svc_cert_context_init();

	if((ret = cert_svc_load_file_to_context(ctx, CERT_PATH)) != CERT_SVC_ERR_NO_ERROR) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_UNINITIATED;
		goto err;
	}

	fp_msg = fopen(MSG_PATH, "rb");
	fseek(fp_msg, 0L, SEEK_END);
	msgLen = ftell(fp_msg);
	fseek(fp_msg, 0L, SEEK_SET);
	msg = (unsigned char*)malloc(sizeof(unsigned char) * (msgLen + 1));
	memset(msg, 0x00, (msgLen + 1));
	fread(msg, sizeof(unsigned char), msgLen, fp_msg);

	fp_sig = fopen(SIG_PATH, "rb");
	fseek(fp_sig, 0L, SEEK_END);
	sigLen = ftell(fp_sig);
	fseek(fp_sig, 0L, SEEK_SET);
	sig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	memset(sig, 0x00, (sigLen + 1));
	fread(sig, sizeof(unsigned char), sigLen, fp_sig);
	tmpsig = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	memset(tmpsig, 0x00, (sigLen + 1));

	for(i = 0; i < sigLen; i++) {
		if(sig[i] != '\n') {
			tmpsig[j] = sig[i];
			j++;
		}
	}

	ret = cert_svc_verify_signature(ctx, NULL, 0, sig, NULL, &validity);

	if(ret != CERT_SVC_ERR_INVALID_PARAMETER) {
		printf("[ERR] ret = [%d]\n", ret);
		tetResult = TET_FAIL;
	}
	else {
		printf("[LOG] verify_signature, validity: [%d]\n", validity);
		tetResult = TET_PASS;
	}

err:
	if(msg != NULL) free(msg);
	if(sig != NULL) free(sig);
	if(tmpsig != NULL) free(tmpsig);
	if(fp_msg != NULL) fclose(fp_msg);
	if(fp_sig != NULL) fclose(fp_sig);
	cert_svc_cert_context_final(ctx);

	printf("[%d] [%s]\n", tetResult, __FILE__);
	tet_result(tetResult);
}
