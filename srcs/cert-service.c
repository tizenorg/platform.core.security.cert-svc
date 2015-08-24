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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>

#include "cert-service.h"
#include "cert-service-util.h"
#include "cert-service-debug.h"
#include "cert-service-store.h"
#include "cert-service-process.h"

#ifndef CERT_SVC_API
#define CERT_SVC_API	__attribute__((visibility("default")))
#endif

#define AUTHOR_SIGNATURE "author-signature.xml"
#define DISTRIBUTOR_SIGNATURE "signature1.xml"

int __is_certified_device(const unsigned char* cert, int certSize)
{
	int (*CheckFunc)(const unsigned char *, int) = NULL;
	int (*CheckFile)(void) = NULL;
	void *handle = NULL;
	int result;
	unsigned char *base64cert = NULL;
	int base64certSize = 0;

	handle = dlopen("libcert-svc-vcore.so", RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		SLOGE("Failed to open notification binary");
		return 0;
	}

	CheckFile = (int(*)(void))(dlsym(handle, "CheckProfileFile"));
	if (!CheckFile) {
		SLOGE("Failed to open symbol CheckProfileFile");
        result = 0;
        goto err;
	}

	result = CheckFile();
	if (!result){
        SLOGD("checking file. device profile dose not exist.");
        result = -1;
        goto err;
	}

	base64cert = (unsigned char *)calloc(certSize*2, 1);
    if (!base64cert) {
        result = 0;
        goto err;
    }
	cert_svc_util_base64_encode(cert, certSize, base64cert, &base64certSize);

	CheckFunc = (int(*)(const unsigned char *, int))(dlsym(handle, "CheckDevice"));
	if (!CheckFunc) {
		SLOGE("Failed to open symbol CheckDevice");
        result = 0;
        goto err_ret_after_free;
	}

	result = CheckFunc(base64cert, base64certSize);
	SLOGD("Result of checking device : %d", result);

err_ret_after_free:
    free(base64cert);

err:
    dlclose(handle);
	return result;
}

int _cert_svc_verify_certificate_with_caflag(CERT_CONTEXT* ctx, int checkCAFlag, int* validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!ctx || !ctx->certBuf || ctx->fileNames) {
		SLOGE("[ERR][%s] Check your parameter. Cannot find certificate.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if(!(ctx->fileNames = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	if(!(ctx->fileNames->filename = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(ctx->fileNames->filename, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);
	ctx->fileNames->next = NULL;

	if((ret = _verify_certificate_with_caflag(ctx->certBuf, &(ctx->certLink), checkCAFlag, ctx->fileNames, validity)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to verify certificate.", __func__);
		goto err;
	}

	SLOGD("root cert path : %s", ctx->fileNames->filename);
	SLOGD("Success to verify certificate.");

err:
	return ret;
}

CERT_SVC_API
int cert_svc_add_certificate_to_store(const char* filePath, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char _filePath[CERT_SVC_MAX_FILE_NAME_SIZE];
	int pathSize = 0;

	if (!filePath) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	pathSize = strlen(filePath);

	if (pathSize <= 0 || pathSize >= CERT_SVC_MAX_FILE_NAME_SIZE) {
		SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	memset(_filePath, 0x0, sizeof(_filePath));

	if (filePath[0] != '/') { // not absolute path, this is regarded relative file path
		if (!getcwd(_filePath, sizeof(_filePath))) {
			SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
			return CERT_SVC_ERR_INVALID_OPERATION;
		}

		int cwdSize = 0;
		_filePath[sizeof(_filePath) - 1] = '\0';

		cwdSize = strlen(_filePath);

		if (cwdSize <=0 || (cwdSize + pathSize + 1) >= CERT_SVC_MAX_FILE_NAME_SIZE) {
			SLOGE("[ERR][%s] Check your parameter. Maybe file path is NULL.", __func__);
			return CERT_SVC_ERR_INVALID_OPERATION;
		}

		strncat(_filePath, "/", 1);
		strncat(_filePath, filePath, pathSize);
	} else {
		strncpy(_filePath, filePath, pathSize);
	}

	ret = _add_certificate_to_store(_filePath, location);

	if (ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to store certificate, [%s]", __func__, _filePath);
		return ret;
	}
	SLOGD("[%s] Success to add certificate [%s].", __func__, filePath);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_delete_certificate_from_store(const char* fileName, const char* location)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!fileName || fileName[0] == '/') {
		SLOGE("[ERR][%s] Check your parameter. Maybe file name is NULL or is not single name.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	ret = _delete_certificate_from_store(fileName, location);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to delete certificate, [%s]", __func__, fileName);
		return ret;
	}

	SLOGD("[%s] Success to delete certificate [%s].", __func__, fileName);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_verify_certificate(CERT_CONTEXT* ctx, int* validity)
{
	return _cert_svc_verify_certificate_with_caflag(ctx, 0, validity);
}

CERT_SVC_API
int cert_svc_verify_certificate_with_caflag(CERT_CONTEXT* ctx, int* validity)
{
	return _cert_svc_verify_certificate_with_caflag(ctx, 1, validity);
}

CERT_SVC_API
int cert_svc_extract_certificate_data(CERT_CONTEXT* ctx)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!ctx || !ctx->certBuf) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (ctx->certDesc != NULL) {
		SLOGE("[ERR][%s] certDesc field already be used.", __func__);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	if (!(ctx->certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(ctx->certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	if ((ret = _extract_certificate_data(ctx->certBuf, ctx->certDesc)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data.", __func__);
		free(ctx->certDesc);
		ctx->certDesc = NULL;
		return ret;
	}

	SLOGD("[%s] Success to extract certificate.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_search_certificate(CERT_CONTEXT* ctx, search_field fldName, char* fldData)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!ctx || fldName > SEARCH_FIELD_END || !fldData) {
		SLOGE("[ERR][%s] Invalid parameter. Check your parameter", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (ctx->fileNames != NULL) {
		SLOGE("[ERR][%s] fileNames field already be used.", __func__);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	if ((ret = _search_certificate(&(ctx->fileNames), fldName, fldData)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to search certificate.", ctx->fileNames);
		return ret;
	}

	SLOGD("[%s] Success to search certificate(s).", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
CERT_CONTEXT* cert_svc_cert_context_init()
{
	CERT_CONTEXT* ctx = NULL;

	if (!(ctx = (CERT_CONTEXT*)malloc(sizeof(CERT_CONTEXT)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return NULL;
	}

	ctx->certBuf = NULL;
	ctx->certDesc = NULL;
	ctx->certLink = NULL;
	ctx->fileNames = NULL;

	SLOGD("[%s] Success to initialize context.", __func__);

	return ctx;
}

CERT_SVC_API
int cert_svc_cert_context_final(CERT_CONTEXT* context)
{
	if (!context)
		return CERT_SVC_ERR_NO_ERROR;

	if (context->certBuf) {
		free(context->certBuf->data);
		free(context->certBuf);
		context->certBuf = NULL;
	}

	release_certificate_data(context->certDesc);
	release_cert_list(context->certLink);
	release_filename_list(context->fileNames);

	free(context);
	context = NULL;

	SLOGD("[%s] Success to finalize context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_load_buf_to_context(CERT_CONTEXT* ctx, unsigned char *buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int size = 0;
    unsigned char *decodedBuf = NULL;
    int decodedSize = 0;

	if (!ctx || !buf) {
		SLOGE("[ERR][%s] context or buf is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (ctx->certBuf) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load buffer content.", __func__);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	if (!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	size = strlen((char *)buf);
	decodedSize = ((size / 4) * 3) + 1;

	if (!(decodedBuf = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	if ((ret = cert_svc_util_base64_decode(buf, size, decodedBuf, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]", __func__, ret);
		free(decodedBuf);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	ctx->certBuf->data = decodedBuf;
	ctx->certBuf->size = decodedSize;

	SLOGD("[%s] Success to load certificate buffer content to context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_load_file_to_context(CERT_CONTEXT* ctx, const char* filePath)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!ctx || !filePath) {
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (ctx->certBuf) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.", __func__);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	if (!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	if ((ret = cert_svc_util_load_file_to_buffer(filePath, ctx->certBuf)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
		free(ctx->certBuf);
		ctx->certBuf = NULL;
		return CERT_SVC_ERR_INVALID_OPERATION;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_push_buf_into_context(CERT_CONTEXT *ctx, unsigned char* buf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* new = NULL;
	int size = 0;
	unsigned char* decodedBuf = NULL;
    int decodedSize = 0;

	if (!ctx || !buf) {
		SLOGE("[ERR][%s] context or buf is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	/* memory alloction new item */
	if (!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	if (!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		free(new);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	size = strlen((char *)buf);
	decodedSize = ((size / 4) * 3) + 1;

	if (!(decodedBuf = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		release_cert_list(new);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}

	if ((ret = cert_svc_util_base64_decode(buf, size, decodedBuf, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to decode string, ret: [%d]", __func__, ret);
		release_cert_list(new);
		free(decodedBuf);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	new->certificate->data = decodedBuf;
	new->certificate->size = decodedSize;
	new->next = NULL;

	/* attach new structure */
	if (!ctx->certLink) {
		ctx->certLink = new;
	} else {
		cur = ctx->certLink;
		while (cur->next)
			cur = cur->next;

		cur->next = new;
	}
	
	SLOGD("[%s] Success to push certificate buffer content to context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_push_file_into_context(CERT_CONTEXT *ctx, const char* filePath)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* cur = NULL;
	cert_svc_linked_list* new = NULL;

	if (!ctx || !filePath) {
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (!(new = (cert_svc_linked_list*)malloc(sizeof(cert_svc_linked_list)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(new, 0x00, sizeof(cert_svc_linked_list));

	if (!(new->certificate = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		free(new);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(new->certificate, 0x00, sizeof(cert_svc_mem_buff));

	if ((ret = cert_svc_util_load_file_to_buffer(filePath, new->certificate)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
		release_cert_list(new);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}
	new->next = NULL;

	/* attach new structure */
	if (!ctx->certLink) {
		ctx->certLink = new;
	} else {
		cur = ctx->certLink;
		while (cur->next)
			cur = cur->next;

		cur->next = new;
	}
	
	SLOGD("[%s] Success to push certificate file content to context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
int cert_svc_load_PFX_file_to_context(CERT_CONTEXT* ctx, unsigned char** privateKey, int* priKeyLen, const char* filePath, char* passPhrase)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if (!ctx || !filePath) {
		SLOGE("[ERR][%s] context or file path is NULL.", __func__);
		return CERT_SVC_ERR_INVALID_PARAMETER;
	}

	if (ctx->certBuf) {
		SLOGE("[ERR][%s] certBuf is already used. we cannot load file.", __func__);
		return CERT_SVC_ERR_INVALID_OPERATION;
	}

	if (!(ctx->certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		return CERT_SVC_ERR_MEMORY_ALLOCATION;
	}
	memset(ctx->certBuf, 0x00, sizeof(cert_svc_mem_buff));

	if ((ret = cert_svc_util_load_PFX_file_to_buffer(filePath, ctx->certBuf, &ctx->certLink, privateKey, priKeyLen, passPhrase)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to load file, filepath: [%s], ret: [%d]", __func__, filePath, ret);
		free(ctx->certBuf);
		ctx->certBuf = NULL;
		return CERT_SVC_ERR_INVALID_OPERATION;
	}
	
	SLOGD("[%s] Success to load certificate file content to context.", __func__);

	return CERT_SVC_ERR_NO_ERROR;
}

CERT_SVC_API
char* cert_svc_get_certificate_crt_file_path(void)
{
	return CERTSVC_CRT_FILE_PATH;
}

CERT_SVC_API
int cert_svc_util_parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld)
{
	return parse_name_fld_data(str, fld);
}
