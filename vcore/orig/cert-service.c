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

#include "orig/cert-service.h"
#include "orig/cert-service-util.h"
#include "orig/cert-service-debug.h"

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
