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

#include <openssl/pkcs12.h>
#include <openssl/pem.h>

#include "orig/cert-service.h"
#include "orig/cert-service-util.h"
#include "orig/cert-service-debug.h"
#include "orig/cert-service-process.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#define CERT_BODY_PREFIX  "-----BEGIN CERTIFICATE-----"
#define CERT_BODY_SUFIX   "-----END CERTIFICATE-----"
#define ICERT_BODY_PREFIX "-----BEGIN TRUSTED CERTIFICATE-----"
#define ICERT_BODY_SUFIX  "-----END TRUSTED CERTIFICATE-----"

/* Tables for base64 operation */
static const unsigned char base64Table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', //  0 ~ 15
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', // 16 ~ 31
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', // 32 ~ 47
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'  // 48 ~ 63
};
static int base64DecodeTable[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //   0 ~  15
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, //  16 ~  31
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, //  32 ~  47
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, //  48 ~  63
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, //  64 ~  79
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, //  80 ~  95
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, //  96 ~ 111
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 112 ~ 127
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128 ~ 143
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 144 ~ 159
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 160 ~ 175
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 176 ~ 191
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 192 ~ 207
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 208 ~ 223
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 224 ~ 239
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1  // 240 ~ 255
};

int get_content_into_buf_PEM(unsigned char* content, cert_svc_mem_buff* cert)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char *startPEM, *endPEM;
	unsigned char* original = NULL;
	long size = 0;
	unsigned char* decoded = NULL;
	int decodedSize = 0;
	int i = 0, j = 0;

	if(!content) {
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}
	startPEM = strstr((const char *)content, CERT_BODY_PREFIX);
	startPEM = (startPEM) ? startPEM + strlen(CERT_BODY_PREFIX) : NULL;
	endPEM = strstr((const char *)content, CERT_BODY_SUFIX);
	if(!startPEM || !endPEM) {
		startPEM = strstr((const char *)content, ICERT_BODY_PREFIX);
		startPEM = (startPEM) ? startPEM + strlen(ICERT_BODY_PREFIX) : NULL;
		endPEM = strstr((const char *)content, ICERT_BODY_SUFIX);
	}
	if(!startPEM || !endPEM) {
		ret = CERT_SVC_ERR_UNKNOWN_ERROR;
		goto err;
	}
	else {
		++startPEM;
		--endPEM;
		size = (long)endPEM - (long)startPEM;
	}

	if(!(original = (unsigned char *)malloc(sizeof(unsigned char) * (size + 1)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(original, 0x00, (size + 1));

	for(i = 0, j = 0; i < size; i++) {
		if(startPEM[i] != '\n')
			original[j++] = startPEM[i];
	}

	size = strlen((char *)original);
	decodedSize = ((size / 4) * 3) + 1;

	if(!(decoded = (unsigned char *)malloc(sizeof(unsigned char) * decodedSize))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(decoded, 0x00, decodedSize);
	if((ret = cert_svc_util_base64_decode(original, size, decoded, &decodedSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to base64 decode.", __func__);
		free(decoded);
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	cert->data = decoded;
	cert->size = decodedSize;

err:
    free(original);

	return ret;
}

int get_content_into_buf_DER(unsigned char* content, cert_svc_mem_buff* cert)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	unsigned char* certData = NULL;

	certData = (unsigned char*)malloc(sizeof(unsigned char) * (cert->size));
	if(certData == NULL) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memcpy(certData, content, cert->size);
	cert->data = certData;

err:
	return ret;
}

int cert_svc_util_get_file_size(const char* filepath, unsigned long int* length)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	FILE* fp_in = NULL;

	if(!(fp_in = fopen(filepath, "r"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filepath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	fseek(fp_in, 0L, SEEK_END);
	(*length) = ftell(fp_in);

err:
	if(fp_in != NULL)
		fclose(fp_in);

	return ret;
}

/* The dark side of cert-svc. */
int cert_svc_util_get_extension(const char* filePath, cert_svc_mem_buff* certBuf) {
    int ret = CERT_SVC_ERR_NO_ERROR;
    FILE *in = NULL;
    X509 *x = NULL;

    if ((in = fopen(filePath, "r")) == NULL) {
        SLOGE("[ERR] Error opening file %s", filePath);
        ret = CERT_SVC_ERR_FILE_IO;
        goto end;
    }

    if ((x = PEM_read_X509(in, NULL, NULL, NULL)) != NULL) {
        strncpy(certBuf->type, "PEM", sizeof(certBuf->type));
        goto end;
    }

    fseek(in, 0L, SEEK_SET);

    if ((x = PEM_read_X509_AUX(in, NULL, NULL, NULL)) != NULL) {
        strncpy(certBuf->type, "PEM", sizeof(certBuf->type));
        goto end;
    }

    fseek(in, 0L, SEEK_SET);

    if ((x = d2i_X509_fp(in, NULL)) != NULL) {
        strncpy(certBuf->type, "DER", sizeof(certBuf->type));
        goto end;
    }

    SLOGE("[ERR] Unknown file type: %s", filePath);
    ret = CERT_SVC_ERR_FILE_IO;

end:
    if (in && fclose(in)) {
        SLOGE("[ERR] Fail in fclose.");
        ret = CERT_SVC_ERR_FILE_IO;
    }
    X509_free(x);
    return ret;
}

int cert_svc_util_load_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	// open file and get content
	FILE* fp_in = NULL;
	unsigned char* content = NULL;
	unsigned long int fileSize = 0;

	/* get file size */
	if((ret = cert_svc_util_get_file_size(filePath, &fileSize)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get file size, [%s]", __func__, filePath);
		goto err;
	}
	certBuf->size = fileSize;

	/* open file and write to buffer */
	if(!(fp_in = fopen(filePath, "rb"))) {
		SLOGE("[ERR][%s] Fail to open file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}

	if(!(content = (unsigned char*)malloc(sizeof(unsigned char) * (unsigned int)(fileSize + 1)))) {
		SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
    memset(content, 0x00, (fileSize + 1));  //ensuring that content[] will be NULL terminated
	if(fread(content, sizeof(unsigned char), fileSize, fp_in) != fileSize) {
		SLOGE("[ERR][%s] Fail to read file, [%s]", __func__, filePath);
		ret = CERT_SVC_ERR_FILE_IO;
		goto err;
	}
    content[fileSize] = 0; // insert null on the end to make null-terminated string

	/* find out certificate type */
	memset(certBuf->type, 0x00, 4);
    if (cert_svc_util_get_extension(filePath, certBuf) != CERT_SVC_ERR_NO_ERROR) {
        SLOGE("[ERR] cert_svc_util_get_extension failed to identify %s", filePath);
        ret = CERT_SVC_ERR_FILE_IO;
        goto err;
    }

	/* load file into buffer */
	if(!strncmp(certBuf->type, "PEM", sizeof(certBuf->type))) {	// PEM format
		if((ret = get_content_into_buf_PEM(content, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to load file to buffer, [%s]", __func__, filePath);
			goto err;
		}
	}
	else if(!strncmp(certBuf->type, "DER", sizeof(certBuf->type))) {	// DER format
		if((ret = get_content_into_buf_DER(content, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to load file to buffer, [%s]", __func__, filePath);
			goto err;
		}
	}

err:
	if(fp_in != NULL)
		fclose(fp_in);

	if(content != NULL)
		free(content);

	return ret;
}

int cert_svc_util_base64_encode(const unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int inputLen = 0, i = 0;
	const unsigned char *cur = NULL;

	if((in == NULL) || (inLen < 1)) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	cur = in;
	inputLen = inLen;

	/* encode data */
	while(inputLen > 2) {
		out[i++] = base64Table[cur[0] >> 2];
		out[i++] = base64Table[((cur[0] & 0x03) << 4) + (cur[1] >> 4)];
		out[i++] = base64Table[((cur[1] & 0x0f) << 2) + (cur[2] >> 6)];
		out[i++] = base64Table[cur[2] & 0x3f];

		cur += 3;
		inputLen -= 3;
	}

	/* determine tail of output string */
	if(inputLen != 0) {	// 1 or 2
		out[i++] = base64Table[cur[0] >> 2];
		if(inputLen > 1) {	// 2
			out[i++] = base64Table[((cur[0] & 0x03) << 4) + (cur[1] >> 4)];
			out[i++] = base64Table[(cur[1] & 0x0f) << 2];
			out[i++] = '=';
		}
		else {	// 1
			out[i++] = base64Table[(cur[0] & 0x03) << 4];
			out[i++] = '=';
			out[i++] = '=';
		}
	}

	out[i] = '\0';
	(*outLen) = i;

err:
	return ret;
}

int cert_svc_util_base64_decode(const unsigned char *in, int inLen, unsigned char *out, int* outLen)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int inputLen = 0, i = 0, j = 0, tail = 0;
	const unsigned char *cur = NULL;
	unsigned char tmpBuf[4];

	if((in == NULL) || (inLen < 1)) {
		SLOGE("[ERR][%s] Check your parameter.", __func__);
		ret = CERT_SVC_ERR_INVALID_PARAMETER;
		goto err;
	}

	cur = in;
	inputLen = inLen;
	memset(tmpBuf, 0x00, 4);

	/* decode data */
	while(inputLen > 1) {
		for(j = 0; j < 4; j++) {
			if(cur[j] == '=') {
				tail++;
				tmpBuf[j] = 0x00;
			}
			else
				tmpBuf[j] = (unsigned char)base64DecodeTable[(int)cur[j]];
		}

		out[i++] = ((tmpBuf[0] & 0x3f) << 2) + ((tmpBuf[1] & 0x30) >> 4);
		out[i++] = ((tmpBuf[1] & 0x0f) << 4) + ((tmpBuf[2] & 0x3c) >> 2);
		out[i++] = ((tmpBuf[2] & 0x03) << 6) + (tmpBuf[3] & 0x3f);

		cur += 4;
		inputLen -= 4;

		memset(tmpBuf, 0x00, 4);
	}

	i -= tail;
	out[i] = '\0';
	(*outLen) = i;

err:
	return ret;
}

