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
 * @file     cert-service.h
 * @author   Kyungwook Tak (k.tak@samsung.com)
 * @version  1.0
 * @brief    cert-svc CAPI header
 */

#ifndef CERT_SERVICE_H
#define CERT_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

/* max size */
#define CERT_SVC_MAX_CERT_TYPE_SIZE 50
#define CERT_SVC_MAX_FILE_NAME_SIZE 256
#define CERT_SVC_MAX_BUFFER_SIZE    (4 * 1024)

/* error codes */
#define CERT_SVC_ERR_NO_ERROR                  0
#define CERT_SVC_ERR_UNKNOWN_ERROR             (-1)
#define CERT_SVC_ERR_BROKEN_CHAIN              (-2)
#define CERT_SVC_ERR_NO_ROOT_CERT              (-3)
#define CERT_SVC_ERR_INVALID_SIGNATURE         (-4)
#define CERT_SVC_ERR_INVALID_CERTIFICATE       (-5)
#define CERT_SVC_ERR_FILE_IO                   (-6)
#define CERT_SVC_ERR_UNSUPPORTED_HASH_TYPE     (-7)
#define CERT_SVC_ERR_UNSUPPORTED_KEY_TYPE      (-8)
#define CERT_SVC_ERR_INVALID_OPERATION         (-9)
#define CERT_SVC_ERR_BUFFER_TOO_SMALL          (-10)
#define CERT_SVC_ERR_NO_MORE_CERTIFICATE       (-11)
#define CERT_SVC_ERR_DUPLICATED_CERTIFICATE    (-12)
#define CERT_SVC_ERR_SYSTEM_CALL               (-13)
#define CERT_SVC_ERR_MEMORY_ALLOCATION         (-14)
#define CERT_SVC_ERR_INVALID_PARAMETER         (-15)
#define CERT_SVC_ERR_PERMISSION_DENIED         (-16)
#define CERT_SVC_ERR_IS_EXPIRED                (-17)
#define CERT_SVC_ERR_INVALID_NO_DEVICE_PROFILE (-25)
#define CERT_SVC_ERR_INVALID_DEVICE_UNIQUE_ID  (-26)

#define CERT_SVC_STORE_PATH "/usr/share/cert-svc/certs/"

typedef enum {
	SEARCH_FIELD_START = 0,
	ISSUER_COUNTRY = 0,
	ISSUER_STATEORPROVINCE,
	ISSUER_LOCALITY,
	ISSUER_ORGANIZATION,
	ISSUER_ORGANIZATIONUNIT,
	ISSUER_COMMONNAME,
	ISSUER_EMAILADDRESS,
	ISSUER_STR,
	SUBJECT_COUNTRY,
	SUBJECT_STATEORPROVINCE,
	SUBJECT_LOCALITY,
	SUBJECT_ORGANIZATION,
	SUBJECT_ORGANIZATIONUNIT,
	SUBJECT_COMMONNAME,
	SUBJECT_EMAILADDRESS,
	SUBJECT_STR,
	SEARCH_FIELD_END = 16,
} search_field;

typedef struct {
	unsigned int firstSecond;
	unsigned int firstMinute;
	unsigned int firstHour;
	unsigned int firstDay;
	unsigned int firstMonth;
	unsigned int firstYear;
	unsigned int secondSecond;
	unsigned int secondMinute;
	unsigned int secondHour;
	unsigned int secondDay;
	unsigned int secondMonth;
	unsigned int secondYear;
} cert_svc_validity_fld_data;

typedef struct {
	unsigned char* countryName;
	unsigned char* stateOrProvinceName;
	unsigned char* localityName;
	unsigned char* organizationName;
	unsigned char* organizationUnitName;
	unsigned char* commonName;
	unsigned char* emailAddress;
} cert_svc_name_fld_data;

typedef struct {
	unsigned char* name;
	unsigned char* data;
	int datasize;
} cert_svc_cert_fld_desc;

typedef struct {
	unsigned int version;
	unsigned int serialNumber;
	unsigned char* sigAlgo;
	unsigned char* issuerStr;
	cert_svc_name_fld_data issuer;
	cert_svc_validity_fld_data validPeriod;
	unsigned char* subjectStr;
	cert_svc_name_fld_data subject;
	unsigned char* pubKeyAlgo;
	int pubKeyLen;
	unsigned char* pubKey;
	unsigned char* issuerUID;
	unsigned char* subjectUID;
} cert_svc_information_fields;

typedef struct {
	unsigned int numOfFields;
	cert_svc_cert_fld_desc* fields;
} cert_svc_extension_fields;

typedef struct {
	char type[4];
	cert_svc_information_fields info;
	cert_svc_extension_fields ext;
	unsigned char* signatureAlgo;
	unsigned char* signatureData;
	int signatureLen;
} cert_svc_cert_descriptor;

typedef struct {
	unsigned char* data;
	char type[4];
	unsigned int size;
} cert_svc_mem_buff;

typedef struct _cert_svc_linked_list {
	cert_svc_mem_buff* certificate;
	struct _cert_svc_linked_list* next;
} cert_svc_linked_list;

typedef struct _cert_filename_list {
	char* filename;
	struct _cert_filename_list* next;
} cert_svc_filename_list;

typedef struct {
	cert_svc_mem_buff* certBuf;
	cert_svc_cert_descriptor* certDesc;
	cert_svc_linked_list* certLink;
	cert_svc_filename_list* fileNames;
} CERT_CONTEXT;

CERT_CONTEXT* cert_svc_cert_context_init();
int cert_svc_cert_context_final(CERT_CONTEXT* ctx);

int cert_svc_load_file_to_context(CERT_CONTEXT* ctx, const char* filePath);

int cert_svc_search_certificate(CERT_CONTEXT* ctx, search_field fldName, char* fldData);

int cert_svc_util_parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld);


#ifdef __cplusplus
}
#endif

#endif // CERT_SERVICE_H
