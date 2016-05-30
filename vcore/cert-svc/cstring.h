/**
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        cstring.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This is part of C api for ValidationCore.
 */
#ifndef _CERTSVC_CSTRING_H_
#define _CERTSVC_CSTRING_H_

#include <cert-svc/cinstance.h>
#include <cert-svc/cstring.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct CertSvcStringList_t {
	size_t privateHandler;
	CertSvcInstance privateInstance;
} CertSvcStringList;

typedef struct CertSvcString_t {
	/*
	 * You are not allowed to use private fields of this structure. It is internal
	 * implementation of strings and it may change at any time without notice!
	 * To extract data use certsvc_string_to_cstring function!
	 */
	char *privateHandler;
	size_t privateLength;
	CertSvcInstance privateInstance;
} CertSvcString;

/**
 * Create CertSvcString with input cstring and size. Newly allocated memory
 * is in same lifecycle with @a instance param unless freed by certsvc_string_free().
 * If empty string is needed, put NULL on @a input param and 0 on @a size param.
 *
 * @param[in]  instance  CertSvcInstance object
 * @param[in]  input     null-terminated string. Put #NULL if empty string needed
 * @param[in]  size      size of @a input to make. put #0 if empty string needed.
 *                       Can be smaller than length of @a input
 * @param[out] output    Output CertSvcString with newly allocated memory
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_new()
 * @see certsvc_instance_free()
 * @see certsvc_string_free()
 */
int certsvc_string_new(
	CertSvcInstance instance,
	const char *input,
	size_t size,
	CertSvcString *output);

/**
 * Create CertSvcString with @a input null-terminated string. @a output CertSvcString will
 * contain pointer to @a input so input could not be freed as long as ouput param is used.
 *
 * @param[in]  instance  CertSvcInstance object
 * @param[in]  input     null-terminated string. Put #NULL if empty string needed
 * @param[in]  size      size of @a input to make. put #0 if empty string needed.
 *                       Can be smaller than length of @a input
 * @param[out] output    Output CertSvcString based on @a input
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_string_new()
 * @see certsvc_string_free()
 */
int certsvc_string_not_managed(
	CertSvcInstance instance,
	const char *input,
	size_t size,
	CertSvcString *output);

/**
 * Get CertSvcString from CertSvcStringList with newly allocated memory.
 * Output CertSvcString can be freed by certsvc_string_free() or reset/free instance
 * of CertSvcInstance which is used to get the CertSvcStringList.
 *
 * @param[in]  handler   Handler to string list
 * @param[in]  position  Index of CertSvcString to get in CertSvcStringList
 * @param[out] buffer    Output CertSvcString must be freed by
 *                       certsvc_string_free() after use
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 *
 * @see certsvc_instance_free()
 * @see certsvc_string_free()
 */
int certsvc_string_list_get_one(CertSvcStringList hander,
								size_t position,
								CertSvcString *buffer);

/**
 * Get list size of CertSvcStringList.
 *
 * @param[in]  handler  Handler to string list
 * @param[out] size     Number of elements on the list
 *
 * @return #CERTSVC_SUCCESS on success, otherwise a zero or negative error value
 */
int certsvc_string_list_get_length(CertSvcStringList hander, size_t *size);

/**
 * Free CertSvcString.
 *
 * @param[in]  string   CertSvcString to free
 */
void certsvc_string_free(CertSvcString string);

/**
 * Free CertSvcStringList.
 *
 * @param[in]  handler   Handler to string list
 */
void certsvc_string_list_free(CertSvcStringList handler);

/**
 * Convert CertSvcString into null-terminated C string. Please note that this pointer
 * is valid as long as CertSvcString is valid.
 *
 * @param[in]  string  CertSvcString
 * @param[out] buffer  null-terminated c string
 * @param[out] len     Length of string
 */
void certsvc_string_to_cstring(CertSvcString string, const char **buffer, size_t *len);

#ifdef __cplusplus
}
#endif

#endif

