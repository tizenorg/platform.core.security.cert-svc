/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        pkcs12.h
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 container manipulation routines.
 */
#pragma once

#include <cert-svc/ccert.h>

/**
 * To import the p12/pfx/crt/pem file to specified store (WIFI_STORE/VPN_STORE/EMAIL_STORE).
 *
 * @param[in] storeType Refers to WIFI_STORE / VPN_STORE / EMAIL_STORE / ALL_STORE.
 * @param[in] path Path to file.
 * @param[in] password Password for opening the file.
 * @param[in] alias Logical name for certificate bundle identification (can't be empty).
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_DUPLICATED_ALIAS, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT, CERTSVC_BAD_ALLOC.
 */
int pkcs12_import_from_file_to_store(CertStoreType storeType, const char *path, const char *password, const char *alias);

/**
 * TO check if the p12/pfx file is protected by password or not.
 *
 * @param[in] filePath Where the file is located.
 * @param[out] passworded A boolean value to state if the file is protected by password or not.
 * @return CERTSVC_SUCCESS, CERTSVC_FAIL, CERTSVC_IO_ERROR, CERTSVC_WRONG_ARGUMENT.
 */
int pkcs12_has_password(const char *filepath, int *passworded);
