/**
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/**
 * @file     cert-server-logic.c
 * @author   Madhan A K (madhan.ak@samsung.com)
 *           Kyungwook Tak (k.tak@samsung.com)
 * @version  1.0
 * @brief    cert-server logic.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/smack.h>
#include <sys/socket.h>

#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>

#include "orig/cert-service.h"
#include "orig/cert-service-debug.h"
#include <cert-svc/cerror.h>
#include <cert-svc/ccert.h>
#include <vcore/cert-svc-client.h>

#include <cert-server-logic.h>

static CertStatus int_to_CertStatus(int intval)
{
	switch (intval) {
	case 1:
		return ENABLED;
	case 0:
	default:
		return DISABLED;
	}
}

static int CertStatus_to_int(CertStatus status)
{
	switch (status) {
	case ENABLED:
		return 1;
	case DISABLED:
	default:
		return 0;
	}
}

char *add_shared_owner_prefix(const char *name)
{
	size_t alias_len = strlen(name) + strlen(ckmc_label_shared_owner) + strlen(ckmc_label_name_separator);
	char *ckm_alias = (char *)malloc(alias_len + 1);
	if (!ckm_alias) {
		SLOGE("Failed to allocate memory");
		return NULL;
	}
	memset(ckm_alias, 0, alias_len + 1);
	strncat(ckm_alias, ckmc_label_shared_owner, alias_len + 1);
	strncat(ckm_alias, ckmc_label_name_separator, alias_len + 1 - strlen(ckmc_label_shared_owner));
	strncat(ckm_alias, name, alias_len + 1 - strlen(ckmc_label_shared_owner) + strlen(ckmc_label_name_separator));

	return ckm_alias;
}

int ckmc_remove_alias_with_shared_owner_prefix(const char *name, int *result)
{
	char *ckm_alias = add_shared_owner_prefix(name);
	if (!ckm_alias) {
		SLOGE("Failed to allocate memory");
		return CERTSVC_BAD_ALLOC;
	}

	*result = ckmc_remove_alias(ckm_alias);

	free(ckm_alias);

	return CERTSVC_SUCCESS;
}

char *get_complete_path(const char *str1, const char *str2)
{
	char *result = NULL;
	int as_result;

	if (!str1 || !str2)
		return NULL;

	if (str1[strlen(str1) - 1] != '/')
		as_result = asprintf(&result, "%s/%s", str1, str2);
	else
		as_result = asprintf(&result, "%s%s", str1, str2);

	if (as_result >= CERTSVC_SUCCESS)
		return result;
	else
		return NULL;
}

/* TODO: root ssl file system refactor */
int add_file_to_dir(const char* dir, const char* pGname, const char* pData, size_t dataLen)
{
	char *systemFile = get_complete_path(dir, pGname);
	if (!systemFile) {
		SLOGE("Failed to get system file path.");
		return CERTSVC_FAIL;
	}

	char realFile[FILENAME_MAX] = {0};
	if (!realpath(systemFile, realFile)) {
		SLOGE("Failed to get realpath. systemFile[%s]", systemFile);
		return CERTSVC_FAIL;
	}

	FILE *stream = fopen(realFile, "ab");
	if (!stream) {
		SLOGE("Fail to open file [%s]", realFile);
		return CERTSVC_FAIL;
	}

	if (fwrite(pData, sizeof(char), dataLen, stream) != dataLen) {
		SLOGE("Fail to write file in system store.");
		fclose(stream);
		return CERTSVC_FAIL;
	}

	fclose(stream);
	return CERTSVC_SUCCESS;
}

int add_file_to_system_cert_dir(const char* pGname, const char* pData, size_t dataLen)
{
	return add_file_to_dir(SYSTEM_CERT_DIR, pGname, pData, dataLen);
}

/* TODO: root ssl file system refactor */
int del_file_from_dir(const char* dir, const char *pGname)
{
	const char *systemFile = get_complete_path(dir, pGname);
	if (!systemFile)   {
		SLOGE("Failed to construct source file path.");
		return CERTSVC_FAIL;
	}

	char realFile[FILENAME_MAX] = {0};
	if (!realpath(systemFile, realFile)) {
		SLOGE("Failed to get realpath. systemFile[%s]", systemFile);
		return CERTSVC_FAIL;
	}

	/* instead of removing the file, the file is trimmed to zero size */
	FILE *stream = fopen(realFile, "wb");
	if (!stream) {
		SLOGE("Failed to open the file for writing, [%s].", realFile);
		return CERTSVC_FAIL;
	}

	fclose(stream);
	return CERTSVC_SUCCESS;
}

int del_file_from_system_cert_dir(const char *pGname)
{
	return del_file_from_dir(SYSTEM_CERT_DIR, pGname);
}

int execute_insert_update_query(sqlite3 *db_handle, char *query)
{
	if (!db_handle) {
		SLOGE("Database not initialised.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (!query) {
		SLOGE("Query is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	/* Begin transaction */
	int result = sqlite3_exec(db_handle, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (result != SQLITE_OK) {
		SLOGE("Failed to begin transaction.");
		return CERTSVC_FAIL;
	}

	/* Executing command */
	result = sqlite3_exec(db_handle, query, NULL, NULL, NULL);
	if (result != SQLITE_OK) {
		SLOGE("Failed to execute query (%s).", query);
		return CERTSVC_FAIL;
	}

	/* Committing the transaction */
	result = sqlite3_exec(db_handle, "COMMIT", NULL, NULL, NULL);
	if (result) {
		SLOGE("Failed to commit transaction. Roll back now.");
		result = sqlite3_exec(db_handle, "ROLLBACK", NULL, NULL, NULL);
		if (result != SQLITE_OK)
			SLOGE("Failed to commit transaction. Roll back now.");

		return CERTSVC_FAIL;
	}

	SLOGD("Transaction Commit and End.");

	return CERTSVC_SUCCESS;
}

int execute_select_query(sqlite3 *db_handle, char *query, sqlite3_stmt **stmt)
{
	if (!db_handle || !query)
		return CERTSVC_WRONG_ARGUMENT;

	sqlite3_stmt *stmts = NULL;
	if (sqlite3_prepare_v2(db_handle, query, strlen(query), &stmts, NULL) != SQLITE_OK) {
		SLOGE("sqlite3_prepare_v2 failed [%s].", query);
		return CERTSVC_FAIL;
	}

	*stmt = stmts;
	return CERTSVC_SUCCESS;
}

int write_to_file(const char *fileName, const char *mode_of_writing, const char *certBuffer, size_t certLength)
{
	int result = CERTSVC_SUCCESS;
	FILE *fp_write = NULL;

	if (!certBuffer || certLength <= 0) {
		SLOGE("Input buffer is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (!(fp_write = fopen(fileName, mode_of_writing))) {
		SLOGE("Failed to open the file for writing, [%s].", fileName);
		return CERTSVC_FAIL;
	}

	/* if mode of writing is to append, then goto end of file */
	if (strcmp(mode_of_writing,"ab") == 0)
		fseek(fp_write, 0L, SEEK_END);

	if (fwrite(certBuffer, sizeof(char), certLength, fp_write) != certLength) {
		SLOGE("Fail to write into file.");
		result = CERTSVC_FAIL;
		goto error;
	}

	/* adding empty line at the end */
	fwrite("\n",sizeof(char), 1, fp_write);

error:
	if (fp_write)
		fclose(fp_write);

	return result;
}

int write_to_ca_cert_crt_file(const char *mode_of_writing, const char *certBuffer, size_t certLength)
{
	return write_to_file(CERTSVC_CRT_FILE_PATH, mode_of_writing, certBuffer, certLength);
}

int saveCertificateToStore(
	const char *pGname,
	const char *pData,
	size_t dataLen)
{
	if (!pGname || !pData || dataLen < 1) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	ckmc_policy_s cert_policy;
	cert_policy.password = NULL;
	cert_policy.extractable = true;

	ckmc_raw_buffer_s cert_data;
	cert_data.data = (unsigned char *)pData;
	cert_data.size = dataLen;

	char *ckm_alias = add_shared_owner_prefix(pGname);
	if (!ckm_alias) {
		SLOGE("Failed to make alias. memory allocation error.");
		return CERTSVC_BAD_ALLOC;
	}

	int result = ckmc_save_data(ckm_alias, cert_data, cert_policy);
	free(ckm_alias);

	if (result != CKMC_ERROR_NONE) {
		SLOGE("Failed to save trusted data. ckm errcode[%d]", result);
		return CERTSVC_FAIL;
	}

	return CERTSVC_SUCCESS;
}

int saveCertificateToSystemStore(
	const char *pGname,
	const char *pData,
	size_t dataLen)
{
	if (!pGname || !pData || dataLen < 1) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	int result = add_file_to_system_cert_dir(pGname, pData, dataLen);
	if (result != CERTSVC_SUCCESS)
		SLOGE("Failed to store the certificate in store.");

	return result;
}

int get_certificate_buffer_from_store(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char *pGname,
	char **certBuffer,
	size_t *certSize)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *tempBuffer = NULL;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!pGname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (storeType != SYSTEM_STORE)
		query = sqlite3_mprintf("select * from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d", \
							   ((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : \
							   (storeType == EMAIL_STORE)? "email" : "ssl"), pGname, ENABLED, ENABLED);
	else
		query = sqlite3_mprintf("select certificate from ssl where gname=%Q and enabled=%d and is_root_app_enabled=%d", \
								pGname, ENABLED, ENABLED);

	result = execute_select_query(db_handle, query, &stmt);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW || records == SQLITE_DONE) {
		SLOGE("No valid records found for given gname [%s].",pGname);
		result = CERTSVC_FAIL;
		goto error;
	}

	tempBuffer = (char *)malloc(sizeof(char) * VCORE_MAX_RECV_DATA_SIZE);
	if (!tempBuffer) {
		SLOGE("Fail to allocate memory");
		result = CERTSVC_FAIL;
		goto error;
	}

	memset(tempBuffer, 0x00, VCORE_MAX_RECV_DATA_SIZE);

	if (storeType == SYSTEM_STORE)
		result = getCertificateDetailFromSystemStore(db_handle, pGname, tempBuffer, certSize);
	else
		result = getCertificateDetailFromStore(db_handle, storeType, PEM_CRT, pGname, tempBuffer, certSize);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to set request data.");
		result = CERTSVC_WRONG_ARGUMENT;
		goto error;
	}

	*certBuffer = tempBuffer;

error:
	if (result != CERTSVC_SUCCESS)
		free(tempBuffer);

	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	return result;
}

int update_ca_certificate_file(sqlite3 *db_handle, char *certBuffer, size_t certLength)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	int count = 0;
	int counter = 0;
	char *pValue = NULL;
	char *query = NULL;
	const char *text;
	sqlite3_stmt *stmt = NULL;

	int storeType[4] = {SYSTEM_STORE, WIFI_STORE, VPN_STORE, EMAIL_STORE};

	/* During install of a root certificate, the root certificate gets appended at
	 * the end to optimise the write operation onto ca-certificate.crt file. */
	if (certBuffer && certLength > 0) {
		result = write_to_ca_cert_crt_file("ab", certBuffer, certLength);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Failed to write to file.");
			result = CERTSVC_FAIL;
		}
		goto error_and_exit;
	}

	while (count < 4) {
		/* get the ssl certificate from database */
		if (count == 0)
			query = sqlite3_mprintf("select certificate from ssl where enabled=%d and is_root_app_enabled=%d", ENABLED, ENABLED);
		else if (count > 0 && count < 4)
			/* gets all the gname which is marked as root certificate and enabled = TRUE */
			query = sqlite3_mprintf("select gname from %Q where is_root_cert=%d and enabled=%d and is_root_app_enabled=%d", \
							  ((count == 1)?"wifi":(count == 2)?"vpn":"email"), ENABLED, ENABLED, ENABLED);

		result = execute_select_query(db_handle, query, &stmt);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			goto next;
		}

		/* update the ca-certificate.crt file */
		while (1) {
			records = sqlite3_step(stmt);
			if (records != SQLITE_ROW || records == SQLITE_DONE) {
				result = CERTSVC_SUCCESS;
				break;
			}

			if (records == SQLITE_ROW) {
				certLength = 0;
				certBuffer = NULL;
				pValue = NULL;

				if (count == 0) {
					/* gets the certificate from database for system store */
					text = (const char *)sqlite3_column_text(stmt, 0);
					if (text) {
						certLength = strlen(text);
						certBuffer = strndup(text, certLength);
					}
				} else {
					/* gets the certificate from key-manager for other stores */
					text = (const char *)sqlite3_column_text(stmt, 0);
					if (text)
						pValue = strndup(text, strlen(text));

					result = get_certificate_buffer_from_store(db_handle, storeType[count], pValue, &certBuffer, &certLength);
					if (result != CERTSVC_SUCCESS) {
						SLOGE("Failed to get certificate buffer from key-manager.");
						goto error_and_exit;
					}
				}

				if (certBuffer) {
					if (counter++ == 0)
						result = write_to_ca_cert_crt_file("wb", certBuffer, certLength);
					else
						result = write_to_ca_cert_crt_file("ab", certBuffer, certLength);

					if (result != CERTSVC_SUCCESS) {
						SLOGE("Failed to write to file.");
						result = CERTSVC_FAIL;
						goto error_and_exit;
					}
				}
			}
		}
next:
		count++;
		if (query) {
			sqlite3_free(query);
			query = NULL;
		}
	}
	SLOGD("Successfully updated ca-certificate.crt file.");

error_and_exit:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	return result;
}

int enable_disable_cert_status(
	sqlite3 *db_handle,
	CertStoreType storeType,
	int is_root_app,
	const char *pGname,
	CertStatus status)
{
	int ckmc_result = CKMC_ERROR_UNKNOWN;
	int result = CERTSVC_SUCCESS;
	int records = 0;
	size_t certSize = 0;
	size_t certLength = 0;
	char *certBuffer = NULL;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;

	if (status != DISABLED && status != ENABLED) {
		SLOGE("Invalid cert status");
		return CERTSVC_INVALID_STATUS;
	}

	query = sqlite3_mprintf("select * from %Q where gname=%Q", ((storeType == WIFI_STORE)? "wifi" : \
			(storeType == VPN_STORE)? "vpn" : (storeType == EMAIL_STORE)? "email" : "ssl"), pGname);
	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_select_query(db_handle, query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS || !stmt) {
		SLOGE("Querying database failed.");
		return CERTSVC_FAIL;
	}

	records = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;

	if (records != SQLITE_ROW) {
		SLOGE("No valid records found.");
		return CERTSVC_FAIL;
	}

	if (status == DISABLED) {
		/* check certificate presence in disabled_certs table before inserting */
		query = sqlite3_mprintf("select * from disabled_certs where gname=%Q", pGname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(db_handle, query, &stmt);
		sqlite3_free(query);
		query = NULL;

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			return CERTSVC_FAIL;
		}

		records = sqlite3_step(stmt);
		sqlite3_finalize(stmt);
		stmt = NULL;

		if (records == SQLITE_ROW) {
			SLOGE("Selected certificate identifier is already disabled.", pGname);
			return CERTSVC_FAIL;
		}

		/* get certificate from keymanager*/
		result = get_certificate_buffer_from_store(db_handle, storeType, pGname, &certBuffer, &certSize);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Failed to get certificate buffer. result[%d]", result);
			return result;
		}

		/* inserting the disabled certificate to disabled_certs table */
		query = sqlite3_mprintf("insert into disabled_certs (gname, certificate) values (%Q, %Q)", pGname, certBuffer);
		free(certBuffer);

		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_insert_update_query(db_handle, query);
		sqlite3_free(query);

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Insert to database failed.");
			return result;
		}

		if (storeType != SYSTEM_STORE) {
			result = ckmc_remove_alias_with_shared_owner_prefix(pGname, &ckmc_result);

			if (result != CERTSVC_SUCCESS || ckmc_result != CKMC_ERROR_NONE) {
				SLOGE("Failed to delete certificate from key-manager. ckmc_result[%d]", ckmc_result);
				return CERTSVC_FAIL;
			}

		} else {
			result = del_file_from_system_cert_dir(pGname);
			if (result != CERTSVC_SUCCESS) {
				SLOGE("Error in del_file_from_system_cert_dir. ret[%d]", result);
				return result;
			}
		}
	} else { /* moving the certificate to enabled state */
		query = sqlite3_mprintf("select certificate from disabled_certs where gname=%Q", pGname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(db_handle, query, &stmt);
		sqlite3_free(query);

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			return CERTSVC_FAIL;
		}

		records = sqlite3_step(stmt);
		if (records == SQLITE_ROW) {
			text = (const char *)sqlite3_column_text(stmt, 0);

			if (!text) {
				SLOGE("Invalid column text");
				sqlite3_finalize(stmt);
				return CERTSVC_FAIL;
			}

			certBuffer = strndup(text, strlen(text));

			sqlite3_finalize(stmt);

			if (!certBuffer) {
				SLOGE("Failed to allocate memory");
				return CERTSVC_BAD_ALLOC;
			}

			certLength = strlen(certBuffer);

			if (storeType == SYSTEM_STORE)
				result = saveCertificateToSystemStore(pGname, certBuffer, certLength);
			else
				result = saveCertificateToStore(pGname, certBuffer, certLength);

			free(certBuffer);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Failed to save certificate to key-manager. ret[%d]", result);
				return result;
			}

			query = sqlite3_mprintf("delete from disabled_certs where gname=%Q", pGname);
			if (!query) {
				SLOGE("Failed to generate query");
				return CERTSVC_BAD_ALLOC;
			}

			result = execute_insert_update_query(db_handle, query);
			sqlite3_free(query);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Unable to delete certificate entry from database. ret[%d]", result);
				return result;
			}
		}
	}

	if (is_root_app == ENABLED)
		query = sqlite3_mprintf("update %Q set is_root_app_enabled=%d , enabled=%d where gname=%Q", ((storeType == WIFI_STORE)? "wifi" : \
							   (storeType == VPN_STORE)? "vpn" : (storeType == EMAIL_STORE)? "email" : "ssl"), CertStatus_to_int(status), status, pGname);
	else
		query = sqlite3_mprintf("update %Q set enabled=%d where gname=%Q", ((storeType == WIFI_STORE)? "wifi" : \
							   (storeType == VPN_STORE)? "vpn" : (storeType == EMAIL_STORE)? "email" : "ssl"), CertStatus_to_int(status), pGname);

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_insert_update_query(db_handle, query);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Update failed. ret[%d]", result);
		return result;
	}

	return result;
}

int setCertificateStatusToStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	int is_root_app,
	const char *pGname,
	CertStatus status)
{
	if (!pGname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	int result = enable_disable_cert_status(db_handle, storeType, is_root_app, pGname, status);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to disable certificate.");
		return result;
	}

	SLOGD("Successfully updated the certificate status from %s to %s.",
		(status == DISABLED) ? "ENABLED" : "DISABLED", (status == DISABLED) ? "DISABLED" : "ENABLED");
	return CERTSVC_SUCCESS;
}

int getCertificateStatusFromStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char* pGname,
	CertStatus *status)
{
	if (!pGname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	char *query = sqlite3_mprintf("select gname, common_name, enabled from %Q where gname=%Q",\
						   ((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : \
						   (storeType == EMAIL_STORE)? "email" : "ssl"), pGname);
	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	sqlite3_stmt *stmt = NULL;
	int result = execute_select_query(db_handle, query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS || !stmt) {
		SLOGE("Querying database failed.");
		*status = DISABLED;
		return CERTSVC_FAIL;
	}

	result = sqlite3_step(stmt);
	if (result != SQLITE_ROW || result == SQLITE_DONE) {
		SLOGE("No valid records found.");
		*status = DISABLED;
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	*status = int_to_CertStatus(sqlite3_column_int(stmt, 2));

	sqlite3_finalize(stmt);

	return CERTSVC_SUCCESS;
}

int check_alias_exist_in_database(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char *alias,
	int *isUnique)
{
	sqlite3_stmt *stmt = NULL;

	if (!alias || !isUnique) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	char *query = sqlite3_mprintf("select * from %Q where common_name=%Q", ((storeType == WIFI_STORE)? "wifi" : \
						   (storeType == VPN_STORE)? "vpn" : "email"),alias);

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	int result = execute_select_query(db_handle, query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS || !stmt) {
		SLOGE("Querying database failed.");
		return CERTSVC_FAIL;
	}

	result = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (result != SQLITE_ROW)
		*isUnique = CERTSVC_TRUE;
	else
		*isUnique = CERTSVC_FALSE;

	return CERTSVC_SUCCESS;
}

int installCertificateToStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char *pGname,
	const char *common_name,
	const char *private_key_gname,
	const char *associated_gname,
	const char *dataBlock,
	size_t dataBlockLen,
	CertType certType)
{
	if ((!pGname)
		|| (certType == P12_END_USER && !common_name && !private_key_gname)
		|| (certType != P12_END_USER && !common_name && !associated_gname)) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (storeType != SYSTEM_STORE
		&& saveCertificateToStore(
			pGname,
			dataBlock,
			dataBlockLen) != CERTSVC_SUCCESS) {
		SLOGE("FAIL to save certificate to key-manager.");
		return CERTSVC_FAIL;
	}

	if (certType == P12_PKEY) {
		SLOGD("Don't save private key in store");
		return CERTSVC_SUCCESS;
	}

	char *query = NULL;
	if (certType == P12_END_USER && private_key_gname) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, private_key_gname, associated_gname, enabled, is_root_app_enabled) "\
								"values (%Q, %Q, %Q, %Q, %d, %d)",((storeType == WIFI_STORE)? "wifi" : \
								(storeType == VPN_STORE)? "vpn" : "email"), pGname, common_name, private_key_gname, pGname, ENABLED, ENABLED);
	} else if (certType == PEM_CRT || certType == P12_TRUSTED) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, is_root_cert, associated_gname, enabled, is_root_app_enabled) values "\
								"(%Q, %Q, %d, %Q, %d, %d)", ((storeType == WIFI_STORE)? "wifi" : \
								(storeType == VPN_STORE)? "vpn" : "email"), pGname, common_name, ENABLED, associated_gname, ENABLED, ENABLED);
	} else if (certType == P12_INTERMEDIATE) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, associated_gname, enabled, is_root_app_enabled) values (%Q, %Q, %Q, %d, %d)", \
								((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : "email"),
								pGname, common_name, associated_gname, ENABLED, ENABLED);
	}

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	int result = execute_insert_update_query(db_handle, query);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Insert to database failed.");
		return CERTSVC_FAIL;
	}

	return CERTSVC_SUCCESS;
}

int checkAliasExistsInStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char* alias,
	int *isUnique)
{
	if (!alias) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	*isUnique = CERTSVC_FAIL;
	int result = check_alias_exist_in_database(db_handle, storeType, alias, isUnique);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to check_alias_exist_in_database. err[%d]", result);
		return CERTSVC_FAIL;
	}

	if (*isUnique == CERTSVC_TRUE) {
		SLOGD("Alias (%s) does not exist in %s store.",
			alias,
			(storeType == VPN_STORE) ? "VPN" :
				(storeType == WIFI_STORE) ? "WIFI" : "EMAIL");
	} else {
		SLOGD("Alias (%s) exist in %s store.",
			alias,
			(storeType == VPN_STORE) ? "VPN" :
				(storeType == WIFI_STORE) ? "WIFI" : "EMAIL");
	}

	return CERTSVC_SUCCESS;
}

int getCertificateDetailFromStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	CertType certType,
	const char *pGname,
	char *pOutData,
	size_t *size)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;
	ckmc_raw_buffer_s *cert_data = NULL;

	if (!pGname || !pOutData) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	/* start constructing query */
	if (certType == P12_PKEY) {
		/* From the given certificate identifier, get the associated_gname for the certificate.
		 * Then query the database for records matching the associated_gname to get the private key */
		query = sqlite3_mprintf("select associated_gname from %Q where gname=%Q", \
							   ((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : "email"), pGname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(db_handle, query, &stmt);
		sqlite3_free(query);

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			return result;
		}

		records = sqlite3_step(stmt);
		if (records != SQLITE_ROW) {
			SLOGE("No valid records found.");
			sqlite3_finalize(stmt);
			return CERTSVC_FAIL;
		}

		text = (const char *)sqlite3_column_text(stmt, 0);

		if (!text) {
			SLOGE("No valid column text");
			sqlite3_finalize(stmt);
			return CERTSVC_FAIL;
		}

		query = sqlite3_mprintf("select private_key_gname from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d", \
					 ((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : "email"), text, ENABLED, ENABLED);

		sqlite3_finalize(stmt);
	} else if (storeType != SYSTEM_STORE) {
		query = sqlite3_mprintf("select * from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d", \
							   ((storeType == WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : \
							   (storeType == EMAIL_STORE)? "email" : "ssl"), pGname, ENABLED, ENABLED);
	}

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_select_query(db_handle, query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		return result;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW) {
		SLOGE("No valid records found.");
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	if (certType == P12_PKEY) {
		if (!(text = (const char *)sqlite3_column_text(stmt, 0))) {
			SLOGE("No valid column text");
			sqlite3_finalize(stmt);
			return CERTSVC_FAIL;
		}

		pGname = text;
	}

	char *ckm_alias = add_shared_owner_prefix(pGname);
	if (!ckm_alias) {
		SLOGE("Failed to make alias. memory allocation error.");
		return CERTSVC_BAD_ALLOC;
	}

	result = ckmc_get_data(ckm_alias, NULL, &cert_data);
	free(ckm_alias);

	sqlite3_finalize(stmt);

	if (result != CKMC_ERROR_NONE) {
		SLOGE("Failed to get certificate from key-manager. ckm ret[%d]", result);
		*size = CERTSVC_FAIL;
		return CERTSVC_FAIL;
	}

	memcpy(pOutData, cert_data->data, cert_data->size);
	pOutData[cert_data->size] = 0;
	*size = cert_data->size;

	ckmc_buffer_free(cert_data);

	return CERTSVC_SUCCESS;
}

int getCertificateDetailFromSystemStore(
	sqlite3 *db_handle,
	const char *pGname,
	char *pOutData,
	size_t *size)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	size_t certLength = 0;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!pGname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	query = sqlite3_mprintf("select certificate from ssl where gname=%Q and is_root_app_enabled=%d", \
							pGname, ENABLED, ENABLED);
	if (!query) {
		SLOGE("Query is NULL.");
		return CERTSVC_FAIL;
	}

	result = execute_select_query(db_handle, query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		return result;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW) {
		SLOGE("No valid records found for passed gname [%s].", pGname);
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	text = (const char *)sqlite3_column_text(stmt, 0);

	if (!text) {
		SLOGE("Fail to sqlite3_column_text");
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	certLength = strlen(text);
	if (certLength >= 4096) {
		sqlite3_finalize(stmt);
		SLOGE("certificate is too long");
		return CERTSVC_FAIL;
	}

	memcpy(pOutData, text, certLength);
	pOutData[certLength] = 0;
	*size = certLength;

	sqlite3_finalize(stmt);
	return CERTSVC_SUCCESS;
}

int deleteCertificateFromStore(sqlite3 *db_handle, CertStoreType storeType, const char *pGname) {

	int result = CERTSVC_SUCCESS;
	int ckmc_result = CKMC_ERROR_UNKNOWN;
	int records = 0;
	char *query = NULL;
	char *private_key_name = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!pGname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (storeType != SYSTEM_STORE) {
		/* start constructing query */
		query = sqlite3_mprintf("select private_key_gname from %Q where gname=%Q", ((storeType == WIFI_STORE)? "wifi" :\
							   (storeType == VPN_STORE)? "vpn" : "email"), pGname);

		result = execute_select_query(db_handle, query, &stmt);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			result = CERTSVC_FAIL;
			goto error;
		}

		records = sqlite3_step(stmt);
		if ((records != SQLITE_ROW) || (records == SQLITE_DONE)) {
			SLOGE("No valid records found for passed gname [%s].",pGname);
			result = CERTSVC_FAIL;
			goto error;
		}

		/* if a cert is having private-key in it, the private key should
		 * be deleted first from key-manager, then the actual cert */
		if (sqlite3_column_text(stmt, 0) != NULL) {
			private_key_name = strdup((const char *)sqlite3_column_text(stmt, 0));
			result = ckmc_remove_alias_with_shared_owner_prefix(private_key_name, &ckmc_result);
			if (result != CERTSVC_SUCCESS || ckmc_result != CKMC_ERROR_NONE) {
				SLOGE("Failed to delete certificate from key-manager. ckmc_result[%d]", ckmc_result);
				result = CERTSVC_FAIL;
				goto error;
			}
		}

		/* removing the actual cert */
		result = ckmc_remove_alias_with_shared_owner_prefix(pGname, &ckmc_result);
		if (result != CERTSVC_SUCCESS || ckmc_result != CKMC_ERROR_NONE) {
			query = sqlite3_mprintf("delete from disabled_certs where gname=%Q", pGname);
			result = execute_insert_update_query(db_handle, query);
			if (result != CERTSVC_SUCCESS) {
				SLOGE("Unable to delete certificate entry from database.");
				result = CERTSVC_FAIL;
				goto error;
			}
		}

		if (query) {
			sqlite3_free(query);
			query = NULL;
		}

		if (stmt) {
			sqlite3_finalize(stmt);
			stmt = NULL;
		}

		query = sqlite3_mprintf("delete from %Q where gname=%Q", ((storeType == WIFI_STORE)? "wifi" : \
							   (storeType == VPN_STORE)? "vpn" : "email"), pGname);

		result = execute_insert_update_query(db_handle, query);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Unable to delete certificate entry from database.");
			result = CERTSVC_FAIL;
			goto error;
		}
	} else {
		SLOGE("Invalid store type passed.");
		result = CERTSVC_INVALID_STORE_TYPE;
	}
	SLOGD("Success in deleting the certificate from store.");

error:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	free(private_key_name);
	return result;
}


int getCertificateListFromStore(
	sqlite3 *db_handle,
	int reqType,
	CertStoreType storeType,
	int is_root_app,
	char **certListBuffer,
	size_t *bufferLen,
	size_t *certCount)
{
	int result = CERTSVC_SUCCESS;
	CertSvcStoreCertList *rootCertHead = NULL;
	CertSvcStoreCertList *tmpNode = NULL;
	CertSvcStoreCertList *currentNode = NULL;
	sqlite3_stmt *stmt = NULL;
	char *query = NULL;
	int loopCount = 0;
	int records = 0;
	size_t count = 0;
	size_t i = 0;


	while (1) {
		/* Iteration only possible from VPN_STORE till SYSTEM_STORE */
		if (loopCount == (MAX_STORE_ENUMS - 1))
			break;

		/* Check if the passed store type matches with any of the in-built store type */
		if ((1 << loopCount) & storeType) {
			/* if a store type matches, put that value as storetype argument in the below function */
			CertStoreType tempStore = (CertStoreType) (1 << loopCount);
			SLOGD("Processing storetype [%s]", (tempStore == WIFI_STORE)? "WIFI" : (tempStore == VPN_STORE)? "VPN" : \
											  (tempStore == EMAIL_STORE)? "EMAIL" : "SYSTEM");

			if (reqType == CERTSVC_GET_ROOT_CERTIFICATE_LIST) {
			// For get_root_certificate_list_from_store
				if (storeType == SYSTEM_STORE) {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q where enabled=%d "\
											"and is_root_app_enabled=%d and order by common_name asc", "ssl", ENABLED, ENABLED);
				} else {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
											"is_root_cert IS NOT NULL and is_root_app_enabled=%d and enabled=%d", \
											(storeType== WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : \
											(storeType == EMAIL_STORE)? "email" : "ssl", ENABLED, ENABLED);
				}
			} else if (reqType == CERTSVC_GET_USER_CERTIFICATE_LIST) {
			// For get_end_user_certificate_list_from_store
				if (storeType == SYSTEM_STORE) {
					SLOGE("Invalid store type passed.");
					return CERTSVC_WRONG_ARGUMENT;
				} else {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
											 "private_key_gname IS NOT NULL and is_root_app_enabled=%d and enabled=%d", \
										   (storeType== WIFI_STORE)? "wifi" : (storeType == VPN_STORE)? "vpn" : \
										   (storeType == EMAIL_STORE)? "email" : "ssl", ENABLED, ENABLED);
				}
			} else {
			// For get_certificate_list_from_store
				if (is_root_app != ENABLED) {
				/* Gets only the list of certificates where is_root_app = 1 (which are enabled by the master application) */
					if (tempStore == SYSTEM_STORE) {
						query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
												"is_root_app_enabled=%d order by common_name asc", \
												(tempStore== WIFI_STORE)? "wifi" : (tempStore == VPN_STORE)? "vpn" : \
												(tempStore == EMAIL_STORE)? "email" : "ssl", ENABLED, ENABLED);
					} else {
						query = sqlite3_mprintf("select gname, common_name, enabled from %Q where is_root_app_enabled=%d", \
											   (tempStore== WIFI_STORE)? "wifi" : (tempStore == VPN_STORE)? "vpn" : \
											   (tempStore == EMAIL_STORE)? "email" : "ssl", ENABLED, ENABLED);
					}
				} else {
				/* Gets all the certificates from store without any restrictions */
					if (tempStore == SYSTEM_STORE) {
						query = sqlite3_mprintf("select gname, common_name, enabled from %Q order by common_name asc", \
											   (tempStore== WIFI_STORE)? "wifi" : (tempStore == VPN_STORE)? "vpn" : \
											   (tempStore == EMAIL_STORE)? "email" : "ssl", ENABLED);
					} else {
						query = sqlite3_mprintf("select gname, common_name, enabled from %Q", \
											   (tempStore== WIFI_STORE)? "wifi" : (tempStore == VPN_STORE)? "vpn" : \
											   (tempStore == EMAIL_STORE)? "email" : "ssl", ENABLED);
					}
				}
			}

			result = execute_select_query(db_handle, query, &stmt);
			if (result != CERTSVC_SUCCESS) {
				SLOGE("Querying database failed.");
				result = CERTSVC_FAIL;
				goto error;
			}

			while (1) {
				records = sqlite3_step(stmt);
				if (records != SQLITE_ROW || records == SQLITE_DONE) {
					if (count == 0) {
						SLOGE("No records found");
						result = CERTSVC_SUCCESS;
						goto error;
					} else {
						break;
					}
				}

				if (records == SQLITE_ROW) {
					tmpNode = (CertSvcStoreCertList *)malloc(sizeof(CertSvcStoreCertList));
					if (!tmpNode) {
						SLOGE("Failed to allocate memory.");
						result = CERTSVC_BAD_ALLOC;
						goto error;
					} else {
						tmpNode->next = NULL;
						const char *textGname = (const char *)sqlite3_column_text(stmt, 0);
						const char *textAlias = (const char *)sqlite3_column_text(stmt, 1);
						if (!textGname || !textAlias) {
							SLOGE("Failed to read texts from records");
							free(tmpNode);
							result = CERTSVC_FAIL;
							goto error;
						}

						int gnameLen = strlen(textGname);
						int aliasLen = strlen(textAlias);

						tmpNode->gname = (char *)malloc(sizeof(char) * (gnameLen + 1));
						tmpNode->title = (char *)malloc(sizeof(char) * (aliasLen + 1));
						if (!tmpNode->title || !tmpNode->gname) {
							free(tmpNode->gname);
							free(tmpNode->title);
							free(tmpNode);
							SLOGE("Failed to allocate memory");
							result = CERTSVC_BAD_ALLOC;
							goto error;
						}

						memset(tmpNode->gname, 0x00, gnameLen + 1);
						memset(tmpNode->title, 0x00, aliasLen + 1);

						memcpy(tmpNode->gname, textGname, gnameLen);
						memcpy(tmpNode->title, textAlias, aliasLen);

						tmpNode->status = (int)sqlite3_column_int(stmt, 2); /* for status */
						tmpNode->storeType = tempStore;
					}

					/* When multiple stores are passed, we need to ensure that the rootcerthead is
					   assigned to currentNode once, else previous store data gets overwritten */
					if (count == 0) {
						rootCertHead = tmpNode;
						currentNode = rootCertHead;
						tmpNode = NULL;
					} else {
						currentNode->next = tmpNode;
						currentNode = tmpNode;
						tmpNode = NULL;
					}
					count++;
				}
			}

			if (count == 0) {
				SLOGD("No entries found in database.");
				result = CERTSVC_SUCCESS;
			}

			if (query) {
				sqlite3_free(query);
				query = NULL;
			}

			if (stmt) {
				sqlite3_finalize(stmt);
				stmt = NULL;
			}
		}
		loopCount++;
	}

	*certCount = count;
	VcoreCertResponseData *respCertData = (VcoreCertResponseData *)malloc(count * sizeof(VcoreCertResponseData));
	if (!respCertData) {
		SLOGE("Failed to allocate memory");
		result = CERTSVC_BAD_ALLOC;
		goto error;
	}
	if (count > 0)
		memset(respCertData, 0x00, count * sizeof(VcoreCertResponseData));
	VcoreCertResponseData* currRespCertData = NULL;

	currentNode = rootCertHead;
	for (i = 0; i < count; i++) {
	   tmpNode = currentNode->next;

	   currRespCertData = respCertData + i;
	   if (strlen(currentNode->gname) > sizeof(currRespCertData->gname)
		   || strlen(currentNode->title) > sizeof(currRespCertData->title)) {
		   SLOGE("String is too long. [%s], [%s]", currentNode->gname, currentNode->title);
		   result = CERTSVC_FAIL;
		   *certListBuffer = NULL;
		   free(respCertData);
		   goto error;
	   }
	   strncpy(currRespCertData->gname, currentNode->gname, strlen(currentNode->gname));
	   strncpy(currRespCertData->title, currentNode->title, strlen(currentNode->title));
	   currRespCertData->status = currentNode->status;
	   currRespCertData->storeType = currentNode->storeType;
	   //SLOGD("get cert list: %d th cert: gname=%s, title=%s, status=%d, storeType=%d", i, currRespCertData->gname, currRespCertData->title, currRespCertData->status, currRespCertData->storeType);

	   currentNode = tmpNode;
	}

	*certListBuffer = (char *) respCertData;
	*bufferLen = count * sizeof(VcoreCertResponseData);

	SLOGD("Success to create certificate list. cert_count=%d", count);
	result= CERTSVC_SUCCESS;
error:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	if (rootCertHead) {
		currentNode = rootCertHead;
		while (currentNode) {
			tmpNode = currentNode->next;
			free(currentNode->title);
			free(currentNode->gname);
			free(currentNode);
			currentNode=tmpNode;
		}
		rootCertHead = NULL;
	}

	return result;
}

int getCertificateAliasFromStore(sqlite3 *db_handle, CertStoreType storeType, const char *gname, char *alias)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	sqlite3_stmt *stmt = NULL;
	char *query = NULL;
	const char *text = NULL;

	query = sqlite3_mprintf("select common_name from %Q where gname=%Q", ((storeType==WIFI_STORE)? "wifi" : \
						   (storeType==VPN_STORE)? "vpn" : "email"), gname);

	result = execute_select_query(db_handle, query, &stmt);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW || records == SQLITE_DONE) {
		SLOGE("No valid records found for gname passed [%s].",gname);
		result = CERTSVC_FAIL;
		goto error;
	}

	if (!(text = (const char *)sqlite3_column_text(stmt, 0))) {
		SLOGE("No column text in returned records");
		result = CERTSVC_FAIL;
		goto error;
	}

	strncpy(alias, text, strlen(text));

	if (strlen(alias) == 0) {
		SLOGE("Unable to get the alias name for the gname passed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	result = CERTSVC_SUCCESS;

	SLOGD("success : getCertificateAliasFromStore");
error:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	return result;
}

int loadCertificatesFromStore(
	sqlite3 *db_handle,
	CertStoreType storeType,
	const char* gname,
	char **ppCertBlockBuffer,
	size_t *bufferLen,
	size_t *certBlockCount)
{
	int result = CERTSVC_SUCCESS;
	size_t count = 0;
	int records = 0;
	sqlite3_stmt *stmt = NULL;
	char *query = NULL;
	char **certs = NULL;
	const char *tmpText = NULL;
	size_t i = 0;

	query = sqlite3_mprintf("select associated_gname from %Q where gname=%Q", ((storeType==WIFI_STORE)? "wifi" : \
						   (storeType==VPN_STORE)? "vpn" : "email"), gname);

	result = execute_select_query(db_handle, query, &stmt);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW || records == SQLITE_DONE) {
		SLOGE("No valid records found for gname passed [%s].",gname);
		result = CERTSVC_FAIL;
		goto error;
	}


	if (records == SQLITE_ROW) {
		if (query)
			sqlite3_free(query);

		const char *columnText = (const char *)sqlite3_column_text(stmt, 0);
		if (!columnText) {
			SLOGE("Failed to sqlite3_column_text");
			result = CERTSVC_FAIL;
			goto error;
		}

		query = sqlite3_mprintf("select gname from %Q where associated_gname=%Q and enabled=%d and is_root_app_enabled=%d", \
							   ((storeType==WIFI_STORE)? "wifi" : (storeType==VPN_STORE)? "vpn" : "email"), \
							   columnText, ENABLED, ENABLED);

		if (stmt)
			sqlite3_finalize(stmt);

		result = execute_select_query(db_handle, query, &stmt);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			result = CERTSVC_FAIL;
			goto error;
		}

		while (1) {
			records = sqlite3_step(stmt);
			if (records != SQLITE_ROW || records == SQLITE_DONE)
				break;

			if (count == 0) {
				certs = (char**) malloc(4 * sizeof(char *));
				if (!certs) {
					SLOGE("Failed to allocate memory");
					result = CERTSVC_BAD_ALLOC;
					goto error;
				}
				memset(certs, 0x00, 4 * sizeof(char *));
			}

			if (records == SQLITE_ROW) {
				tmpText = (const char *)sqlite3_column_text(stmt, 0);
				if (!tmpText) {
					SLOGE("Failed to sqlite3_column_text.");
					result = CERTSVC_FAIL;
					goto error;
				}

				if (!((certs)[count] = strdup(tmpText))) {
					SLOGE("Failed to allocate memory");
					result = CERTSVC_BAD_ALLOC;
					goto error;
				}
			}

			count++;
		}

		if (count == 0) {
			SLOGE("No valid records found for the gname passed [%s].",gname);
			return CERTSVC_FAIL;
		}
	}

	*certBlockCount = count;
	*bufferLen = count * sizeof(ResponseCertBlock);
	ResponseCertBlock *certBlockList = (ResponseCertBlock *) malloc(*bufferLen);
	if (!certBlockList) {
		SLOGE("Failed to allocate memory for ResponseCertBlock");
		result = CERTSVC_BAD_ALLOC;
		goto error;
	}

	if (count > 0)
		memset(certBlockList, 0x00, *bufferLen);

	ResponseCertBlock *currentBlock = NULL;
	for (i = 0; i < count; i++) {
		currentBlock = certBlockList + i;
		if (sizeof(currentBlock->dataBlock) < strlen(certs[i])) {
			SLOGE("src is longer than dst. src[%s] dst size[%d]", certs[i], sizeof(currentBlock->dataBlock));
			free(certBlockList);
			result = CERTSVC_FAIL;
			goto error;
		}
		strncpy(currentBlock->dataBlock, certs[i], strlen(certs[i]));
		currentBlock->dataBlockLen = strlen(certs[i]);
	}
	*ppCertBlockBuffer = (char *)certBlockList;

	result = CERTSVC_SUCCESS;

	SLOGD("success: loadCertificatesFromStore. CERT_COUNT=%d", count);

error:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	if (certs) {
		for(i = 0; i < count; i++)
			free(certs[i]);

		free(certs);
	}

	return result;
}
