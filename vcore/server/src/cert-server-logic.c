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
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <sys/smack.h>
#include <sys/socket.h>

#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>

#include <cert-svc/cerror.h>
#include <cert-svc/ccert.h>
#include <vcore/Client.h>

#include <cert-server-debug.h>
#include <cert-server-logic.h>
#include <cert-server-db.h>

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

static const char *storetype_to_string(CertStoreType type)
{
	switch (type) {
	case VPN_STORE:    return "vpn";
	case EMAIL_STORE:  return "email";
	case WIFI_STORE:   return "wifi";
	case SYSTEM_STORE: return "ssl";
	default:           return NULL;
	}
}

static CertStoreType nextStore(CertStoreType type)
{
	switch (type) {
	case NONE_STORE:   return VPN_STORE;
	case VPN_STORE:    return WIFI_STORE;
	case WIFI_STORE:   return EMAIL_STORE;
	case EMAIL_STORE:  return SYSTEM_STORE;
	case SYSTEM_STORE: return NONE_STORE;
	default:           return NONE_STORE;
	}
}

static bool hasStore(CertStoreType types, CertStoreType type)
{
	return (types & type) != 0 ? true : false;
}

char *add_shared_owner_prefix(const char *name)
{
	char *ckm_alias = NULL;
	int result = asprintf(&ckm_alias, "%s%s%s", ckmc_owner_id_system, ckmc_owner_id_separator, name);
	if (result < 0 || ckm_alias == NULL) {
		SLOGE("Failed to allocate memory");
		return NULL;
	}

	return ckm_alias;
}

int ckmc_remove_alias_with_shared_owner_prefix(const char *name)
{
	char *ckm_alias = add_shared_owner_prefix(name);
	if (!ckm_alias) {
		SLOGE("Failed to allocate memory");
		return CKMC_ERROR_OUT_OF_MEMORY;
	}

	int result = ckmc_remove_alias(ckm_alias);

	free(ckm_alias);

	return result;
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

	if (as_result < 0)
		return NULL;

	return result;
}

int add_file_to_system_cert_dir(const char *gname)
{
	int ret = CERTSVC_SUCCESS;

	/* find certificate which filehash name is gname in root ca certs path. */
	char *target = get_complete_path(ROOT_CA_CERTS_DIR, gname);
	char *link = get_complete_path(SYSTEM_CERT_DIR, gname);

	if (target == NULL || link == NULL) {
		SLOGE("Failed to get complete path.");
		ret = CERTSVC_BAD_ALLOC;
		goto out;
	}

	if (symlink(target, link) != 0) {
		SLOGE("Failed to make symlink from[%s] to[%s]", target, link);
		ret = CERTSVC_FAIL;
		goto out;
	}

out:

	free(target);
	free(link);

	return ret;
}

int del_file_from_system_cert_dir(const char *gname)
{
	int ret = CERTSVC_SUCCESS;
	char *link = NULL;

	link = get_complete_path(SYSTEM_CERT_DIR, gname);
	if (!link)   {
		SLOGE("Failed to construct source file path.");
		return CERTSVC_FAIL;
	}

	if (unlink(link) != 0) {
		SLOGE("unlink %s failed. errno : %d", link, errno);
		ret = CERTSVC_FAIL;
		goto out;
	}

out:

	free(link);

	return ret;
}

int write_to_ca_cert_crt_file(const char *mode, const char *cert)
{
	int result = CERTSVC_SUCCESS;
	FILE *fp = NULL;

	if (cert == NULL || strlen(cert) == 0) {
		SLOGE("Input buffer is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (!(fp = fopen(CERTSVC_CRT_FILE_PATH, mode))) {
		SLOGE("Failed to open the file for writing, [%s].", CERTSVC_CRT_FILE_PATH);
		return CERTSVC_FAIL;
	}

	/* if mode of writing is to append, then goto end of file */
	if (strcmp(mode,"ab") == 0)
		fseek(fp, 0L, SEEK_END);

	size_t cert_len = strlen(cert);
	if (fwrite(cert, sizeof(char), cert_len, fp) != cert_len) {
		SLOGE("Fail to write into file.");
		result = CERTSVC_FAIL;
		goto error;
	}

	/* adding empty line at the end */
	fwrite("\n", sizeof(char), 1, fp);

error:
	if (fp)
		fclose(fp);

	return result;
}

int saveCertificateToStore(const char *gname, const char *cert)
{
	if (!gname || !cert) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	ckmc_policy_s cert_policy;
	cert_policy.password = NULL;
	cert_policy.extractable = true;

	ckmc_raw_buffer_s cert_data;
	cert_data.data = (unsigned char *)cert;
	cert_data.size = strlen(cert);

	char *ckm_alias = add_shared_owner_prefix(gname);
	if (!ckm_alias) {
		SLOGE("Failed to make alias. memory allocation error.");
		return CERTSVC_BAD_ALLOC;
	}

	int result = ckmc_save_data(ckm_alias, cert_data, cert_policy);
	free(ckm_alias);

	if (result == CKMC_ERROR_DB_ALIAS_EXISTS) {
		SLOGI("same alias with gname[%s] alrady exist in ckm. Maybe other store type have it. skip.", gname);
		return CERTSVC_SUCCESS;
	}

	if (result != CKMC_ERROR_NONE) {
		SLOGE("Failed to save trusted data. ckm errcode[%d]", result);
		return CERTSVC_FAIL;
	}

	return CERTSVC_SUCCESS;
}

int saveCertificateToSystemStore(const char *gname)
{
	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	int result = add_file_to_system_cert_dir(gname);
	if (result != CERTSVC_SUCCESS)
		SLOGE("Failed to store the certificate in store.");

	return result;
}

int get_certificate_buffer_from_store(CertStoreType storeType, const char *gname, char **pcert)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *tempBuffer = NULL;
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (storeType != SYSTEM_STORE)
		query = sqlite3_mprintf("select * from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d",
				storetype_to_string(storeType), gname, ENABLED, ENABLED);
	else
		query = sqlite3_mprintf("select certificate from ssl where gname=%Q and enabled=%d and is_root_app_enabled=%d",
				gname, ENABLED, ENABLED);

	result = execute_select_query(query, &stmt);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW || records == SQLITE_DONE) {
		SLOGE("No valid records found for given gname [%s].",gname);
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
		result = getCertificateDetailFromSystemStore(gname, tempBuffer);
	else
		result = getCertificateDetailFromStore(storeType, PEM_CRT, gname, tempBuffer);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to set request data.");
		result = CERTSVC_WRONG_ARGUMENT;
		goto error;
	}

	*pcert = tempBuffer;

error:
	if (result != CERTSVC_SUCCESS)
		free(tempBuffer);

	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	return result;
}

int update_ca_certificate_file(char *cert)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	int counter = 0;
	char *gname = NULL;
	char *query = NULL;
	const char *text;
	sqlite3_stmt *stmt = NULL;
	CertStoreType storeType;

	/*
	 * During install of a root certificate, the root certificate gets appended at
	 * the end to optimise the write operation onto ca-certificate.crt file.
	 */
	if (cert != NULL && strlen(cert) > 0) {
		result = write_to_ca_cert_crt_file("ab", cert);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Failed to write to file. result[%d]", result);
			return result;
		}

		return CERTSVC_SUCCESS;
	}

	for (storeType = VPN_STORE; storeType != NONE_STORE; storeType = nextStore(storeType)) {
		if (storeType == SYSTEM_STORE)
			query = sqlite3_mprintf("select certificate from ssl where enabled=%d and is_root_app_enabled=%d", ENABLED, ENABLED);
		else
			query = sqlite3_mprintf("select gname from %Q where is_root_cert=%d and enabled=%d and is_root_app_enabled=%d",
					storetype_to_string(storeType), ENABLED, ENABLED, ENABLED);

		result = execute_select_query(query, &stmt);
		if (query) {
			sqlite3_free(query);
			query = NULL;
		}

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			goto error_and_exit;
		}

		/* update the ca-certificate.crt file */
		while (1) {
			records = sqlite3_step(stmt);
			if (records == SQLITE_DONE) {
				result = CERTSVC_SUCCESS;
				break;
			}

			if (records != SQLITE_ROW) {
				SLOGE("DB query error when select. result[%d].", records);
				result = CERTSVC_FAIL;
				goto error_and_exit;
			}

			cert = NULL;
			gname = NULL;

			if (storeType == SYSTEM_STORE) {
				text = (const char *)sqlite3_column_text(stmt, 0);
				if (text)
					cert = strndup(text, strlen(text));
			} else {
				text = (const char *)sqlite3_column_text(stmt, 0);
				if (text)
					gname = strndup(text, strlen(text));

				result = get_certificate_buffer_from_store(storeType, gname, &cert);
				if (result != CERTSVC_SUCCESS) {
					SLOGE("Failed to get certificate buffer from key-manager. gname[%s]", gname);
					goto error_and_exit;
				}
			}

			if (cert == NULL) {
				SLOGE("Failed to extract cert buffer to update ca-certificate.");
				result = CERTSVC_FAIL;
				goto error_and_exit;
			}

			if (counter++ == 0)
				result = write_to_ca_cert_crt_file("wb", cert);
			else
				result = write_to_ca_cert_crt_file("ab", cert);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Failed to write to file.");
				result = CERTSVC_FAIL;
				goto error_and_exit;
			}
		}
	}

	SLOGD("Successfully updated ca-certificate.crt file. added cert num[%d]", counter);

error_and_exit:
	if (stmt)
		sqlite3_finalize(stmt);

	return result;
}

int enable_disable_cert_status(
	CertStoreType storeType,
	int is_root_app,
	const char *gname,
	CertStatus status)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *cert = NULL;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;

	if (status != DISABLED && status != ENABLED) {
		SLOGE("Invalid cert status");
		return CERTSVC_INVALID_STATUS;
	}

	query = sqlite3_mprintf("select * from %Q where gname=%Q", storetype_to_string(storeType), gname);
	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_select_query(query, &stmt);
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
		query = sqlite3_mprintf("select * from disabled_certs where gname=%Q", gname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(query, &stmt);
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
			SLOGE("Selected certificate identifier is already disabled.", gname);
			return CERTSVC_FAIL;
		}

		/* get certificate from keymanager*/
		result = get_certificate_buffer_from_store(storeType, gname, &cert);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Failed to get certificate buffer. result[%d]", result);
			return result;
		}

		/* inserting the disabled certificate to disabled_certs table */
		query = sqlite3_mprintf("insert into disabled_certs (gname, certificate) values (%Q, %Q)", gname, cert);
		free(cert);

		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_insert_update_query(query);
		sqlite3_free(query);

		if (result != CERTSVC_SUCCESS) {
			SLOGE("Insert to database failed.");
			return result;
		}

		if (storeType != SYSTEM_STORE) {
			result = ckmc_remove_alias_with_shared_owner_prefix(gname);

			if (result != CKMC_ERROR_NONE) {
				SLOGE("Failed to delete certificate from key-manager. ckmc_result[%d]", result);
				return CERTSVC_FAIL;
			}

		} else {
			result = del_file_from_system_cert_dir(gname);
			if (result != CERTSVC_SUCCESS) {
				SLOGE("Error in del_file_from_system_cert_dir. ret[%d]", result);
				return result;
			}
		}
	} else { /* moving the certificate to enabled state */
		query = sqlite3_mprintf("select certificate from disabled_certs where gname=%Q", gname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(query, &stmt);
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

			cert = strndup(text, strlen(text));

			sqlite3_finalize(stmt);

			if (!cert) {
				SLOGE("Failed to allocate memory");
				return CERTSVC_BAD_ALLOC;
			}

			if (storeType == SYSTEM_STORE)
				result = saveCertificateToSystemStore(gname);
			else
				result = saveCertificateToStore(gname, cert);

			free(cert);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Failed to save certificate to key-manager. ret[%d]", result);
				return result;
			}

			query = sqlite3_mprintf("delete from disabled_certs where gname=%Q", gname);
			if (!query) {
				SLOGE("Failed to generate query");
				return CERTSVC_BAD_ALLOC;
			}

			result = execute_insert_update_query(query);
			sqlite3_free(query);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Unable to delete certificate entry from database. ret[%d]", result);
				return result;
			}
		}
	}

	if (is_root_app == ENABLED)
		query = sqlite3_mprintf("update %Q set is_root_app_enabled=%d , enabled=%d where gname=%Q",
				storetype_to_string(storeType), CertStatus_to_int(status), status, gname);
	else
		query = sqlite3_mprintf("update %Q set enabled=%d where gname=%Q",
				storetype_to_string(storeType), CertStatus_to_int(status), gname);

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_insert_update_query(query);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Update failed. ret[%d]", result);
		return result;
	}

	return result;
}

int setCertificateStatusToStore(
	CertStoreType storeType,
	int is_root_app,
	const char *gname,
	CertStatus status)
{
	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	int result = enable_disable_cert_status(storeType, is_root_app, gname, status);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to disable certificate.");
		return result;
	}

	SLOGD("Successfully updated the certificate status from %s to %s.",
		(status == DISABLED) ? "ENABLED" : "DISABLED", (status == DISABLED) ? "DISABLED" : "ENABLED");
	return CERTSVC_SUCCESS;
}

int getCertificateStatusFromStore(
	CertStoreType storeType,
	const char* gname,
	CertStatus *status)
{
	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	char *query = sqlite3_mprintf("select gname, common_name, enabled from %Q where gname=%Q",
			storetype_to_string(storeType), gname);
	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	sqlite3_stmt *stmt = NULL;
	int result = execute_select_query(query, &stmt);
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
	CertStoreType storeTypes,
	const char *alias,
	int *punique)
{
	char *query = NULL;
	sqlite3_stmt *stmt = NULL;
	int result = CERTSVC_SUCCESS;
	CertStoreType storeType;
	bool unique = false;

	if (!alias || !punique) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	for (storeType = VPN_STORE; storeType < SYSTEM_STORE; storeType = nextStore(storeType)) {
		if (!hasStore(storeTypes, storeType))
			continue;

		query = sqlite3_mprintf("select * from %Q where common_name=%Q",
				storetype_to_string(storeType), alias);

		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(query, &stmt);

		sqlite3_free(query);
		query = NULL;

		if (result != CERTSVC_SUCCESS || !stmt) {
			SLOGE("Querying database failed. result[%d]", result);
			return CERTSVC_FAIL;
		}

		result = sqlite3_step(stmt);

		sqlite3_finalize(stmt);
		stmt = NULL;

		if (result == SQLITE_DONE) {
			unique = true;
			break;
		}
	}

	*punique = unique ? CERTSVC_TRUE : CERTSVC_FALSE;

	return CERTSVC_SUCCESS;
}

int installCertificateToStore(
	CertStoreType storeType,
	const char *gname,
	const char *common_name,
	const char *private_key_gname,
	const char *associated_gname,
	const char *dataBlock,
	CertType certType)
{
	if ((!gname)
		|| (certType == P12_END_USER && !common_name && !private_key_gname)
		|| (certType != P12_END_USER && !common_name && !associated_gname)) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	int result = CERTSVC_SUCCESS;

	if (storeType != SYSTEM_STORE) {
		result = saveCertificateToStore(gname, dataBlock);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("FAIL to save certificate to key-manager. result[%d]", result);
			return CERTSVC_FAIL;
		}
	}

	if (certType == P12_PKEY) {
		SLOGD("Don't save private key in store");
		return CERTSVC_SUCCESS;
	}

	char *query = NULL;
	if (certType == P12_END_USER && private_key_gname) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, private_key_gname, associated_gname, enabled, is_root_app_enabled) "\
				"values (%Q, %Q, %Q, %Q, %d, %d)", storetype_to_string(storeType), gname, common_name, private_key_gname,
				gname, ENABLED, ENABLED);
	} else if (certType == PEM_CRT || certType == P12_TRUSTED) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, is_root_cert, associated_gname, enabled, is_root_app_enabled) values "\
				"(%Q, %Q, %d, %Q, %d, %d)", storetype_to_string(storeType), gname, common_name, ENABLED,
				associated_gname, ENABLED, ENABLED);
	} else if (certType == P12_INTERMEDIATE) {
		query = sqlite3_mprintf("insert into %Q (gname, common_name, associated_gname, enabled, is_root_app_enabled) values (%Q, %Q, %Q, %d, %d)",
				storetype_to_string(storeType), gname, common_name, associated_gname, ENABLED, ENABLED);
	}

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_insert_update_query(query);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Insert to database failed.");
		return CERTSVC_FAIL;
	}

	return CERTSVC_SUCCESS;
}

int checkAliasExistsInStore(CertStoreType storeType, const char *alias, int *punique)
{
	if (!alias) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	*punique = CERTSVC_FAIL;
	int result = check_alias_exist_in_database(storeType, alias, punique);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Failed to check_alias_exist_in_database. err[%d]", result);
		return CERTSVC_FAIL;
	}

	if (*punique == CERTSVC_TRUE)
		SLOGD("Alias (%s) does not exist in store(%d).", alias, storeType);
	else
		SLOGD("Alias (%s) exist in store(%d).", alias, storeType);

	return CERTSVC_SUCCESS;
}

int getCertificateDetailFromStore(
	CertStoreType storeType,
	CertType certType,
	const char *gname,
	char *pOutData)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;
	ckmc_raw_buffer_s *cert_data = NULL;

	if (!gname || !pOutData) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	/* start constructing query */
	if (certType == P12_PKEY) {
		/* From the given certificate identifier, get the associated_gname for the certificate.
		 * Then query the database for records matching the associated_gname to get the private key */
		query = sqlite3_mprintf("select associated_gname from %Q where gname=%Q",
				storetype_to_string(storeType), gname);
		if (!query) {
			SLOGE("Failed to generate query");
			return CERTSVC_BAD_ALLOC;
		}

		result = execute_select_query(query, &stmt);
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

		query = sqlite3_mprintf("select private_key_gname from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d",
				storetype_to_string(storeType), text, ENABLED, ENABLED);

		sqlite3_finalize(stmt);
	} else if (storeType != SYSTEM_STORE) {
		query = sqlite3_mprintf("select * from %Q where gname=%Q and enabled=%d and is_root_app_enabled=%d",
				storetype_to_string(storeType), gname, ENABLED, ENABLED);
	}

	if (!query) {
		SLOGE("Failed to generate query");
		return CERTSVC_BAD_ALLOC;
	}

	result = execute_select_query(query, &stmt);
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

		gname = text;
	}

	char *ckm_alias = add_shared_owner_prefix(gname);
	if (!ckm_alias) {
		SLOGE("Failed to make alias. memory allocation error.");
		return CERTSVC_BAD_ALLOC;
	}

	result = ckmc_get_data(ckm_alias, NULL, &cert_data);
	free(ckm_alias);

	sqlite3_finalize(stmt);

	if (result != CKMC_ERROR_NONE) {
		SLOGE("Failed to get certificate from key-manager. ckm ret[%d]", result);
		return CERTSVC_FAIL;
	}

	memcpy(pOutData, cert_data->data, cert_data->size);
	pOutData[cert_data->size] = 0;

	ckmc_buffer_free(cert_data);

	return CERTSVC_SUCCESS;
}

int getCertificateDetailFromSystemStore(const char *gname, char *pOutData)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *query = NULL;
	const char *text = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	query = sqlite3_mprintf("select certificate from ssl where gname=%Q and is_root_app_enabled=%d",
			gname, ENABLED, ENABLED);
	if (!query) {
		SLOGE("Query is NULL.");
		return CERTSVC_FAIL;
	}

	result = execute_select_query(query, &stmt);
	sqlite3_free(query);

	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		return result;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW) {
		SLOGE("No valid records found for passed gname [%s].", gname);
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	text = (const char *)sqlite3_column_text(stmt, 0);

	if (!text) {
		SLOGE("Fail to sqlite3_column_text");
		sqlite3_finalize(stmt);
		return CERTSVC_FAIL;
	}

	size_t cert_len = strlen(text);
	if (cert_len >= 4096) {
		sqlite3_finalize(stmt);
		SLOGE("certificate is too long");
		return CERTSVC_FAIL;
	}

	memcpy(pOutData, text, cert_len);
	pOutData[cert_len] = '\0';

	sqlite3_finalize(stmt);

	return CERTSVC_SUCCESS;
}

int deleteCertificateFromStore(CertStoreType storeType, const char *gname)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	char *query = NULL;
	char *private_key_name = NULL;
	sqlite3_stmt *stmt = NULL;

	SLOGD("Remove certificate of gname[%s] in store[%d]", gname, storeType);

	if (!gname) {
		SLOGE("Invalid input parameter passed.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (storeType == SYSTEM_STORE) {
		SLOGE("Invalid store type passed.");
		return CERTSVC_INVALID_STORE_TYPE;
	}

	/* start constructing query */
	query = sqlite3_mprintf("select private_key_gname from %Q where gname=%Q",
			storetype_to_string(storeType), gname);

	result = execute_select_query(query, &stmt);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Querying database failed.");
		result = CERTSVC_FAIL;
		goto error;
	}

	records = sqlite3_step(stmt);
	if (records != SQLITE_ROW) {
		SLOGE("No valid records found for passed gname [%s]. result[%d].", gname, records);
		result = CERTSVC_FAIL;
		goto error;
	}

	/* if a cert is having private-key in it, the private key should
	 * be deleted first from key-manager, then the actual cert */
	if (sqlite3_column_text(stmt, 0) != NULL)
		private_key_name = strdup((const char *)sqlite3_column_text(stmt, 0));

	query = sqlite3_mprintf("delete from disabled_certs where gname=%Q", gname);
	result = execute_insert_update_query(query);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Unable to delete certificate entry from database. result[%d]", result);
		goto error;
	}

	if (query) {
		sqlite3_free(query);
		query = NULL;
	}

	if (stmt) {
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	query = sqlite3_mprintf("delete from %Q where gname=%Q",
			storetype_to_string(storeType), gname);

	result = execute_insert_update_query(query);
	if (result != CERTSVC_SUCCESS) {
		SLOGE("Unable to delete certificate entry from database. result[%d]", result);
		goto error;
	}

	if (query) {
		sqlite3_free(query);
		query = NULL;
	}

	if (stmt) {
		sqlite3_finalize(stmt);
		stmt = NULL;
	}

	CertStoreType other = ALL_STORE & ~SYSTEM_STORE & ~storeType;
	CertStoreType current;
	int gname_exist = 0;
	for (current = VPN_STORE; current < SYSTEM_STORE; current = nextStore(current)) {
		if (!hasStore(other, current))
			continue;

		query = sqlite3_mprintf("select * from %Q where gname=%Q",
				storetype_to_string(current), gname);
		result = execute_select_query(query, &stmt);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			result = CERTSVC_FAIL;
			goto error;
		}
		records = sqlite3_step(stmt);
		if (records == SQLITE_ROW) {
			SLOGI("Same gname[%s] exist on store[%d].", gname, current);
			gname_exist = 1;
			break;
		}

		sqlite3_free(query);
		sqlite3_finalize(stmt);
		query = NULL;
		stmt = NULL;
	}

	if (!gname_exist) {
		SLOGD("The gname[%s] which is in store[%d] is the last one. so remove it from ckm either.", gname, current);

		if (private_key_name != NULL) {
			result = ckmc_remove_alias_with_shared_owner_prefix(private_key_name);
			if (result != CKMC_ERROR_NONE) {
				SLOGE("Failed to delete certificate from key-manager. ckmc_result[%d]", result);
				result = CERTSVC_FAIL;
				goto error;
			}
		}

		/* removing the actual cert */
		result = ckmc_remove_alias_with_shared_owner_prefix(gname);
		if (result != CKMC_ERROR_NONE) {
			SLOGE("Failed to remove data in ckm with gname[%s]. ckm_result[%d]", gname, result);
			result = CERTSVC_FAIL;
			goto error;
		}
	}

	SLOGD("Success in deleting the certificate from store.");
	result = CERTSVC_SUCCESS;

error:
	if (query)
		sqlite3_free(query);

	if (stmt)
		sqlite3_finalize(stmt);

	free(private_key_name);

	return result;
}

static int makeCertListNode(
	CertStoreType storeType,
	const char *gname,
	const char *title,
	int statusInt,
	CertSvcStoreCertList **out)
{
	CertSvcStoreCertList *node = NULL;
	int result = CERTSVC_SUCCESS;
	size_t gname_len = 0;
	size_t title_len = 0;

	if (out == NULL || gname == NULL || title == NULL) {
		SLOGE("Failed to read texts from records");
		return CERTSVC_WRONG_ARGUMENT;
	}

	node = (CertSvcStoreCertList *)malloc(sizeof(CertSvcStoreCertList));
	if (node == NULL) {
		SLOGE("Failed to allocate memory.");
		return CERTSVC_BAD_ALLOC;
	}

	gname_len = strlen(gname);
	title_len = strlen(title);

	node->gname = (char *)malloc(sizeof(char) * (gname_len + 1));
	node->title = (char *)malloc(sizeof(char) * (title_len + 1));
	if (node->title == NULL || node->gname == NULL) {
		SLOGE("Failed to allocate memory");
		result = CERTSVC_BAD_ALLOC;
		goto error;
	}

	memcpy(node->gname, gname, gname_len);
	memcpy(node->title, title, title_len);
	node->gname[gname_len] = '\0';
	node->title[title_len] = '\0';

	node->storeType = storeType;
	node->status = int_to_CertStatus(statusInt);
	node->next = NULL;

	*out = node;

	return CERTSVC_SUCCESS;

error:
	if (node != NULL) {
		free(node->gname);
		free(node->title);
	}
	free(node);

	return result;
}

int getCertificateListFromStore(
	int reqType,
	CertStoreType storeTypes,
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
	int records = 0;
	size_t count = 0;
	size_t i = 0;

	CertStoreType storeType;
	for (storeType = VPN_STORE; storeType != NONE_STORE; storeType = nextStore(storeType)) {
		if (!hasStore(storeTypes, storeType))
			continue;

		SLOGD("Processing storetype [%s]", storetype_to_string(storeType));

		if (reqType == CERTSVC_GET_ROOT_CERTIFICATE_LIST) {
			if (storeType == SYSTEM_STORE) {
				query = sqlite3_mprintf("select gname, common_name, enabled from %Q where enabled=%d "\
						"and is_root_app_enabled=%d and order by common_name asc", "ssl", ENABLED, ENABLED);
			} else {
				query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
						"is_root_cert IS NOT NULL and is_root_app_enabled=%d and enabled=%d",
						storetype_to_string(storeType), ENABLED, ENABLED);
			}
		} else if (reqType == CERTSVC_GET_USER_CERTIFICATE_LIST) {
			if (storeType == SYSTEM_STORE) {
				SLOGE("Invalid store type passed.");
				return CERTSVC_WRONG_ARGUMENT;
			} else {
				query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
						"private_key_gname IS NOT NULL and is_root_app_enabled=%d and enabled=%d",
						storetype_to_string(storeType), ENABLED, ENABLED);
			}
		} else {
			if (is_root_app != ENABLED) {
			/* Gets only the list of certificates where is_root_app = 1 (which are enabled by the master application) */
				if (storeType == SYSTEM_STORE) {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q where "\
							"is_root_app_enabled=%d order by common_name asc",
							storetype_to_string(storeType), ENABLED, ENABLED);
				} else {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q where is_root_app_enabled=%d",
							storetype_to_string(storeType), ENABLED, ENABLED);
				}
			} else {
			/* Gets all the certificates from store without any restrictions */
				if (storeType == SYSTEM_STORE) {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q order by common_name asc",
							storetype_to_string(storeType), ENABLED);
				} else {
					query = sqlite3_mprintf("select gname, common_name, enabled from %Q",
							storetype_to_string(storeType), ENABLED);
				}
			}
		}

		result = execute_select_query(query, &stmt);
		if (result != CERTSVC_SUCCESS) {
			SLOGE("Querying database failed.");
			result = CERTSVC_FAIL;
			goto error;
		}

		while ((records = sqlite3_step(stmt)) == SQLITE_ROW) {
			result = makeCertListNode(
					storeType,
					(const char *)sqlite3_column_text(stmt, 0),
					(const char *)sqlite3_column_text(stmt, 1),
					(int)sqlite3_column_int(stmt, 2),
					&tmpNode);

			if (result != CERTSVC_SUCCESS) {
				SLOGE("Failed to make new cert list node. result[%d]", result);
				goto error;
			}

			if (count == 0)
				rootCertHead = tmpNode;
			else
				currentNode->next = tmpNode;

			currentNode = tmpNode;
			tmpNode = NULL;
			count++;
		}

		if (records != SQLITE_DONE) {
			SLOGE("Error in getting data from sqlite3 statement. result[%d]", records);
			result = CERTSVC_FAIL;
			goto error;
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

	   currentNode = tmpNode;
	}

	*certListBuffer = (char *) respCertData;
	*bufferLen = count * sizeof(VcoreCertResponseData);

	SLOGD("Success to create certificate list. cert_count=%d", count);
	result = CERTSVC_SUCCESS;

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
			currentNode = tmpNode;
		}
	}

	return result;
}

int getCertificateAliasFromStore(CertStoreType storeType, const char *gname, char *alias)
{
	int result = CERTSVC_SUCCESS;
	int records = 0;
	sqlite3_stmt *stmt = NULL;
	char *query = NULL;
	const char *text = NULL;

	query = sqlite3_mprintf("select common_name from %Q where gname=%Q",
			storetype_to_string(storeType), gname);

	result = execute_select_query(query, &stmt);
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

	query = sqlite3_mprintf("select associated_gname from %Q where gname=%Q",
			storetype_to_string(storeType), gname);

	result = execute_select_query(query, &stmt);
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

		query = sqlite3_mprintf("select gname from %Q where associated_gname=%Q and enabled=%d and is_root_app_enabled=%d",
				storetype_to_string(storeType), columnText, ENABLED, ENABLED);

		if (stmt)
			sqlite3_finalize(stmt);

		result = execute_select_query(query, &stmt);
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
