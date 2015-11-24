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
 * @file     cert-server-db.c
 * @author   Kyungwook Tak (k.tak@samsung.com)
 * @version  1.0
 * @brief    cert server db utils.
 */

#include <db-util.h>
#include <cert-server-debug.h>
#include <cert-server-db.h>

sqlite3 *cert_store_db = NULL;

int initialize_db(void)
{
	int result = CERTSVC_SUCCESS;

	if (cert_store_db != NULL)
		return CERTSVC_SUCCESS;

	result = db_util_open(CERTSVC_SYSTEM_STORE_DB, &cert_store_db, 0);
	if (result != SQLITE_OK) {
		SLOGE("opening %s failed!", CERTSVC_SYSTEM_STORE_DB);
		cert_store_db = NULL;
		return CERTSVC_FAIL;
	}

	return CERTSVC_SUCCESS;
}

void deinitialize_db(void)
{
	if (cert_store_db == NULL)
		return;

	db_util_close(cert_store_db);
	cert_store_db = NULL;
}

int execute_insert_update_query(const char *query)
{
	if (!cert_store_db) {
		SLOGE("Database not initialised.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	if (!query) {
		SLOGE("Query is NULL.");
		return CERTSVC_WRONG_ARGUMENT;
	}

	/* Begin transaction */
	int result = sqlite3_exec(cert_store_db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (result != SQLITE_OK) {
		SLOGE("Failed to begin transaction.");
		return CERTSVC_FAIL;
	}

	/* Executing command */
	result = sqlite3_exec(cert_store_db, query, NULL, NULL, NULL);
	if (result != SQLITE_OK) {
		SLOGE("Failed to execute query (%s).", query);
		return CERTSVC_FAIL;
	}

	/* Committing the transaction */
	result = sqlite3_exec(cert_store_db, "COMMIT", NULL, NULL, NULL);
	if (result) {
		SLOGE("Failed to commit transaction. Roll back now.");
		result = sqlite3_exec(cert_store_db, "ROLLBACK", NULL, NULL, NULL);
		if (result != SQLITE_OK)
			SLOGE("Failed to commit transaction. Roll back now.");

		return CERTSVC_FAIL;
	}

	SLOGD("Transaction Commit and End.");

	return CERTSVC_SUCCESS;
}

int execute_select_query(const char *query, sqlite3_stmt **stmt)
{
	if (!cert_store_db || !query)
		return CERTSVC_WRONG_ARGUMENT;

	sqlite3_stmt *stmts = NULL;
	if (sqlite3_prepare_v2(cert_store_db, query, strlen(query), &stmts, NULL) != SQLITE_OK) {
		SLOGE("sqlite3_prepare_v2 failed [%s].", query);
		return CERTSVC_FAIL;
	}

	*stmt = stmts;
	return CERTSVC_SUCCESS;
}
