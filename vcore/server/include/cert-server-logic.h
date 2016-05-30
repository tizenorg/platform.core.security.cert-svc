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
 * @file     cert-server-logic.h
 * @author   Madhan A K (madhan.ak@samsung.com)
 * @version  1.0
 * @brief    cert-server routines.
 */

#ifndef CERT_SERVER_LOGIC_H_
#define CERT_SERVER_LOGIC_H_

int getCertificateDetailFromStore(CertStoreType storeType, CertType certType, const char *gname,
								  char *cert);

int getCertificateDetailFromSystemStore(const char *gname, char *cert);

int deleteCertificateFromStore(CertStoreType storeType, const char *gname);

int getCertificateStatusFromStore(CertStoreType storeType, const char *gname, CertStatus *status);

int setCertificateStatusToStore(CertStoreType storeType, int is_root_app, const char *gname,
								CertStatus status);

int checkAliasExistsInStore(CertStoreType storeType, const char *alias, int *punique);

int installCertificateToStore(CertStoreType storeType, const char *gname, const char *common_name,
							  const char *private_key_gname, const char *associated_gname, const char *pCertBuffer,
							  CertType certType);

int getCertificateListFromStore(int reqType, CertStoreType storeType, int is_root_app,
								char **ppCertListBuffer, size_t *bufferLen, size_t *certCount);

int getCertificateAliasFromStore(CertStoreType storeType, const char *gname, char *alias);

int loadCertificatesFromStore(CertStoreType storeType, const char *gname, char **ppCertBlockBuffer,
							  size_t *bufferLen, size_t *certBlockCount);

int update_ca_certificate_file(char *cert);

#endif
