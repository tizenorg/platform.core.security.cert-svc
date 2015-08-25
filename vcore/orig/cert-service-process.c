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
#include <dirent.h>
#include <error.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fts.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "orig/cert-service.h"
#include "orig/cert-service-util.h"
#include "orig/cert-service-debug.h"
#include "orig/cert-service-process.h"

#define get_ASN1_INTEGER(x)	ASN1_INTEGER_get((x))
#define get_ASN1_OBJECT(x)	OBJ_nid2ln(OBJ_obj2nid((x)))
#define get_X509_NAME(x)	X509_NAME_oneline((x), NULL, 0)

static unsigned char** __get_field_by_tag(unsigned char* str, int *tag_len, cert_svc_name_fld_data* fld)
{
	const struct {
		const char* name;
		int len;
		unsigned char **field;
	} tags[] = {
		{"C=", 2, &(fld->countryName)},
		{"ST=", 3, &(fld->stateOrProvinceName)},
		{"L=", 2, &(fld->localityName)},
		{"O=", 2, &(fld->organizationName)},
		{"OU=", 3, &(fld->organizationUnitName)},
		{"CN=", 3, &(fld->commonName)},
		{"emailAddress=", 13, &(fld->emailAddress)}
	};
	unsigned char **field = NULL;
	if (str[0] == '/') {
		int i = sizeof(tags) / sizeof(tags[0]) - 1;
		while (i >= 0 && strncmp((const char*)(str + 1), (const char*)(tags[i].name), tags[i].len)) {
			i--;
		}
		if (i >= 0) {
			*tag_len = tags[i].len + 1;
			field = tags[i].field;
		}
	}
	return field;
}

static X509 *_d2i_X509(cert_svc_mem_buff *certBuf, X509 **out)
{
	const unsigned char *certContent = certBuf->data;
	return d2i_X509(out, &certContent, certBuf->size);
}

/*SURC k.astrakhant 2011.07.14 : this version can parse info string with any order of tags*/
int parse_name_fld_data(unsigned char* str, cert_svc_name_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	unsigned char **prev_field = NULL;
	int i = 0, l = 0;
    if (fld == NULL) {
        ret = CERT_SVC_ERR_INVALID_PARAMETER;
        return ret;
    }
	memset(fld, 0, sizeof(cert_svc_name_fld_data));
	while (str[i] != '\0') {
		int tag_len;
		unsigned char **field = __get_field_by_tag(str + i, &tag_len, fld);
		while (field == NULL && str[i] != '\0') {
			i++;
			field = __get_field_by_tag(str + i, &tag_len, fld);
		}
		if (prev_field != NULL) {
			*prev_field = (unsigned char*)strndup((const char*)(str + l), i - l);
		}
		if (field != NULL) {
			i += tag_len;
			l = i;
			prev_field = field;
		}
	}
	return ret;
}

int parse_time_fld_data(unsigned char* before, unsigned char* after, cert_svc_validity_fld_data* fld)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	char* index = NULL;
	char year[5] = {0, };
	char month[3] = {0, };
	char day[3] = {0, };
	char hour[3] = {0, };
	char minute[3] = {0, };
	char second[3] = {0, };

	if((strlen((char*)before) < 15) || (strlen((char*)after) < 15)) {
		SLOGE("[ERR][%s] Fail to parse time fld.", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	// first(before)
	index = (char*)before;
	strncpy(year, index, 4);
	(*fld).firstYear = (unsigned int)(strtoul(year, NULL, 10));
	strncpy(month, (index + 4), 2);
	(*fld).firstMonth = (unsigned int)(strtoul(month, NULL, 10));
	strncpy(day, (index + 6), 2);
	(*fld).firstDay = (unsigned int)(strtoul(day, NULL, 10));
	strncpy(hour, (index + 8), 2);
	(*fld).firstHour = (unsigned int)(strtoul(hour, NULL, 10));
	strncpy(minute, (index + 10), 2);
	(*fld).firstMinute = (unsigned int)(strtoul(minute, NULL, 10));
	strncpy(second, (index + 12), 2);
	(*fld).firstSecond = (unsigned int)(strtoul(second, NULL, 10));

	// second(after)
	index = (char*)after;
	strncpy(year, index, 4);
	(*fld).secondYear = (unsigned int)(strtoul(year, NULL, 10));
	strncpy(month, (index + 4), 2);
	(*fld).secondMonth = (unsigned int)(strtoul(month, NULL, 10));
	strncpy(day, (index + 6), 2);
	(*fld).secondDay = (unsigned int)(strtoul(day, NULL, 10));
	strncpy(hour, (index + 8), 2);
	(*fld).secondHour = (unsigned int)(strtoul(hour, NULL, 10));
	strncpy(minute, (index + 10), 2);
	(*fld).secondMinute = (unsigned int)(strtoul(minute, NULL, 10));
	strncpy(second, (index + 12), 2);
	(*fld).secondSecond = (unsigned int)(strtoul(second, NULL, 10));

err:
	return ret;
}

cert_svc_linked_list* find_issuer_from_list(cert_svc_linked_list* list, cert_svc_linked_list* p)
{
	/* find q and q has subject string which be same with issuer string of parameter p */
	cert_svc_linked_list* q = NULL;
	cert_svc_cert_descriptor* tmp1 = NULL;
	cert_svc_cert_descriptor* tmp2 = NULL;

	tmp1 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if (tmp1 == NULL) {
		SLOGE("[ERR][%s] Fail to allocate certificate descriptor.", __func__);
		return NULL;
	}

	memset(tmp1, 0x00, sizeof(cert_svc_cert_descriptor));

	if(_extract_certificate_data(p->certificate, tmp1) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to extract certificate data.", __func__);
		goto err;
	}

	for(q = list; q != NULL; q = q->next) {
		tmp2 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
		if (tmp2 == NULL) {
			SLOGE("[ERR][%s] Fail to allocate certificate descriptor.", __func__);
			goto err;
		}

		memset(tmp2, 0x00, sizeof(cert_svc_cert_descriptor));

		_extract_certificate_data(q->certificate, tmp2);

		if(!strncmp((const char*)(tmp2->info.subjectStr), (const char*)(tmp1->info.issuerStr), strlen((const char*)(tmp1->info.issuerStr)))) {	// success
			release_certificate_data(tmp1);
			release_certificate_data(tmp2);
			return q;
		}
		release_certificate_data(tmp2);
		tmp2 = NULL;
	}

err:	// fail
	release_certificate_data(tmp1);
	release_certificate_data(tmp2);
	return NULL;
}

int sort_cert_chain(cert_svc_linked_list** unsorted, cert_svc_linked_list** sorted)
{
	cert_svc_linked_list* p = NULL;
	cert_svc_linked_list* q = NULL;
	cert_svc_linked_list* r = NULL;

	cert_svc_cert_descriptor* tmp1 = NULL;
	cert_svc_cert_descriptor* tmp2 = NULL;

	if((*unsorted) == NULL) {
		for(p = (*sorted); p->next != NULL; p = p->next) {
			tmp1 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
			if(tmp1 == NULL) {
				SLOGE("[ERR][%s] Fail to allocate certificate descriptor.", __func__);
				return CERT_SVC_ERR_MEMORY_ALLOCATION;
			}
			memset(tmp1, 0x00, sizeof(cert_svc_cert_descriptor));
			tmp2 = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
			if(tmp2 == NULL) {
				release_certificate_data(tmp1);
				SLOGE("[ERR][%s] Fail to allocate certificate descriptor.", __func__);
				return CERT_SVC_ERR_MEMORY_ALLOCATION;
			}
			memset(tmp2, 0x00, sizeof(cert_svc_cert_descriptor));

			_extract_certificate_data(p->certificate, tmp1);
			_extract_certificate_data(p->next->certificate, tmp2);

			if(strncmp((const char*)(tmp1->info.issuerStr), (const char*)(tmp2->info.subjectStr), strlen((const char*)(tmp2->info.subjectStr)))) {
				SLOGE("[ERR][%s] Certificate chain is broken.", __func__);
				release_certificate_data(tmp1);
				release_certificate_data(tmp2);
				return CERT_SVC_ERR_BROKEN_CHAIN;
			}
			else {
				release_certificate_data(tmp1);
				tmp1 = NULL;
				release_certificate_data(tmp2);
				tmp2 = NULL;
			}
		}
		release_certificate_data(tmp1);
		release_certificate_data(tmp2);
		return CERT_SVC_ERR_NO_ERROR;
	}
	else if((*unsorted)->next == NULL) {
		(*unsorted)->next = *sorted;
		*sorted = *unsorted;
		*unsorted = NULL;
	}
	else {
		r = (*unsorted);
		for(p = (*unsorted); p != NULL; p = p->next) {
			if((q = find_issuer_from_list((*unsorted), p)) == NULL)
				break;

			r = p;
		}

		if(q != NULL) {
			SLOGE("[ERR][%s] Certificate chain is broken.", __func__);
			return CERT_SVC_ERR_BROKEN_CHAIN;
		}

		if(r == p) {
			q = (*unsorted)->next;
			(*unsorted)->next = (*sorted);
			(*sorted) = (*unsorted);
			(*unsorted) = q;
		}
		else if((*sorted) == NULL) {
			(*sorted) = p;
			r->next = p->next;
			(*sorted)->next = NULL;
		}
		else {
			r->next = p->next;
			p->next = (*sorted);
			(*sorted) = p;
		}
	}

	return sort_cert_chain(unsorted, sorted);
}

int _remove_selfsigned_cert_in_chain(cert_svc_linked_list** certList)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* prev = NULL;
	cert_svc_linked_list* current = NULL;
	cert_svc_linked_list* start = NULL;
	cert_svc_linked_list* deleted = NULL;
	cert_svc_cert_descriptor* certdesc = NULL;
	int first_tag = 0;

	start = (*certList);
	prev = start;

	for(current = (*certList); current != NULL; current = current->next) {
		deleted = current;

		certdesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
		if(certdesc == NULL) {
			SLOGE("[ERR][%s] Fail to allocate certificate descriptor.", __func__);
			return CERT_SVC_ERR_MEMORY_ALLOCATION;
		}
		memset(certdesc, 0x00, sizeof(cert_svc_cert_descriptor));

		if((ret = _extract_certificate_data(current->certificate, certdesc)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to extract certificate data.", __func__);
			goto err;
		}

		if(!strncmp((const char*)(certdesc->info.subjectStr), (const char*)(certdesc->info.issuerStr), strlen((const char*)(certdesc->info.issuerStr)))) { // self-signed
			if(first_tag == 0) { // first cert is self-signed
				start = start->next;
				prev = start;

				deleted->next = NULL;
				release_cert_list(deleted);

				release_certificate_data(certdesc);
				certdesc = NULL;
				continue;
			}
			else {
				prev->next = current->next;

				deleted->next = NULL;
				release_cert_list(deleted);
			}
		}
		else {
			prev = current;
		}

		release_certificate_data(certdesc);
		certdesc = NULL;

		first_tag = 1;
	}

	(*certList) = start;

err:
	if(certdesc != NULL)
		release_certificate_data(certdesc);

	return ret;
}

int _verify_certificate_with_caflag(
	cert_svc_mem_buff *certBuf,
	cert_svc_linked_list **certList,
	int checkCaFlag,
	cert_svc_filename_list *rootPath,
	int *validity)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* sorted = NULL;
	cert_svc_linked_list* tempNode = NULL;
	cert_svc_cert_descriptor* findRoot = NULL;
	cert_svc_filename_list* fileNames = NULL;
	cert_svc_mem_buff* CACert = NULL;

	int certNum = 0;
	int certIndex = 0, i = 0;
	X509_STORE_CTX* storeCtx = NULL;
	X509* rootCert = NULL;
	X509** interCert = NULL;
	X509* targetCert = NULL;
	STACK_OF(X509) *tchain, *uchain;
	int caFlagValidity;

	OpenSSL_add_all_algorithms();
	tchain = sk_X509_new_null();
	uchain = sk_X509_new_null();

	findRoot = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor));
	if (findRoot == NULL) {
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memset(findRoot, 0x00, sizeof(cert_svc_cert_descriptor));

	if (*certList != NULL) {
		/* remove self-signed certificate in certList */
		ret = _remove_selfsigned_cert_in_chain(certList);
		if (ret != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("Fail to remove self-signed certificate in chain.");
			goto err;
		}

		/* sort certList */
		ret = sort_cert_chain(certList, &sorted);
		if (ret != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("Fail to sort certificate chain.");
			goto err;
		}

		/*
		 *  find root cert from store, the SUBJECT field of root cert
		 *  is same with ISSUER field of certList[0]
		 */
		tempNode = sorted;
		while (tempNode->next != NULL) {
			certNum++;
			tempNode = tempNode->next;
		}
		certNum++;

		ret = _extract_certificate_data(tempNode->certificate, findRoot);
	} else {
		ret = _extract_certificate_data(certBuf, findRoot);
	}

	if (ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("Fail to extract certificate data");
		goto err;
	}

	ret = _search_certificate(&fileNames, SUBJECT_STR, (char*)findRoot->info.issuerStr);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("Fail to search root certificate");
		goto err;
	}

	if (fileNames->filename == NULL) {
		ret = CERT_SVC_ERR_NO_ROOT_CERT;
		goto err;
	}

	CACert = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff));
	if (CACert == NULL) {
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	memset(CACert, 0x00, sizeof(cert_svc_mem_buff));

	/* use the first found CA cert - ignore other certificate(s). */
	ret = cert_svc_util_load_file_to_buffer(fileNames->filename, CACert);
	if (ret != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("Fail to load CA cert to buffer.");
		goto err;
	}

	/* store root certicate path into ctx */
	strncpy(rootPath->filename, fileNames->filename, CERT_SVC_MAX_FILE_NAME_SIZE - 1);
	rootPath->filename[CERT_SVC_MAX_FILE_NAME_SIZE - 1] = '\0';

	/* insert root certificate into trusted chain */
	_d2i_X509(CACert, &rootCert);
	if (!sk_X509_push(tchain, rootCert)) {
		SLOGE("Fail to push certificate into stack.");
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	_d2i_X509(certBuf, &targetCert);

	if (sorted != NULL) {
		interCert = (X509**)malloc(sizeof(X509*) * certNum);
		if (interCert == NULL) {
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		memset(interCert, 0x00, (sizeof(X509*) * certNum));
		for (tempNode = sorted, certIndex = 0;
				tempNode != NULL;
				tempNode = tempNode->next, certIndex++) {

			_d2i_X509(tempNode->certificate, &interCert[certIndex]);
			if (interCert[certIndex] == NULL) {
				SLOGE("Invalid certificate. failed to parse certificate.");
				ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
				goto err;
			}

			/* insert all certificate(s) into chain */
			if (!sk_X509_push(uchain, interCert[certIndex])) {
				SLOGE("Fail to push certificate into stack.");
				ret = CERT_SVC_ERR_INVALID_OPERATION;
				goto err;
			}
		}
	}

	storeCtx = X509_STORE_CTX_new();

	if (!X509_STORE_CTX_init(storeCtx, 0, targetCert, uchain)) {
		SLOGE("Fail to initialize X509 store context.");
		ret = CERT_SVC_ERR_INVALID_OPERATION;
		goto err;
	}

	X509_STORE_CTX_trusted_stack(storeCtx, tchain);

	*validity = X509_verify_cert(storeCtx);
	if (*validity != 1) {
		int error = X509_STORE_CTX_get_error(storeCtx);

		SLOGE("err str: [%s]", X509_verify_cert_error_string(error));
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	if (checkCaFlag) {
		caFlagValidity = X509_check_ca(rootCert);
		if (caFlagValidity != 1) {
			*validity = 0;
			SLOGE("Invalid CA Flag for CA Certificate, caFlagValidity: [%d]", caFlagValidity);
		}
	}

err:
	if (ret != CERT_SVC_ERR_NO_ERROR)
		SLOGE("Error in cert-service-process. code[%d]", ret);

	if (rootCert != NULL)
		X509_free(rootCert);

	if (targetCert != NULL)
		X509_free(targetCert);

	if (storeCtx != NULL)
		X509_STORE_CTX_free(storeCtx);

	if (tchain != NULL)
		sk_X509_free(tchain);

	if (uchain != NULL)
		sk_X509_free(uchain);

	if (interCert != NULL) {
		for (i = 0; i < certNum; i++) {
			if (interCert[i] != NULL)
				X509_free(interCert[i]);
		}
		free(interCert);
	}

	release_certificate_buf(CACert);
	release_certificate_data(findRoot);
	release_filename_list(fileNames);
	release_cert_list(sorted);

	return ret;
}

int _extract_certificate_data(cert_svc_mem_buff* cert, cert_svc_cert_descriptor* certDesc)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	X509* x = NULL;
	int i = 0;
	// get signature algorithm
	char* signatureAlgo = NULL;
	int sigLen = 0;
	// get issuer
	int issuerStrLen = 0;
	unsigned char* tmpIssuerStr = NULL;
	// get time
	ASN1_GENERALIZEDTIME* timeNotBefore = NULL;
	ASN1_GENERALIZEDTIME* timeNotAfter = NULL;
	// get subject
	int subjectStrLen = 0;
	unsigned char* tmpSubjectStr = NULL;
	// get public key algorithm
	char* publicKeyAlgo = NULL;
	int publicKeyAlgoLen = 0;
	// get public key
	unsigned char* pubkeyTmp = NULL;
	int pkeyLen = 0;
	EVP_PKEY* evp = NULL;
	int issuerUidLen = 0, subjectUidLen = 0;
	// get extension values
	X509_EXTENSION* ext = NULL;
	char* extObject = NULL;
	int extObjLen = 0;
	char* extValue = NULL;
	int extValLen = 0;

	// get signature algorithm and signature
	char* sigAlgo = NULL;
	int sigAlgoLen = 0, sigDataLen = 0;

	memset(certDesc, 0x00, sizeof(cert_svc_cert_descriptor));

	_d2i_X509(cert, &x);
	if(x == NULL) {
		SLOGE("[ERR][%s] Fail to allocate X509 structure.", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}

	/* get type */
	strncpy(certDesc->type, cert->type, 3);
	certDesc->type[3] = '\0';
	/* get version and serial number */
	certDesc->info.version = get_ASN1_INTEGER(x->cert_info->version) + 1;	// default is 0 --> version 1
	certDesc->info.serialNumber = get_ASN1_INTEGER(x->cert_info->serialNumber);
	/* get signature algorithm */
	signatureAlgo = (char*)get_ASN1_OBJECT(x->cert_info->signature->algorithm);
	if(signatureAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	sigLen = strlen((const char*)signatureAlgo);
	certDesc->info.sigAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (sigLen + 1));
	if(certDesc->info.sigAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.sigAlgo, 0x00, (sigLen + 1));
	memcpy(certDesc->info.sigAlgo, signatureAlgo, sigLen);
	/* get issuer */
	tmpIssuerStr = (unsigned char*)get_X509_NAME(x->cert_info->issuer);
	issuerStrLen = strlen((const char*)tmpIssuerStr);
	certDesc->info.issuerStr = (unsigned char*)malloc(sizeof(unsigned char) * (issuerStrLen + 1));
	if(certDesc->info.issuerStr == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.issuerStr, 0x00, (issuerStrLen + 1));
	memcpy(certDesc->info.issuerStr, tmpIssuerStr, issuerStrLen);

	if((ret = parse_name_fld_data(tmpIssuerStr, &(certDesc->info.issuer))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.", __func__);
		goto err;
	}
	/* get time */
	ASN1_TIME_to_generalizedtime(x->cert_info->validity->notBefore, &timeNotBefore);
	ASN1_TIME_to_generalizedtime(x->cert_info->validity->notAfter, &timeNotAfter);
	if((ret = parse_time_fld_data(timeNotBefore->data, timeNotAfter->data, &(certDesc->info.validPeriod))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_validity_fld_data.", __func__);
		goto err;
	}
	/* get subject */
	tmpSubjectStr = (unsigned char*)get_X509_NAME(x->cert_info->subject);
	subjectStrLen = strlen((const char*)tmpSubjectStr);
	certDesc->info.subjectStr = (unsigned char*)malloc(sizeof(unsigned char) * (subjectStrLen + 1));
	if(certDesc->info.subjectStr == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.subjectStr, 0x00, (subjectStrLen + 1));
	memcpy(certDesc->info.subjectStr, tmpSubjectStr, subjectStrLen);

	if((ret = parse_name_fld_data(tmpSubjectStr, &(certDesc->info.subject))) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.", __func__);
		goto err;
	}
	/* get public key algorithm */
	publicKeyAlgo = (char*)get_ASN1_OBJECT(x->cert_info->key->algor->algorithm);
	if(publicKeyAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}

	publicKeyAlgoLen = strlen((const char*)publicKeyAlgo);
	certDesc->info.pubKeyAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (publicKeyAlgoLen + 1));
	if(certDesc->info.pubKeyAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->info.pubKeyAlgo, 0x00, (publicKeyAlgoLen + 1));
	memcpy(certDesc->info.pubKeyAlgo, publicKeyAlgo, publicKeyAlgoLen);
	/* get public key */
	if((evp = X509_get_pubkey(x)) == NULL) {
		SLOGE("[ERR][%s] Public key is null.", __func__);
		ret = CERT_SVC_ERR_INVALID_CERTIFICATE;
		goto err;
	}
	pkeyLen = i2d_PublicKey(x->cert_info->key->pkey, NULL);
	certDesc->info.pubKey = (unsigned char*)malloc(sizeof(unsigned char) * (pkeyLen + 1));
	if(certDesc->info.pubKey == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	pubkeyTmp = certDesc->info.pubKey;
	i2d_PublicKey(x->cert_info->key->pkey, &pubkeyTmp);
	certDesc->info.pubKeyLen = pkeyLen;
	/* get issuer UID */
	if(x->cert_info->issuerUID != NULL) {
		issuerUidLen = x->cert_info->issuerUID->length;
		certDesc->info.issuerUID = (unsigned char*)malloc(sizeof(unsigned char) * (issuerUidLen + 1));
		if(certDesc->info.issuerUID == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}
		memset(certDesc->info.issuerUID, 0x00, (issuerUidLen + 1));
		memcpy(certDesc->info.issuerUID, x->cert_info->issuerUID->data, issuerUidLen);
	}
	else
		certDesc->info.issuerUID = NULL;

	/* get subject UID */
	if(x->cert_info->subjectUID != NULL) {
		subjectUidLen = x->cert_info->subjectUID->length;
		certDesc->info.subjectUID = (unsigned char*)malloc(sizeof(unsigned char) * (subjectUidLen + 1));
		if(certDesc->info.subjectUID == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}
		memset(certDesc->info.subjectUID, 0x00, (subjectUidLen + 1));
		memcpy(certDesc->info.subjectUID, x->cert_info->subjectUID->data, subjectUidLen);
	}
	else
		certDesc->info.subjectUID = NULL;
	/* get extension fields */
	if(x->cert_info->extensions != NULL) {
//		certDesc->ext.numOfFields = x->cert_info->extensions->num;
		certDesc->ext.numOfFields = sk_X509_EXTENSION_num(x->cert_info->extensions);
		certDesc->ext.fields = (cert_svc_cert_fld_desc*)malloc(sizeof(cert_svc_cert_fld_desc) * certDesc->ext.numOfFields);
		if(certDesc->ext.fields == NULL) {
			SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		for(i = 0; i < (int)certDesc->ext.numOfFields; i++) {
			ext = sk_X509_EXTENSION_value(x->cert_info->extensions, i);
			if(ext != NULL) {
				extObject = (char*)get_ASN1_OBJECT(ext->object);
			    if(extObject == NULL) {
					SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
			        ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			        goto err;
			    }
				extObjLen = strlen((const char*)extObject);
				certDesc->ext.fields[i].name = (unsigned char*)malloc(sizeof(unsigned char) * (extObjLen + 1));
				if(certDesc->ext.fields[i].name == NULL) {
					SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
					ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
					goto err;
				}
				memset(certDesc->ext.fields[i].name, 0x00, (extObjLen + 1));
				memcpy(certDesc->ext.fields[i].name, extObject, extObjLen);

				extValue = (char*)ext->value->data;
				extValLen = ext->value->length;
				certDesc->ext.fields[i].data = (unsigned char*)malloc(sizeof(unsigned char) * (extValLen + 1));
				if(certDesc->ext.fields[i].data == NULL) {
					SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
					ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
					goto err;
				}
				memset(certDesc->ext.fields[i].data, 0x00, (extValLen + 1));
				memcpy(certDesc->ext.fields[i].data, extValue, extValLen);

				certDesc->ext.fields[i].datasize = extValLen;
			}
		}
	}
	/* get signature algorithm and signature */
	sigAlgo = (char*)get_ASN1_OBJECT(x->sig_alg->algorithm);
	if(sigAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	sigAlgoLen = strlen((const char*)sigAlgo);
	certDesc->signatureAlgo = (unsigned char*)malloc(sizeof(unsigned char) * (sigAlgoLen + 1));
	if(certDesc->signatureAlgo == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->signatureAlgo, 0x00, (sigAlgoLen + 1));
	memcpy(certDesc->signatureAlgo, sigAlgo, sigAlgoLen);

	sigDataLen = x->signature->length;
	certDesc->signatureLen = sigDataLen;
	certDesc->signatureData = (unsigned char*)malloc(sizeof(unsigned char) * (sigDataLen + 1));
	if(certDesc->signatureData == NULL) {
		SLOGE("[ERR][%s] Failed to allocate memory.", __func__);
		ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
		goto err;
	}
	memset(certDesc->signatureData, 0x00, (sigDataLen + 1));
	memcpy(certDesc->signatureData, x->signature->data, sigDataLen);

err:
	if(x != NULL) X509_free(x);
	if(evp != NULL) EVP_PKEY_free(evp);

	if(tmpIssuerStr != NULL) OPENSSL_free(tmpIssuerStr);
	if(tmpSubjectStr != NULL) OPENSSL_free(tmpSubjectStr);

	if(timeNotBefore != NULL) ASN1_GENERALIZEDTIME_free(timeNotBefore);
	if(timeNotAfter != NULL) ASN1_GENERALIZEDTIME_free(timeNotAfter);

	return ret;
}

int search_data_field(search_field fldName, char* fldData, cert_svc_cert_descriptor* certDesc)
{
	int ret = -1;
	int len = 0;

	switch(fldName) {
		case ISSUER_COUNTRY:
			if(certDesc->info.issuer.countryName) {
				len = strlen((const char*)(certDesc->info.issuer.countryName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.countryName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_STATEORPROVINCE:
			if(certDesc->info.issuer.stateOrProvinceName) {
				len = strlen((const char*)(certDesc->info.issuer.stateOrProvinceName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.stateOrProvinceName), len)) {
					if((int)strlen(fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_LOCALITY:
			if(certDesc->info.issuer.localityName) {
				len = strlen((const char*)(certDesc->info.issuer.localityName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.localityName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_ORGANIZATION:
			if(certDesc->info.issuer.organizationName) {
				len = strlen((const char*)(certDesc->info.issuer.organizationName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.organizationName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_ORGANIZATIONUNIT:
			if(certDesc->info.issuer.organizationUnitName) {
				len = strlen((const char*)(certDesc->info.issuer.organizationUnitName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.organizationUnitName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_COMMONNAME:
			if(certDesc->info.issuer.commonName) {
				len = strlen((const char*)(certDesc->info.issuer.commonName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.commonName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_EMAILADDRESS:
			if(certDesc->info.issuer.emailAddress) {
				len = strlen((const char*)(certDesc->info.issuer.emailAddress));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuer.emailAddress), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case ISSUER_STR:
			if(certDesc->info.issuerStr) {
				len = strlen((const char*)(certDesc->info.issuerStr));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.issuerStr), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_COUNTRY:
			if(certDesc->info.subject.countryName) {
				len = strlen((const char*)(certDesc->info.subject.countryName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.countryName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_STATEORPROVINCE:
			if(certDesc->info.subject.stateOrProvinceName) {
				len = strlen((const char*)(certDesc->info.subject.stateOrProvinceName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.stateOrProvinceName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_LOCALITY:
			if(certDesc->info.subject.localityName) {
				len = strlen((const char*)(certDesc->info.subject.localityName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.localityName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_ORGANIZATION:
			if(certDesc->info.subject.organizationName) {
				len = strlen((const char*)(certDesc->info.subject.organizationName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.organizationName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_ORGANIZATIONUNIT:
			if(certDesc->info.subject.organizationUnitName) {
				len = strlen((const char*)(certDesc->info.subject.organizationUnitName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.organizationUnitName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_COMMONNAME:
			if(certDesc->info.subject.commonName) {
				len = strlen((const char*)(certDesc->info.subject.commonName));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.commonName), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_EMAILADDRESS:
			if(certDesc->info.subject.emailAddress) {
				len = strlen((const char*)(certDesc->info.subject.emailAddress));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subject.emailAddress), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		case SUBJECT_STR:
			if(certDesc->info.subjectStr) {
				len = strlen((const char*)(certDesc->info.subjectStr));
				if(!strncmp((const char*)fldData, (const char*)(certDesc->info.subjectStr), len)) {
					if((int)strlen((const char*)fldData) == len) ret = 1;
					else ret = 0;
				}
				else ret = 0;
			}
			else ret = 0;
			break;
		default:
			ret = 0;
	}

	return ret;
}

int _get_all_certificates(char *const *paths, cert_svc_filename_list **lst) {
    int ret = CERT_SVC_ERR_NO_ERROR;
    FTS *fts = NULL;
    FTSENT *ftsent;

    char tmp[10];
    int len;
    cert_svc_filename_list *local = NULL;
    cert_svc_filename_list *el;

    if (NULL == (fts = fts_open(paths, FTS_LOGICAL, NULL))) {
        ret = CERT_SVC_ERR_FILE_IO;
        SLOGE("[ERR][%s] Fail to open directories.", __func__);
        goto out;
    }

    while ((ftsent = fts_read(fts)) != NULL) {

        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
            ret = CERT_SVC_ERR_FILE_IO;
            SLOGE("[ERR][%s] Fail to read directories.", __func__);
            goto out;
        }

        if (ftsent->fts_info != FTS_F)
            continue;

        if (-1 != readlink(ftsent->fts_path, tmp, 10))
            continue;

        len = strlen((const char *)(ftsent->fts_path));
        if (strcmp((ftsent->fts_path + len - strlen(".pem")), ".pem") != 0
            && strcmp((ftsent->fts_path + len - strlen(".der")), ".der") != 0)
            continue;

        el = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list));
        if (!el) {
            ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
            SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
            goto out;
        }
        el->next = local;
        local = el;

        local->filename = (char*)malloc(len+1);
        if (!local->filename) {
            ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
            SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
            goto out;
        }
        strncpy(local->filename, ftsent->fts_path, len+1);
    }

    *lst = local;
    local = NULL;

out:
    while (local) {
        el = local;
        local = local->next;
        free(el->filename);
        free(el);
    }

    if (fts != NULL)
        fts_close(fts);
    return ret;
}

int get_all_certificates(cert_svc_filename_list** allCerts)
{
    int ret;
    char *buffer[4];

    buffer[0] = ROOT_CA_CERTS_DIR;
    buffer[1] = CERTSVC_DIR;
    buffer[2] = SYSTEM_CERT_DIR;
    buffer[3] = NULL;

    if (!allCerts) {
        SLOGE("[ERR][%s] Invalid argument.", __func__);
        return CERT_SVC_ERR_INVALID_PARAMETER;
    }

    if ((ret = _get_all_certificates(buffer, allCerts)) != CERT_SVC_ERR_NO_ERROR) {
        SLOGE("[ERR][%s] Fail to get filelist.", __func__);
        return ret;
    }

    return CERT_SVC_ERR_NO_ERROR;
}

int _search_certificate(cert_svc_filename_list** fileNames, search_field fldName, char* fldData)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* allCerts = NULL;
	cert_svc_filename_list* p = NULL;
	cert_svc_filename_list* q = NULL;
	cert_svc_filename_list* newNode = NULL;
	cert_svc_mem_buff* certBuf = NULL;
	cert_svc_cert_descriptor* certDesc = NULL;
	int matched = 0;
	struct stat file_info;

	if((ret = get_all_certificates(&allCerts)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get all certificate file list, ret: [%d]", __func__, ret);
		goto err;
	}

	/* if match, store certificate file path into fileNames */
	p = allCerts;

	while(1) {
		if((lstat(p->filename, &file_info)) < 0) {	// get file information
			SLOGE("[ERR][%s] Fail to get file(%s) information.", __func__, p->filename);
			ret = CERT_SVC_ERR_INVALID_OPERATION;
			goto err;
		}
		if((file_info.st_mode & S_IFLNK) == S_IFLNK) {	// if symbolic link, continue
			SLOGD("[LOG][%s] %s is symbolic link, ignored.", __func__, p->filename);
			goto fail_to_load_file;
		}

		// allocate memory
		if(!(certBuf = (cert_svc_mem_buff*)malloc(sizeof(cert_svc_mem_buff)))) {
			SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		// load content into buffer
		if((ret = cert_svc_util_load_file_to_buffer(p->filename, certBuf)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to load file to buffer, filename: [%s], ret: [%d]", __func__, p->filename, ret);
			free(certBuf);
			certBuf = NULL;
			goto fail_to_load_file;
		}

		// allocate memory
		if(!(certDesc = (cert_svc_cert_descriptor*)malloc(sizeof(cert_svc_cert_descriptor)))) {
			SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
			ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
			goto err;
		}

		// load content into descriptor buffer
		if((ret = _extract_certificate_data(certBuf, certDesc)) != CERT_SVC_ERR_NO_ERROR) {
			SLOGE("[ERR][%s] Fail to extract certificate data, filename: [%s], ret: [%d]", __func__, p->filename, ret);
			goto fail_to_extract_file;
		}

		// search
		if(search_data_field(fldName, fldData, certDesc) == 1) {	// found!!
			matched = 1;

			if(!(newNode = (cert_svc_filename_list*)malloc(sizeof(cert_svc_filename_list)))) {
				SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
				ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
				goto err;
			}
			if(!(newNode->filename = (char*)malloc(sizeof(char) * CERT_SVC_MAX_FILE_NAME_SIZE))) {
				SLOGE("[ERR][%s] Fail to allocate memory.", __func__);
				ret = CERT_SVC_ERR_MEMORY_ALLOCATION;
				free(newNode);
				goto err;
			}
			memset(newNode->filename, 0x00, CERT_SVC_MAX_FILE_NAME_SIZE);

			strncpy(newNode->filename, p->filename, CERT_SVC_MAX_FILE_NAME_SIZE - 1);
			newNode->filename[CERT_SVC_MAX_FILE_NAME_SIZE - 1] = '\0';

			newNode->next = NULL;

			if((*fileNames) == NULL)
				(*fileNames) = newNode;
			else {
				q = (*fileNames);
				while(q->next != NULL)
					q = q->next;

				q->next = newNode;
			}
		}

fail_to_extract_file:
		// free allocated memory - certBuf, certDesc
		release_certificate_buf(certBuf);
		certBuf = NULL;
		release_certificate_data(certDesc);
		certDesc = NULL;

fail_to_load_file:
		if(p->next == NULL)
			break;
		p = p->next;
	}

	if(matched != 1) {	// not founded
		SLOGE("[ERR][%s] Cannot find any certificate you want.", __func__);
		ret = CERT_SVC_ERR_NO_MORE_CERTIFICATE;
	}
	else
		ret = CERT_SVC_ERR_NO_ERROR;

err:
	release_certificate_buf(certBuf);
	release_certificate_data(certDesc);
	release_filename_list(allCerts);

	return ret;
}

X509 *__loadCert(const char *file)
{
	FILE *fp = fopen(file, "r");
	if(fp == NULL)
		return NULL;
	X509 *cert;
	if(!(cert = d2i_X509_fp(fp, NULL))) {
		fseek(fp, 0, SEEK_SET);
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
	}
	fclose(fp);
	return cert;
}

int __loadSystemCerts(STACK_OF(X509) *systemCerts)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* allCerts = NULL;
	cert_svc_filename_list* p = NULL;
	struct stat file_info;
	X509 *cert;

	if((ret = get_all_certificates(&allCerts)) != CERT_SVC_ERR_NO_ERROR) {
		SLOGE("[ERR][%s] Fail to get all certificate file list, ret: [%d]", __func__, ret);
		goto err;
	}

	p = allCerts;
	while(1) {
		if((lstat(p->filename, &file_info)) < 0) {	// get file information
			SLOGE("[ERR][%s] Fail to get file(%s) information.", __func__, p->filename);
			ret = CERT_SVC_ERR_INVALID_OPERATION;
			goto err;
		}
		if((file_info.st_mode & S_IFLNK) == S_IFLNK) {	// if symbolic link, continue
//			SLOGD("[LOG][%s] %s is symbolic link, ignored.", __func__, p->filename);
			goto fail_to_load_file;
		}

		cert = __loadCert(p->filename);
		if(cert != NULL) {
		    sk_X509_push(systemCerts, cert);
		}
fail_to_load_file:
		if(p->next == NULL)
			break;
		p = p->next;
	}

	ret = CERT_SVC_ERR_NO_ERROR;
err:
	release_filename_list(allCerts);

	return ret;
}

int release_certificate_buf(cert_svc_mem_buff* certBuf)
{
	int ret = CERT_SVC_ERR_NO_ERROR;

	if(certBuf == NULL)
		return ret;

	if(certBuf->data != NULL) {
		free(certBuf->data);
		certBuf->data = NULL;
	}
	free(certBuf);
	certBuf = NULL;

	return ret;
}

int release_certificate_data(cert_svc_cert_descriptor* certDesc)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	int i = 0;

	if(certDesc == NULL)
		return ret;

	/* parse cert descriptor information fields */
	if(certDesc->info.sigAlgo != NULL) free(certDesc->info.sigAlgo);
	if(certDesc->info.issuerStr != NULL) free(certDesc->info.issuerStr);
	if(certDesc->info.issuer.countryName != NULL) free(certDesc->info.issuer.countryName);
	if(certDesc->info.issuer.localityName != NULL) free(certDesc->info.issuer.localityName);
	if(certDesc->info.issuer.stateOrProvinceName != NULL) free(certDesc->info.issuer.stateOrProvinceName);
	if(certDesc->info.issuer.organizationName != NULL) free(certDesc->info.issuer.organizationName);
	if(certDesc->info.issuer.organizationUnitName != NULL) free(certDesc->info.issuer.organizationUnitName);
	if(certDesc->info.issuer.commonName != NULL) free(certDesc->info.issuer.commonName);
	if(certDesc->info.issuer.emailAddress != NULL) free(certDesc->info.issuer.emailAddress);
	if(certDesc->info.subjectStr != NULL) free(certDesc->info.subjectStr);
	if(certDesc->info.subject.countryName != NULL) free(certDesc->info.subject.countryName);
	if(certDesc->info.subject.localityName != NULL) free(certDesc->info.subject.localityName);
	if(certDesc->info.subject.stateOrProvinceName != NULL) free(certDesc->info.subject.stateOrProvinceName);
	if(certDesc->info.subject.organizationName != NULL) free(certDesc->info.subject.organizationName);
	if(certDesc->info.subject.organizationUnitName != NULL) free(certDesc->info.subject.organizationUnitName);
	if(certDesc->info.subject.commonName != NULL) free(certDesc->info.subject.commonName);
	if(certDesc->info.subject.emailAddress != NULL) free(certDesc->info.subject.emailAddress);
	if(certDesc->info.pubKeyAlgo != NULL) free(certDesc->info.pubKeyAlgo);
	if(certDesc->info.pubKey != NULL) free(certDesc->info.pubKey);
	if(certDesc->info.issuerUID != NULL) free(certDesc->info.issuerUID);
	if(certDesc->info.subjectUID != NULL) free(certDesc->info.subjectUID);

	/* parse cert descriptor extension fields */
	if(certDesc->ext.numOfFields > 0) {
		for(i = 0; i < (int)certDesc->ext.numOfFields; i++) {
			if(certDesc->ext.fields[i].name != NULL) free(certDesc->ext.fields[i].name);
			if(certDesc->ext.fields[i].data != NULL) free(certDesc->ext.fields[i].data);
		}
		if(certDesc->ext.fields != NULL) free(certDesc->ext.fields);
	}

	/* parse signature */
	if(certDesc->signatureAlgo != NULL) free(certDesc->signatureAlgo);
	if(certDesc->signatureData != NULL) free(certDesc->signatureData);

	if(certDesc != NULL) free(certDesc);

	return ret;
}

int release_cert_list(cert_svc_linked_list* certList)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_linked_list* startCert = NULL;
	cert_svc_linked_list* curCert = NULL;

	if(certList == NULL)
		return ret;

	startCert = certList;

	while(1) {
		curCert = startCert;
		startCert = startCert->next;
	
		if(curCert->certificate != NULL) {
			if(curCert->certificate->data != NULL) {
				free(curCert->certificate->data);
				curCert->certificate->data = NULL;
			}
			free(curCert->certificate);
			curCert->certificate = NULL;
		}

		curCert->next = NULL;

		if(curCert != NULL) {
			free(curCert);
			curCert = NULL;
		}

		if(startCert == NULL)
			break;
	}

	return ret;
}

int release_filename_list(cert_svc_filename_list* fileNames)
{
	int ret = CERT_SVC_ERR_NO_ERROR;
	cert_svc_filename_list* startList = NULL;
	cert_svc_filename_list* curList = NULL;

	if(fileNames == NULL)
		return ret;

	startList = fileNames;

	while(1) {
		curList = startList;
		startList = startList->next;

		if(curList->filename != NULL) {
			free(curList->filename);
			curList->filename = NULL;
		}
		curList->next = NULL;
		if(curList != NULL) {
			free(curList);
			curList = NULL;
		}

		if(startList == NULL)
			break;
	}

	return ret;
}
