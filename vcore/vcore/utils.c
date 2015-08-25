#include "orig/cert-service.h"
#include "orig/cert-service-debug.h"
#include <cert-svc/cerror.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

void _copy_field(const unsigned char *in, unsigned char **out)
{
	size_t in_len = strlen((const char *)(in));

	*out = (unsigned char *)malloc(sizeof(unsigned char) * (in_len + 1));
	if (!(*out)) {
		LOGE("Failed to allocate memory.");
		return;
	}
	
	memcpy(*out, in, in_len + 1);
}

char *get_complete_path(const char *str1, const char *str2)
{
	size_t str1_len = strlen(str1);
	char *result = NULL;
	int as_result;

	if (str1[str1_len - 1] != '/')
		as_result = asprintf(&result, "%s/%s", str1, str2);
	else
		as_result = asprintf(&result, "%s%s", str1, str2);

	if (as_result < 0)
		return NULL;

	return result;
}


int get_common_name(const char *path, struct x509_st *x509Struct, char **commonName)
{
	int result = CERTSVC_SUCCESS;
	const unsigned char* data = NULL;
	CERT_CONTEXT* context = NULL;
	unsigned char *_commonName = NULL;
	unsigned char *tmpSubjectStr = NULL;
	cert_svc_name_fld_data *certFieldData = NULL;

	if (!path && !x509Struct) {
		LOGE("Invalid input parameter.");
		return  CERTSVC_WRONG_ARGUMENT;
	}

	/* If x509Struct is empty, we need to read the certificate and construct the x509 structure */
	if (!x509Struct) {
		context = cert_svc_cert_context_init();
		if (!context) {
			LOGE("Failed to allocate memory.");
			return CERTSVC_BAD_ALLOC;
		}

		result = cert_svc_load_file_to_context(context, path);
		if (result != CERT_SVC_ERR_NO_ERROR) {
			LOGE("Failed to load file into context.");
			result = CERTSVC_FAIL;
			goto err;
		}

		if (!context->certBuf || !context->certBuf->data) {
			LOGE("Empty certificate buffer.");
			result = CERTSVC_FAIL;
			goto err;
		}

		data = context->certBuf->data;
		d2i_X509(&x509Struct, &data, context->certBuf->size);

		if (!x509Struct) {
			LOGE("[ERR][%s] Fail to construct X509 structure.", __func__);
			result = CERT_SVC_ERR_INVALID_CERTIFICATE;
			goto err;
		}
	}

	/* At this point we assume that we have the x509Struct filled with information */
	tmpSubjectStr = (unsigned char *)X509_NAME_oneline((x509Struct->cert_info->subject), NULL, 0);
	if (!tmpSubjectStr) {
		LOGE("[ERR][%s] Fail to parse certificate.", __func__);
		result = CERTSVC_FAIL;
		goto err;
	}

	certFieldData = (cert_svc_name_fld_data *)malloc(sizeof(cert_svc_name_fld_data));
	if (!certFieldData) {
		LOGE("Failed to allocate memory.");
		result = CERTSVC_BAD_ALLOC;
		goto err;
	}

	certFieldData->commonName = NULL;
	certFieldData->organizationName = NULL;
	certFieldData->organizationUnitName = NULL;
	certFieldData->emailAddress = NULL;

	result = cert_svc_util_parse_name_fld_data(tmpSubjectStr, certFieldData);
	if (result != CERT_SVC_ERR_NO_ERROR) {
		LOGE("[ERR][%s] Fail to parse cert_svc_name_fld_data.", __func__);
		result = CERTSVC_FAIL;
		goto err;
	}

	result = CERTSVC_SUCCESS;

	if (certFieldData->commonName)
		_copy_field(certFieldData->commonName, &_commonName);
	else if (certFieldData->organizationName)
		_copy_field(certFieldData->organizationName, &_commonName);
	else if (certFieldData->organizationUnitName)
		_copy_field(certFieldData->organizationUnitName, &_commonName);
	else if (certFieldData->emailAddress)
		_copy_field(certFieldData->emailAddress, &_commonName);

	if (!_commonName) {
		LOGE("Failed to get common name");
		result = CERTSVC_FAIL;
		goto err;
	}

	*commonName = (char *)_commonName;
	LOGD("Success to get common name for title. commonname[%s]", *commonName);

err:
	if (x509Struct)
		X509_free(x509Struct);

	if (context)
		cert_svc_cert_context_final(context);

	if (tmpSubjectStr)
		OPENSSL_free(tmpSubjectStr);

	if (certFieldData) {
		free(certFieldData->countryName);
		free(certFieldData->localityName);
		free(certFieldData->stateOrProvinceName);
		free(certFieldData->organizationName);
		free(certFieldData->organizationUnitName);
		free(certFieldData->commonName);
		free(certFieldData->emailAddress);
		free(certFieldData);
	}

	return result;
}
