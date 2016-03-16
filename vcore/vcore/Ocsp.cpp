/*
 *  Copyright (c) 2015 Samsung Electronics Co.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        Ocsp.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       OCSP check for signature validator. It should be used only internally.
 */

#include <memory>
#include <functional>

#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>

#include <dpl/log/log.h>
#include <vcore/CryptoInit.h>

#include <vcore/Ocsp.h>

/* Maximum leeway in validity period : 5 minitues as a default */
#define MAX_VALIDITY_PERIOD (5 * 60)

namespace {

typedef std::unique_ptr<X509_STORE_CTX, std::function<void(X509_STORE_CTX *)>> X509_STORE_CTX_PTR;
typedef std::unique_ptr<STACK_OF(X509), std::function<void(STACK_OF(X509) *)>> X509_STACK_PTR;
typedef std::unique_ptr<X509_STORE,     std::function<void(X509_STORE *)>> X509_STORE_PTR;
typedef std::unique_ptr<SSL_CTX,        std::function<void(SSL_CTX *)>> SSL_CTX_PTR;
typedef std::unique_ptr<BIO,            std::function<void(BIO *)>> BIO_PTR;
typedef std::unique_ptr<char,           std::function<void(void *)>> RAIIstr;
typedef std::unique_ptr<OCSP_REQUEST,   std::function<void(OCSP_REQUEST *)>> OCSP_REQUEST_PTR;
typedef std::unique_ptr<OCSP_RESPONSE,  std::function<void(OCSP_RESPONSE *)>> OCSP_RESPONSE_PTR;
typedef std::unique_ptr<OCSP_BASICRESP, std::function<void(OCSP_BASICRESP *)>> OCSP_BASICRESP_PTR;

inline X509_STACK_PTR create_x509_stack()
{
	return X509_STACK_PTR(sk_X509_new_null(), [](STACK_OF(X509) * stack) {
		sk_X509_free(stack);
	});
}

inline X509_STORE_CTX_PTR create_x509_store_ctx()
{
	return X509_STORE_CTX_PTR(X509_STORE_CTX_new(), X509_STORE_CTX_free);
}

inline X509_STORE_PTR create_x509_store()
{
	return X509_STORE_PTR(X509_STORE_new(), X509_STORE_free);
}

inline SSL_CTX_PTR create_SSL_CTX()
{
	return SSL_CTX_PTR(SSL_CTX_new(SSLv23_client_method()), SSL_CTX_free);
}

inline RAIIstr create_RAIIstr(char *str)
{
	return RAIIstr(str, [](void * ptr) {
		OPENSSL_free(ptr);
	});
}

inline BIO_PTR create_BIO(BIO *bio)
{
	return BIO_PTR(bio, BIO_free_all);
}

inline OCSP_REQUEST_PTR create_OCSP_REQUEST()
{
	return OCSP_REQUEST_PTR(OCSP_REQUEST_new(), OCSP_REQUEST_free);
}

inline OCSP_RESPONSE_PTR create_OCSP_RESPONSE(OCSP_RESPONSE *resp)
{
	return OCSP_RESPONSE_PTR(resp, OCSP_RESPONSE_free);
}

inline OCSP_BASICRESP_PTR create_OCSP_BASICRESP(OCSP_BASICRESP *basicResp)
{
	return OCSP_BASICRESP_PTR(basicResp, OCSP_BASICRESP_free);
}

void BIO_write_and_free(BIO *bio)
{
	if (!bio)
		return;

	std::vector<char> message(1024);
	int size = BIO_read(bio, message.data(), message.size());
	if (size > 0) {
		message.resize(size);
		LogError("OCSP error description ["
				 << std::string(message.begin(), message.end()) << "]");
	}

	BIO_free_all(bio);
}

} // namespace anonymous

namespace ValidationCore {

Ocsp::Ocsp()
{
}

Ocsp::~Ocsp()
{
}

Ocsp::Result checkInternal(
	const CertificatePtr &_cert,
	const CertificatePtr &_issuer,
	X509_STACK_PTR &trustedCerts)
{
	/* initialize openssl library */
	CryptoInitSingleton::Instance();

	BIO_PTR bioLogger(BIO_new(BIO_s_mem()), BIO_write_and_free);

	X509 *cert = _cert->getX509();
	X509 *issuer = _issuer->getX509();
	std::string ocspUrl = _cert->getOCSPURL();

	if (ocspUrl.empty())
		VcoreThrowMsg(Ocsp::Exception::OcspUnsupported,
					  "Certificate[" << _cert->getOneLine() << "] doesn't provide OCSP extension");

	char *_ocspUrl = new char[ocspUrl.length() + 1];
	if (_ocspUrl == NULL)
		VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to alloc memory");
	strncpy(_ocspUrl, ocspUrl.c_str(), ocspUrl.length() + 1);

	char *_host = NULL;
	char *_port = NULL;
	char *_path = NULL;
	int use_ssl = 0;

	int temp = OCSP_parse_url(_ocspUrl, &_host, &_port, &_path, &use_ssl);

	LogDebug("ocspUrl[" << _ocspUrl
			 << "] host[" << _host
			 << "] port[" << _port
			 << "] path[" << _path
			 << "] use_ssl[" << use_ssl << "]");

	delete []_ocspUrl;

	if (temp == 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidUrl, "ocsp url parsing failed. url : " << ocspUrl);
	}

	RAIIstr host = create_RAIIstr(_host);
	RAIIstr port = create_RAIIstr(_port);
	RAIIstr path = create_RAIIstr(_path);

	BIO_PTR cbio = create_BIO(BIO_new_connect(host.get()));
	if (cbio.get() == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to create bio connect");
	}

	if (port)
		BIO_set_conn_port(cbio.get(), port.get());

	if (use_ssl == 1) {
		SSL_CTX_PTR ssl_ctx = create_SSL_CTX();
		if (ssl_ctx.get() == NULL) {
			ERR_print_errors(bioLogger.get());
			VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to SSL_CTX_new");
		}

		SSL_CTX_set_mode(ssl_ctx.get(), SSL_MODE_AUTO_RETRY);

		BIO_PTR sbio = create_BIO(BIO_new_ssl(ssl_ctx.get(), 1));
		if (sbio.get() == NULL) {
			ERR_print_errors(bioLogger.get());
			VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to BIO_new_ssl");
		}

		cbio.reset(BIO_push(sbio.get(), cbio.get()));
		if (cbio.get() == NULL) {
			ERR_print_errors(bioLogger.get());
			VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to BIO_push");
		}
	}

	if (BIO_do_connect(cbio.get()) <= 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::NetworkError, "Failed to BIO_do_connect");
	}

	OCSP_REQUEST_PTR req = create_OCSP_REQUEST();
	if (req.get() == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to OCSP_REQUEST_new");
	}

	OCSP_CERTID *certid = OCSP_cert_to_id(NULL, cert, issuer);
	if (certid == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to OCSP_cert_to_id");
	}

	if (OCSP_request_add0_id(req.get(), certid) == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::UnknownError, "Failed to OCSP_request_add0_id");
	}

	OCSP_RESPONSE_PTR resp =
		create_OCSP_RESPONSE(OCSP_sendreq_bio(cbio.get(), path.get(), req.get()));

	if (resp.get() == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::NetworkError, "Failed to OCSP_sendreq_bio");
	}

	if (OCSP_response_status(resp.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::ServerError, "Failed to OCSP_response_status");
	}

	OCSP_BASICRESP_PTR basicResp =
		create_OCSP_BASICRESP(OCSP_response_get1_basic(resp.get()));
	if (basicResp.get() == NULL) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "Failed to OCSP_response_get1_basic");
	}

	X509_STORE_PTR trustedStore = create_x509_store();
	if (trustedCerts.get()) {
		for (int idx = 0; idx < sk_X509_num(trustedCerts.get()); idx++)
			X509_STORE_add_cert(trustedStore.get(), sk_X509_value(trustedCerts.get(), idx));
		X509_STORE_add_cert(trustedStore.get(), issuer);
	}

	if (OCSP_basic_verify(basicResp.get(), NULL, trustedStore.get(), 0) <= 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "Failed to OCSP_basic_verify");
	}

	if (OCSP_check_nonce(req.get(), basicResp.get()) == 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "nonce exists but not equal");
	}

	int ocspStatus = -1;
	int reason = 0;
	ASN1_GENERALIZEDTIME *rev = NULL;
	ASN1_GENERALIZEDTIME *thisupd = NULL;
	ASN1_GENERALIZEDTIME *nextupd = NULL;
	if (OCSP_resp_find_status(
				basicResp.get(),
				certid,
				&ocspStatus,
				&reason,
				&rev,
				&thisupd,
				&nextupd) == 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "Failed to OCSP_resp_find_status");
	}

	if (OCSP_check_validity(thisupd, nextupd, MAX_VALIDITY_PERIOD, -1) == 0) {
		ERR_print_errors(bioLogger.get());
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "Failed to OCSP_check_validity");
	}

	if (ocspStatus != V_OCSP_CERTSTATUS_GOOD && ocspStatus != V_OCSP_CERTSTATUS_REVOKED)
		VcoreThrowMsg(Ocsp::Exception::InvalidResponse, "Unknown ocsp status.");

	return ocspStatus == V_OCSP_CERTSTATUS_GOOD ?
		   Ocsp::Result::GOOD : Ocsp::Result::REVOKED;
}

Ocsp::Result Ocsp::check(const SignatureData &data)
{
	if (!data.isCertListSorted())
		VcoreThrowMsg(Exception::InvalidParam, "cert list should be sorted");

	const CertificateList &certChain = data.getCertList();
	if (certChain.size() < 3)
		VcoreThrowMsg(Exception::InvalidParam, "cert chain is too short");

	X509_STACK_PTR trustedCerts = create_x509_stack();

	auto it = certChain.cbegin();
	it++;
	it++;
	/* don't trust the user cert and the first intermediate CA cert */
	for (; it != certChain.cend(); it++) {
		const auto &cert = it->get();

		if (cert->getDER().empty())
			VcoreThrowMsg(Exception::InvalidParam, "Broken certificate chain.");

		sk_X509_push(trustedCerts.get(), cert->getX509());
	}

	auto itCert = certChain.cbegin();
	auto itIssuer = certChain.cbegin();
	itIssuer++;
	/* check ocsp except except self-signed root CA cert */
	for (; itIssuer != certChain.end(); itCert++, itIssuer++) {
		if (checkInternal(*itCert, *itIssuer, trustedCerts) == Result::REVOKED)
			return Result::REVOKED;

		LogDebug("ocsp status good for cert : " << (*itCert)->getOneLine());
	}

	return Result::GOOD;
}

}
