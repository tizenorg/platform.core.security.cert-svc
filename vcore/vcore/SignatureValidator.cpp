/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        SignatureValidator.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementatin of tizen signature validation protocol.
 */

#include <memory>
#include <string>
#include <utility>

#include <dpl/log/log.h>

#include <vcore/CertificateCollection.h>
#include <vcore/Certificate.h>
#include <vcore/ReferenceValidator.h>
#include <vcore/ValidatorFactories.h>
#include <vcore/XmlsecAdapter.h>
#include <vcore/SignatureReader.h>
#include <vcore/SignatureFinder.h>
#include <vcore/Ocsp.h>
#include <vcore/PluginHandler.h>

#include <vcore/SignatureValidator.h>

using namespace ValidationCore::CertStoreId;

namespace {

const std::string TOKEN_PREFIX          = "http://www.w3.org/ns/widgets-digsig#";
const std::string TOKEN_ROLE_AUTHOR_URI = TOKEN_PREFIX + "role-author";
const std::string TOKEN_ROLE_DIST_URI   = TOKEN_PREFIX + "role-distributor";
const std::string TOKEN_PROFILE_URI     = TOKEN_PREFIX + "profile";

enum class CertTimeStatus : int {
	VALID,
	NOT_YET,
	EXPIRED
};

inline time_t _getMidTime(time_t lower, time_t upper)
{
	return (lower >> 1) + (upper >> 1);
}

inline CertTimeStatus _timeValidation(time_t lower, time_t upper, time_t current)
{
	if (current < lower)
		return CertTimeStatus::NOT_YET;
	else if (current > upper)
		return CertTimeStatus::EXPIRED;
	else
		return CertTimeStatus::VALID;
}

inline bool _isTimeStrict(const Set &stores)
{
	return (stores.contains(TIZEN_TEST) || stores.contains(TIZEN_VERIFY))
		? true : false;
}

} // namespace anonymous


namespace ValidationCore {

class SignatureValidator::Impl {
public:
	Impl(const SignatureFileInfo &info);
	virtual ~Impl() {};

	VCerr check(
		const std::string &contentPath,
		bool checkOcsp,
		bool checkReferences,
		SignatureData &outData);

	VCerr checkList(
		const std::string &contentPath,
		const UriList &uriList,
		bool checkOcsp,
		bool checkReferences,
		SignatureData &outData);

	VCerr makeChainBySignature(
		bool completeWithSystemCert,
		CertificateList &certList);

	std::string errorToString(VCerr code);

private:
	VCerr baseCheck(
		const std::string &contentPath,
		bool checkOcsp,
		bool checkReferences);

	VCerr baseCheckList(
		const std::string &contentPath,
		const UriList &uriList,
		bool checkOcsp,
		bool checkReferences);

	VCerr makeDataBySignature(bool completeWithSystemCert);
	VCerr additionalCheck(VCerr result);

	VCerr parseSignature(void);
	VCerr preStep(void);
	bool checkRoleURI(void);
	bool checkProfileURI(void);
	bool checkObjectReferences(void);

	PluginHandler m_pluginHandler;
	SignatureFileInfo m_fileInfo;
	XmlSec::XmlSecContext m_context;
	SignatureData m_data;
	bool m_disregarded;
};


SignatureValidator::Impl::Impl(const SignatureFileInfo &info)
	: m_fileInfo(info)
	, m_disregarded(false)
{
}

bool SignatureValidator::Impl::checkRoleURI(void)
{
	std::string roleURI = m_data.getRoleURI();

	if (roleURI.empty()) {
		LogWarning("URI attribute in Role tag couldn't be empty.");
		return false;
	}

	if (roleURI != TOKEN_ROLE_AUTHOR_URI && m_data.isAuthorSignature()) {
		LogWarning("URI attribute in Role tag does not "
			"match with signature filename.");
		return false;
	}

	if (roleURI != TOKEN_ROLE_DIST_URI && !m_data.isAuthorSignature()) {
		LogWarning("URI attribute in Role tag does not "
			"match with signature filename.");
		return false;
	}
	return true;
}


bool SignatureValidator::Impl::checkProfileURI(void)
{
	if (TOKEN_PROFILE_URI != m_data.getProfileURI()) {
		LogWarning("Profile tag contains unsupported value "
			"in URI attribute " << m_data.getProfileURI());
		return false;
	}
	return true;
}

bool SignatureValidator::Impl::checkObjectReferences(void)
{
	for (const auto &object : m_data.getObjectList()) {
		if (!m_data.containObjectReference(object)) {
			LogWarning("Signature does not contain reference for object " << object);
			return false;
		}
	}

	return true;
}

VCerr SignatureValidator::Impl::additionalCheck(VCerr result)
{
	try {
		if (m_pluginHandler.fail()) {
			LogInfo("No validator plugin found. Skip additional check.");
			return result;
		}

		return m_pluginHandler.step(result, m_data);
	} catch (...) {
		LogError("Exception in additional check by plugin.");
		return E_SIG_PLUGIN;
	}
}

VCerr SignatureValidator::Impl::parseSignature(void)
{
	try {
		SignatureReader xml;
		xml.initialize(m_data, SIGNATURE_SCHEMA_PATH);
		xml.read(m_data);
	} catch (ParserSchemaException::CertificateLoaderError &e) {
		LogError("Certificate loader error: " << e.DumpToString());
		return E_SIG_INVALID_CERT;
	} catch (...) {
		LogError("Failed to parse signature file by signature reader.");
		return E_SIG_INVALID_FORMAT;
	}

	return E_SIG_NONE;
}

/*
 *  Make SignatureData by parsing signature file.
 *  and get certificate chain with attached certificate in signature
 */
VCerr SignatureValidator::Impl::makeDataBySignature(bool completeWithSystemCert)
{
	m_data = SignatureData(m_fileInfo.getFileName(), m_fileInfo.getFileNumber());

	if (parseSignature()) {
		LogError("Failed to parse signature.");
		return E_SIG_INVALID_FORMAT;
	}

	if (!checkRoleURI() || !checkProfileURI())
		return E_SIG_INVALID_FORMAT;

	try {
		CertificateCollection collection;
		collection.load(m_data.getCertList());

		if (!collection.sort() || collection.empty()) {
			LogError("Certificates do not form valid chain.");
			return E_SIG_INVALID_CHAIN;
		}

		if (completeWithSystemCert && !collection.completeCertificateChain()) {
			LogError("Failed to complete cert chain with system cert");
			return E_SIG_INVALID_CHAIN;
		}

		m_data.setSortedCertificateList(collection.getChain());

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return E_SIG_INVALID_CHAIN;
	} catch (const std::exception &e) {
		LogError("std exception occured : " << e.what());
		return E_SIG_UNKNOWN;
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::makeChainBySignature");
		return E_SIG_UNKNOWN;
	}

	return E_SIG_NONE;
}

VCerr SignatureValidator::Impl::preStep(void)
{
	VCerr result = makeDataBySignature(true);
	if (result != E_SIG_NONE)
		return result;

	// Is Root CA certificate trusted?
	Set storeIdSet = createCertificateIdentifier().find(m_data.getCertList().back());

	LogDebug("root certificate from " << storeIdSet.typeToString() << " domain");
	if (m_data.isAuthorSignature()) {
		if (!storeIdSet.contains(TIZEN_DEVELOPER)) {
			LogWarning("author-signature.xml has got unrecognized Root CA certificate. "
				"Signature will be disregarded.");
			m_disregarded = true;
		}
	} else {
		if (storeIdSet.contains(TIZEN_DEVELOPER)) {
			LogError("distributor should not have developer set: "
				<< m_data.getSignatureFileName());
			return E_SIG_INVALID_CHAIN;
		}

		if (m_data.getSignatureNumber() == 1 && !storeIdSet.isContainsVis()) {
			LogWarning("signature1.xml has got unrecognized Root CA certificate. "
				"Signature will be disregarded.");
			m_disregarded = true;
		}
	}

	m_data.setStorageType(storeIdSet);

	/*
	 * We add only Root CA certificate because the rest
	 * of certificates are present in signature files ;-)
	 */
	m_context.signatureFile = m_data.getSignatureFileName();
	m_context.certificatePtr = m_data.getCertList().back();

	/* certificate time check */
	time_t lower = m_data.getEndEntityCertificatePtr()->getNotBefore();
	time_t upper = m_data.getEndEntityCertificatePtr()->getNotAfter();
	time_t current = time(NULL);
	CertTimeStatus status = _timeValidation(lower, upper, current);

	if (status != CertTimeStatus::VALID) {
		if (_isTimeStrict(storeIdSet))
			return status == CertTimeStatus::EXPIRED
					? E_SIG_CERT_EXPIRED : E_SIG_CERT_NOT_YET;

		time_t mid = _getMidTime(lower, upper);
		LogInfo("Use middle notBeforeTime and notAfterTime."
				" lower: " << lower
				<< " upper: " << upper
				<< " mid: " << mid
				<< " current: " << current);
		m_context.validationTime = mid;
	}

	return E_SIG_NONE;
}

VCerr SignatureValidator::Impl::baseCheck(
	const std::string &contentPath,
	bool checkOcsp,
	bool checkReferences)
{
	try {
		VCerr result = preStep();
		if (result != E_SIG_NONE)
			return result;

		if (!m_data.isAuthorSignature()) {
			XmlSecSingleton::Instance().validate(m_context);

			m_data.setReference(m_context.referenceSet);
			if (!checkObjectReferences()) {
				LogWarning("Failed to check Object References");
				return E_SIG_INVALID_REF;
			}

			if (checkReferences) {
				ReferenceValidator fileValidator(contentPath);
				if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(m_data)) {
					LogWarning("Invalid package - file references broken");
					return E_SIG_INVALID_REF;
				}
			}
		}

		if (checkOcsp && Ocsp::check(m_data) == Ocsp::Result::REVOKED) {
			LogError("Certificate is Revoked by OCSP server.");
			return E_SIG_REVOKED;
		}

		LogDebug("Signature validation check done successfully ");

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return E_SIG_INVALID_CHAIN;
	} catch (const XmlSec::Exception::InternalError &e) {
		LogError("XmlSec internal error : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const XmlSec::Exception::InvalidFormat &e) {
		LogError("XmlSec invalid format : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const XmlSec::Exception::InvalidSig &e) {
		LogError("XmlSec invalid signature : " << e.DumpToString());
		return E_SIG_INVALID_SIG;
	} catch (const XmlSec::Exception::OutOfMemory &e) {
		LogError("XmlSec out of memory : " << e.DumpToString());
		return E_SIG_OUT_OF_MEM;
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec unknown exception : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const Ocsp::Exception::Base &e) {
		LogInfo("OCSP will be handled by cert-checker later. : " << e.DumpToString());
		/*
		 *  Don't care ocsp exception here.
		 *  just return signature disregard or verified
		 *  because exception case will be handled by cert-checker after app installed
		 */
	} catch (const std::exception &e) {
		LogError("std exception occured : " << e.what());
		return E_SIG_UNKNOWN;
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::check");
		return E_SIG_UNKNOWN;
	}

	return m_disregarded ? E_SIG_DISREGARDED : E_SIG_NONE;
}

VCerr SignatureValidator::Impl::baseCheckList(
	const std::string &contentPath,
	const UriList &uriList,
	bool checkOcsp,
	bool checkReferences)
{
	try {
		VCerr result = preStep();
		if (result != E_SIG_NONE)
			return result;

		if (uriList.size() == 0)
			XmlSecSingleton::Instance().validateNoHash(m_context);
		else
			XmlSecSingleton::Instance().validatePartialHash(m_context, uriList);

		m_data.setReference(m_context.referenceSet);
		/*
		if (!checkObjectReferences()) {
			LogWarning("Failed to check Object References");
			return E_SIG_INVALID_REF;
		}
		*/

		if (checkReferences) {
			ReferenceValidator fileValidator(contentPath);
			if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(m_data)) {
				LogWarning("Invalid package - file references broken");
				return E_SIG_INVALID_REF;
			}
		}

		if (checkOcsp && Ocsp::check(m_data) == Ocsp::Result::REVOKED) {
			LogError("Certificate is Revoked by OCSP server.");
			return E_SIG_REVOKED;
		}

		LogDebug("Signature validation of check list done successfully ");

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return E_SIG_INVALID_CHAIN;
	} catch (const XmlSec::Exception::InternalError &e) {
		LogError("XmlSec internal error : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const XmlSec::Exception::InvalidFormat &e) {
		LogError("XmlSec invalid format : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const XmlSec::Exception::InvalidSig &e) {
		LogError("XmlSec invalid signature : " << e.DumpToString());
		return E_SIG_INVALID_SIG;
	} catch (const XmlSec::Exception::OutOfMemory &e) {
		LogError("XmlSec out of memory : " << e.DumpToString());
		return E_SIG_OUT_OF_MEM;
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec unknown exception : " << e.DumpToString());
		return E_SIG_INVALID_FORMAT;
	} catch (const Ocsp::Exception::Base &e) {
		LogInfo("OCSP will be handled by cert-checker later. : " << e.DumpToString());
		/*
		 *  Don't care ocsp exception here.
		 *  just return signature disregard or verified
		 *  because exception case will be handled by cert-checker after app installed
		 */
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::checkList");
		return E_SIG_UNKNOWN;
	}

	return m_disregarded ? E_SIG_DISREGARDED : E_SIG_NONE;
}

VCerr SignatureValidator::Impl::check(
	const std::string &contentPath,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	VCerr result;

	result = baseCheck(contentPath, checkOcsp, checkReferences);
	result = additionalCheck(result);

	outData = m_data;

	return result;
}

VCerr SignatureValidator::Impl::checkList(
	const std::string &contentPath,
	const UriList &uriList,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	VCerr result;

	result = baseCheckList(contentPath, uriList, checkOcsp, checkReferences);
	result = additionalCheck(result);

	outData = m_data;

	return result;
}

VCerr SignatureValidator::Impl::makeChainBySignature(
	bool completeWithSystemCert,
	CertificateList &certList)
{
	VCerr result = makeDataBySignature(completeWithSystemCert);
	if (result != E_SIG_NONE)
		return result;

	certList = m_data.getCertList();

	return E_SIG_NONE;
}

std::string SignatureValidator::Impl::errorToString(VCerr code)
{
	switch (code) {
	case E_SIG_NONE:           return "Success.";
	case E_SIG_INVALID_FORMAT: return "Invalid format of signature file.";
	case E_SIG_INVALID_CERT:   return "Invalid format of certificate in signature.";
	case E_SIG_INVALID_CHAIN:  return "Invalid certificate chain with certificate in signature.";
	case E_SIG_INVALID_SIG:    return "Invalid signature. Signed with wrong key, changed signature file or changed package file.";
	case E_SIG_INVALID_REF:    return "Invalid file reference. An unsinged file is found.";
	case E_SIG_CERT_EXPIRED:   return "Certificate in signature is expired.";
	case E_SIG_CERT_NOT_YET:   return "Certificate in signature is not valid yet.";
	case E_SIG_DISREGARDED:    return "Signature validation can be disregarded in some cases.";
	case E_SIG_REVOKED:        return "One of certificate is revoked in certificate chain.";
	case E_SIG_PLUGIN:         return "Failed to load plugin for additional validation check.";
	case E_SIG_OUT_OF_MEM:     return "Out of memory.";
	case E_SIG_UNKNOWN:        return "Unknown error.";
	default:                   return m_pluginHandler.errorToString(code);
	}
}


SignatureValidator::SignatureValidator(const SignatureFileInfo &info)
{
	std::unique_ptr<SignatureValidator::Impl> impl(new(std::nothrow) SignatureValidator::Impl(info))
;
	m_pImpl = std::move(impl);
}
SignatureValidator::~SignatureValidator() {}

std::string SignatureValidator::errorToString(VCerr code)
{
	if (!m_pImpl)
		return "out of memory. error.";

	return m_pImpl->errorToString(code);
}

VCerr SignatureValidator::check(
	const std::string &contentPath,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	if (!m_pImpl)
		return E_SIG_OUT_OF_MEM;

	return m_pImpl->check(
			contentPath,
			checkOcsp,
			checkReferences,
			outData);
}

VCerr SignatureValidator::checkList(
	const std::string &contentPath,
	const UriList &uriList,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	if (!m_pImpl)
		return E_SIG_OUT_OF_MEM;

	return m_pImpl->checkList(
			contentPath,
			uriList,
			checkOcsp,
			checkReferences,
			outData);
}

VCerr SignatureValidator::makeChainBySignature(
	bool completeWithSystemCert,
	CertificateList &certList)
{
	if (!m_pImpl)
		return E_SIG_OUT_OF_MEM;

	return m_pImpl->makeChainBySignature(completeWithSystemCert, certList);
}

} // namespace ValidationCore
