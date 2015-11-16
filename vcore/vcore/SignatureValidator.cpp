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

struct tm _ASN1_GetTimeT(ASN1_TIME *time)
{
	struct tm t;
	const char *str = (const char *)time->data;
	size_t i = 0;

	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) {
		/* two digit year */
		t.tm_year = (str[i] - '0') * 10 + (str[i + 1] - '0');
		i += 2;
		if (t.tm_year < 70)
			t.tm_year += 100;
	} else if (time->type == V_ASN1_GENERALIZEDTIME) {
		/* four digit year */
		t.tm_year =
			(str[i] - '0') * 1000
			+ (str[i + 1] - '0') * 100
			+ (str[i + 2] - '0') * 10
			+ (str[i + 3] - '0');
		i += 4;
		t.tm_year -= 1900;
	}

	t.tm_mon  = (str[i]     - '0') * 10 + (str[i + 1] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i + 2] - '0') * 10 + (str[i + 3] - '0');
	t.tm_hour = (str[i + 4] - '0') * 10 + (str[i + 5] - '0');
	t.tm_min  = (str[i + 6] - '0') * 10 + (str[i + 7] - '0');
	t.tm_sec  = (str[i + 8] - '0') * 10 + (str[i + 9] - '0');

	/* Note: we did not adjust the time based on time zone information */
	return t;
}

struct tm getMidTime(const struct tm &tb, const struct tm &ta)
{
	struct tm tMid;
	memset(&tMid, 0, sizeof(tMid));

	LogDebug("Certificate's notBeforeTime : Year["
		<< (tb.tm_year + 1900)
		<< "] Month[" << (tb.tm_mon + 1)
		<< "] Day[" << tb.tm_mday << "]  ");

	LogDebug("Certificate's notAfterTime : Year["
		<< (ta.tm_year + 1900)
		<< "] Month[" << (ta.tm_mon + 1)
		<< "] Day[" << ta.tm_mday << "]  ");

	int year = (ta.tm_year - tb.tm_year) / 4;

	if (year == 0) {
		tMid.tm_year = tb.tm_year;
		tMid.tm_mon = tb.tm_mon + 1;
		tMid.tm_mday = tb.tm_mday;

		if (tMid.tm_mon == 12) {
			tMid.tm_year = ta.tm_year;
			tMid.tm_mon = ta.tm_mon - 1;
			tMid.tm_mday = ta.tm_mday;

			if (tMid.tm_mon < 0) {
				tMid.tm_year = ta.tm_year;
				tMid.tm_mon = ta.tm_mon;
				tMid.tm_mday = ta.tm_mday - 1;

				if (tMid.tm_mday == 0) {
					tMid.tm_year = tb.tm_year;
					tMid.tm_mon = tb.tm_mon;
					tMid.tm_mday = tb.tm_mday + 1;
				}
			}
		}
	} else {
		tMid.tm_year = tb.tm_year + year;
		tMid.tm_mon = (tb.tm_mon + ta.tm_mon) / 2;
		tMid.tm_mday = (tb.tm_mday + ta.tm_mday) / 2;
	}

	LogDebug("cmp cert with validation time. Year["
		<< (tMid.tm_year + 1900)
		<< "] Month[" << (tMid.tm_mon + 1)
		<< "] Day[" << tMid.tm_mday << "]  ");

	return tMid;
}

inline CertTimeStatus timeValidation(ASN1_TIME *min, ASN1_TIME *max, time_t *cur)
{
	if (X509_cmp_time(min, cur) > 0)
		return CertTimeStatus::NOT_YET;
	else if (X509_cmp_time(max, cur) < 0)
		return CertTimeStatus::EXPIRED;
	else
		return CertTimeStatus::VALID;
}

inline bool isTimeStrict(const Set &stores)
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
		LogDebug("signaturefile name = " << m_data.getSignatureFileName());
		if (storeIdSet.contains(TIZEN_DEVELOPER)) {
			LogError("distributor has author level siganture! "
				"Signature will be disregarded.");
			return E_SIG_INVALID_FORMAT;
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
	ASN1_TIME *notAfterTime = m_data.getEndEntityCertificatePtr()->getNotAfterTime();
	ASN1_TIME *notBeforeTime = m_data.getEndEntityCertificatePtr()->getNotBeforeTime();

	time_t nowTime = time(NULL);

	CertTimeStatus status = timeValidation(notBeforeTime, notAfterTime, &nowTime);
	if (status != CertTimeStatus::VALID) {
		if (isTimeStrict(storeIdSet))
			return status == CertTimeStatus::EXPIRED
					? E_SIG_CERT_EXPIRED : E_SIG_CERT_NOT_YET;

		struct tm tMid = getMidTime(
				_ASN1_GetTimeT(notBeforeTime),
				_ASN1_GetTimeT(notAfterTime));

		m_context.validationTime = mktime(&tMid);
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
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&m_context)) {
				LogWarning("Installation break - invalid package!");
				return E_SIG_INVALID_FORMAT;
			}

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
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec exception : " << e.DumpToString());
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

		if (uriList.size() == 0) {
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validateNoHash(&m_context)) {
				LogWarning("Installation break - invalid package! >> validateNoHash");
				return E_SIG_INVALID_FORMAT;
			}
		} else {
			XmlSecSingleton::Instance().setPartialHashList(uriList);
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validatePartialHash(&m_context)) {
				LogWarning("Installation break - invalid package! >> validatePartialHash");
				return E_SIG_INVALID_FORMAT;
			}
		}

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
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec exception : " << e.DumpToString());
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
	case E_SIG_NONE:           return "E_SIG_NONE";
	case E_SIG_INVALID_FORMAT: return "E_SIG_INVALID_FORMAT";
	case E_SIG_INVALID_CERT:   return "E_SIG_INVALID_CERT";
	case E_SIG_INVALID_CHAIN:  return "E_SIG_INVALID_CHAIN";
	case E_SIG_INVALID_REF:    return "E_SIG_INVALID_REF";
	case E_SIG_CERT_EXPIRED:   return "E_SIG_CERT_EXPIRED";
	case E_SIG_CERT_NOT_YET:   return "E_SIG_CERT_NOT_YET";
	case E_SIG_DISREGARDED:    return "E_SIG_DISREGARDED";
	case E_SIG_REVOKED:        return "E_SIG_REVOKED";
	case E_SIG_PLUGIN:         return "E_SIG_PLUGIN";
	case E_SIG_OUT_OF_MEM:     return "E_SIG_OUT_OF_MEM";
	case E_SIG_UNKNOWN:        return "E_SIG_UNKNOWN";
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

