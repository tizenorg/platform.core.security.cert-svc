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

#include <dpl/log/log.h>

#include <vcore/CertificateCollection.h>
#include <vcore/Certificate.h>
#include <vcore/ReferenceValidator.h>
#include <vcore/ValidatorFactories.h>
#include <vcore/XmlsecAdapter.h>
#include <vcore/SignatureReader.h>
#include <vcore/SignatureFinder.h>
#include <vcore/Ocsp.h>

#include <vcore/SignatureValidator.h>

namespace {

const std::string TOKEN_ROLE_AUTHOR_URI =
	"http://www.w3.org/ns/widgets-digsig#role-author";
const std::string TOKEN_ROLE_DISTRIBUTOR_URI =
	"http://www.w3.org/ns/widgets-digsig#role-distributor";
const std::string TOKEN_PROFILE_URI =
	"http://www.w3.org/ns/widgets-digsig#profile";

static tm _ASN1_GetTimeT(ASN1_TIME *time)
{
	struct tm t;
	const char* str = (const char *)time->data;
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

static bool checkRoleURI(const ValidationCore::SignatureData &data)
{
	std::string roleURI = data.getRoleURI();

	if (roleURI.empty()) {
		LogWarning("URI attribute in Role tag couldn't be empty.");
		return false;
	}

	if (roleURI != TOKEN_ROLE_AUTHOR_URI && data.isAuthorSignature()) {
		LogWarning("URI attribute in Role tag does not "
			"match with signature filename.");
		return false;
	}

	if (roleURI != TOKEN_ROLE_DISTRIBUTOR_URI && !data.isAuthorSignature()) {
		LogWarning("URI attribute in Role tag does not "
			"match with signature filename.");
		return false;
	}
	return true;
}

static bool checkProfileURI(const ValidationCore::SignatureData &data)
{
	if (TOKEN_PROFILE_URI != data.getProfileURI()) {
		LogWarning("Profile tag contains unsupported value "
			"in URI attribute " << data.getProfileURI());
		return false;
	}
	return true;
}

static bool checkObjectReferences(const ValidationCore::SignatureData &data)
{
	ValidationCore::ObjectList objectList = data.getObjectList();
	ValidationCore::ObjectList::const_iterator iter;
	for (iter = objectList.begin(); iter != objectList.end(); ++iter) {
		if (!data.containObjectReference(*iter)) {
			LogWarning("Signature does not contain reference for object " << *iter);
			return false;
		}
	}
	return true;
}

static struct tm getMidTime(const struct tm &tb, const struct tm &ta)
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

} // namespace anonymous



namespace ValidationCore {

/*
 *  Prepare to check / checklist. parse xml and save info to signature data.
 *
 *  [out] outData  : signature data for validating and will be finally returned to client.
 */
int prepareToCheck(SignatureData &outData)
{
	try {
		SignatureReader xml;
		xml.initialize(outData, SIGNATURE_SCHEMA_PATH);
		xml.read(outData);
	} catch (...) {
		LogError("Failed to parse signature file by signature reader.");
		return -1;
	}

	return 0;
}

/*
 *  Make SignatureData by parsing signature file.
 *  and get certificate chain with attached certificate in signature
 */
static int makeDataBySignature(
	const SignatureFileInfo &fileInfo,
	bool completeWithSystemCert,
	SignatureData &data)
{
	data = SignatureData(fileInfo.getFileName(), fileInfo.getFileNumber());

	if (prepareToCheck(data)) {
		LogError("Failed to prepare to check.");
		return -1;
	}

	if (!checkRoleURI(data) || !checkProfileURI(data))
		return -1;

	try {
		CertificateCollection collection;
		collection.load(data.getCertList());

		if (!collection.sort() || collection.empty()) {
			LogError("Certificates do not form valid chain.");
			return -1;
		}

		if (completeWithSystemCert && !collection.completeCertificateChain()) {
			LogError("Failed to complete cert chain with system cert");
			return -1;
		}

		data.setSortedCertificateList(collection.getChain());
		return 0;

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return -1;
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::makeChainBySignature");
		return -1;
	}
}

/*
 *  Same logic (check, checkList) is functionalized here.
 *
 *  [in]  fileInfo  : file info of signature to check
 *  [out] disregard : distributor signature disregard flag.
 *  [out] context   : xml sec for validating.
 *  [out] data      : signature data for validationg and will be finally returned to client.
 */
static SignatureValidator::Result checkInternal(
	const SignatureFileInfo &fileInfo,
	bool &disregard,
	XmlSec::XmlSecContext &context,
	SignatureData &data)
{
	if (makeDataBySignature(fileInfo, true, data))
		return SignatureValidator::SIGNATURE_INVALID;

	// Is Root CA certificate trusted?
	CertStoreId::Set storeIdSet = createCertificateIdentifier().find(data.getCertList().back());

	LogDebug("root certificate from " << storeIdSet.typeToString() << " domain");
	if (data.isAuthorSignature()) {
		if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER)) {
			LogWarning("author-signature.xml has got unrecognized Root CA "
				"certificate. Signature will be disregarded.");
			disregard = true;
		}
	} else {
		LogDebug("signaturefile name = " << data.getSignatureFileName());
		if (storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER)) {
			LogError("distributor has author level siganture! Signature will be disregarded.");
			return SignatureValidator::SIGNATURE_INVALID;
		}

		if (data.getSignatureNumber() == 1 && !storeIdSet.isContainsVis()) {
			LogWarning("signature1.xml has got unrecognized Root CA "
				"certificate. Signature will be disregarded.");
			disregard = true;
		}
	}

	data.setStorageType(storeIdSet);

	/*
	 * We add only Root CA certificate because the rest
	 * of certificates are present in signature files ;-)
	 */
	context.signatureFile = data.getSignatureFileName();
	context.certificatePtr = data.getCertList().back();

	/* certificate time check */
	ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
	ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

	time_t nowTime = time(NULL);

	if (X509_cmp_time(notBeforeTime, &nowTime) > 0  || X509_cmp_time(notAfterTime, &nowTime) < 0) {
		if (storeIdSet.contains(CertStoreId::TIZEN_TEST) || storeIdSet.contains(CertStoreId::TIZEN_VERIFY)) {
			LogError("TIZEN_VERIFY : check certificate Time : FALSE");
			return SignatureValidator::SIGNATURE_INVALID;
		}

		struct tm tMid = getMidTime(_ASN1_GetTimeT(notBeforeTime), _ASN1_GetTimeT(notAfterTime));

		context.validationTime = mktime(&tMid);
	}

	return SignatureValidator::SIGNATURE_VERIFIED;
}

SignatureValidator::Result SignatureValidator::check(
	const SignatureFileInfo &fileInfo,
	const std::string &widgetContentPath,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	bool disregard = false;

	try {
		XmlSec::XmlSecContext context;
		Result result = checkInternal(fileInfo, disregard, context, outData);
		if (result != SIGNATURE_VERIFIED)
			return result;

		if (!outData.isAuthorSignature()) {
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&context)) {
				LogWarning("Installation break - invalid package!");
				return SIGNATURE_INVALID;
			}

			outData.setReference(context.referenceSet);
			if (!checkObjectReferences(outData)) {
				LogWarning("Failed to check Object References");
				return SIGNATURE_INVALID;
			}

			if (checkReferences) {
				ReferenceValidator fileValidator(widgetContentPath);
				if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(outData)) {
					LogWarning("Invalid package - file references broken");
					return SIGNATURE_INVALID;
				}
			}
		}

		if (checkOcsp && Ocsp::check(outData) == Ocsp::Result::REVOKED)
			return SIGNATURE_REVOKED;

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return SIGNATURE_INVALID;
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec exception : " << e.DumpToString());
		return SIGNATURE_INVALID;
	} catch (const Ocsp::Exception::Base &e) {
		LogError("Ocsp exception : " << e.DumpToString());
		/*
		 *  Don't care ocsp exception here.
		 *  just return signature disregard or verified
		 *  because exception case will be handled by cert-checker after app installed
		 */
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::check");
		return SIGNATURE_INVALID;
	}

	return disregard ? SIGNATURE_DISREGARD : SIGNATURE_VERIFIED;
}

SignatureValidator::Result SignatureValidator::checkList(
	const SignatureFileInfo &fileInfo,
	const std::string &widgetContentPath,
	const std::list<std::string> &uriList,
	bool checkOcsp,
	bool checkReferences,
	SignatureData &outData)
{
	bool disregard = false;

	try {
		XmlSec::XmlSecContext context;
		Result result = checkInternal(fileInfo, disregard, context, outData);
		if (result != SIGNATURE_VERIFIED)
			return result;

		if (uriList.size() == 0) {
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validateNoHash(&context)) {
				LogWarning("Installation break - invalid package! >> validateNoHash");
				return SIGNATURE_INVALID;
			}
		} else {
			XmlSecSingleton::Instance().setPartialHashList(uriList);
			if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validatePartialHash(&context)) {
				LogWarning("Installation break - invalid package! >> validatePartialHash");
				return SIGNATURE_INVALID;
			}
		}

		outData.setReference(context.referenceSet);
		/*
		if (!checkObjectReferences(outData)) {
			LogWarning("Failed to check Object References");
			return SIGNATURE_INVALID;
		}
		*/

		if (checkReferences) {
			ReferenceValidator fileValidator(widgetContentPath);
			if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(outData)) {
				LogWarning("Invalid package - file references broken");
				return SIGNATURE_INVALID;
			}
		}

		if (checkOcsp && Ocsp::check(outData) == Ocsp::Result::REVOKED)
			return SIGNATURE_REVOKED;

	} catch (const CertificateCollection::Exception::Base &e) {
		LogError("CertificateCollection exception : " << e.DumpToString());
		return SIGNATURE_INVALID;
	} catch (const XmlSec::Exception::Base &e) {
		LogError("XmlSec exception : " << e.DumpToString());
		return SIGNATURE_INVALID;
	} catch (const Ocsp::Exception::Base &e) {
		LogError("Ocsp exception : " << e.DumpToString());
		/*
		 *  Don't care ocsp exception here.
		 *  just return signature disregard or verified
		 *  because exception case will be handled by cert-checker after app installed
		 */
	} catch (...) {
		LogError("Unknown exception in SignatureValidator::checkList");
		return SIGNATURE_INVALID;
	}

	return disregard ? SIGNATURE_DISREGARD : SIGNATURE_VERIFIED;
}

SignatureValidator::Result SignatureValidator::makeChainBySignature(
	const SignatureFileInfo &fileInfo,
	bool completeWithSystemCert,
	CertificateList &certList)
{
	SignatureData data;
	if (makeDataBySignature(fileInfo, completeWithSystemCert, data))
		return SIGNATURE_INVALID;

	certList = data.getCertList();

	return SIGNATURE_VALID;
}


} // namespace ValidationCore

