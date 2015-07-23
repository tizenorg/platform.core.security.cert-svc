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
 * @file        CertificateCollection.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.1
 * @brief
 */

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>

#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cprimitives.h>

#include <dpl/log/log.h>
#include <vcore/Base64.h>

#include <vcore/CertificateCollection.h>

namespace {

using namespace ValidationCore;

inline std::string toBinaryString(int data)
{
    char buffer[sizeof(int)];
    memcpy(buffer, &data, sizeof(int));
    return std::string(buffer, sizeof(int));
}

CertificatePtr getCertFromStore(X509_NAME *subject)
{
    if (!subject) {
        LogError("Invalid input!");
        return CertificatePtr();
    }

    CertSvcInstance instance;
    if (certsvc_instance_new(&instance) != CERTSVC_SUCCESS) {
        LogError("Failed to make instance");
		return CertificatePtr();
    }

    char buffer[1024];
    X509_NAME_oneline(subject, buffer, 1024);

    LogDebug("Search certificate with subject: " << buffer);
	CertSvcCertificateList certList;
	int result = certsvc_certificate_search(instance, CERTSVC_SUBJECT, buffer, &certList);
    if (result != CERTSVC_SUCCESS) {
        LogError("Error during certificate search. result : " << result);
		certsvc_instance_free(instance);
        return CertificatePtr();
    }

	size_t listSize = 0;
	result = certsvc_certificate_list_get_length(certList, &listSize);
	if (result != CERTSVC_SUCCESS || listSize <= 0) {
		LogError("Error in certsvc_certificate_list_get_length. result : " << result);
		certsvc_instance_free(instance);
		return CertificatePtr();
	}

	CertSvcCertificate cert;
	result = certsvc_certificate_list_get_one(certList, 0, &cert);
	if (result != CERTSVC_SUCCESS) {
		LogError("Failed to get cert from cert list. result : " << result);
		certsvc_certificate_list_all_free(certList);
		certsvc_instance_free(instance);
		return CertificatePtr();
	}

	X509 *pCertX509 = NULL;
	result = certsvc_certificate_dup_x509(cert, &pCertX509);
	certsvc_certificate_list_all_free(certList);
	certsvc_instance_free(instance);

    if (result != CERTSVC_SUCCESS || !pCertX509) {
        LogError("Error during certificate dup x509. result : " << result);
        return CertificatePtr();
    }

    CertificatePtr parentCert(new Certificate(pCertX509));
    X509_free(pCertX509);

    return parentCert;
}
} // namespace

namespace ValidationCore {

CertificateCollection::CertificateCollection()
  : m_collectionStatus(COLLECTION_UNSORTED)
{}

void CertificateCollection::clear(void)
{
    m_collectionStatus = COLLECTION_UNSORTED;
    m_certList.clear();
}

void CertificateCollection::load(const CertificateList &certList)
{
    m_collectionStatus = COLLECTION_UNSORTED;
    std::copy(certList.begin(),
              certList.end(),
              std::back_inserter(m_certList));
}

std::string CertificateCollection::toBase64String() const
{
    std::ostringstream output;
    int certNum = m_certList.size();
    output << toBinaryString(certNum);

    for (auto i = m_certList.begin(); i != m_certList.end(); ++i) {
        std::string derCert = (*i)->getDER();
        output << toBinaryString(derCert.size());
        output << derCert;
    }
    Base64Encoder base64;
    base64.reset();
    base64.append(output.str());
    base64.finalize();
    return base64.get();
}

CertificateList CertificateCollection::getCertificateList() const
{
    return m_certList;
}

bool CertificateCollection::isChain() const
{
    if (COLLECTION_SORTED != m_collectionStatus)
        VcoreThrowMsg(CertificateCollection::Exception::WrongUsage,
                      "You must sort certificate first");

    return (COLLECTION_SORTED == m_collectionStatus) ? true : false;
}

bool CertificateCollection::sort()
{
    if (COLLECTION_UNSORTED == m_collectionStatus) {
        sortCollection();
    }
    return (COLLECTION_SORTED == m_collectionStatus) ? true : false;
}

CertificateList CertificateCollection::getChain() const
{
    if (COLLECTION_SORTED != m_collectionStatus)
        VcoreThrowMsg(CertificateCollection::Exception::WrongUsage,
                      "You must sort certificates first");

    return m_certList;
}

void CertificateCollection::sortCollection()
{
    // sorting is not necessary
    if (m_certList.empty()) {
        m_collectionStatus = COLLECTION_SORTED;
        return;
    }

    CertificateList sorted;
    std::map<std::string, CertificatePtr> subTransl;
    std::map<std::string, CertificatePtr> issTransl;

    // Sort all certificate by subject
    for (auto it = m_certList.begin(); it != m_certList.end(); ++it) {
        subTransl.insert(std::make_pair((*it)->getOneLine(), (*it)));
    }
    // We need one start certificate
    sorted.push_back(subTransl.begin()->second);
    subTransl.erase(subTransl.begin());

    // Get the issuer from front certificate and find certificate with this subject in subTransl.
    // Add this certificate to the front.
    while (!subTransl.empty()) {
        std::string issuer = sorted.back()->getOneLine(Certificate::FIELD_ISSUER);
        auto it = subTransl.find(issuer);
        if (it == subTransl.end()) {
            break;
        }
        sorted.push_back(it->second);
        subTransl.erase(it);
    }

    // Sort all certificates by issuer
    for (auto it = subTransl.begin(); it != subTransl.end(); ++it) {
        issTransl.insert(std::make_pair(it->second->getOneLine(Certificate::FIELD_ISSUER), it->second));
    }

    // Get the subject from last certificate and find certificate with such issuer in issTransl.
    // Add this certificate at end.
    while (!issTransl.empty()) {
        std::string sub = sorted.front()->getOneLine();
        auto it = issTransl.find(sub);
        if (it == issTransl.end()) {
            break;
        }
        sorted.push_front(it->second);
        issTransl.erase(it);
    }

    if (!issTransl.empty()) {
        LogWarning("Certificates don't form a valid chain.");
        m_collectionStatus = COLLECTION_CHAIN_BROKEN;
        return;
    }

    m_collectionStatus = COLLECTION_SORTED;
    m_certList = sorted;
}

/*
 *  Precondition : cert list sorted and has more than one cert
 */
bool CertificateCollection::completeCertificateChain()
{
    CertificatePtr last = m_certList.back();
    if (last->isSignedBy(last))
        return true;

    /* TODO Add getIssuerName function to Certificate.h */
    CertificatePtr parent = getCertFromStore(X509_get_issuer_name(last->getX509()));

    if (!parent.get())
        return false;

    m_certList.push_back(parent);
    if (!parent->isSignedBy(parent))
        return false;

    return true;
}

size_t CertificateCollection::size() const {
    return m_certList.size();
}

bool CertificateCollection::empty() const {
    return m_certList.empty();
}

CertificateCollection::const_iterator CertificateCollection::begin() const {
    return m_certList.begin();
}

CertificateCollection::const_iterator CertificateCollection::end() const {
    return m_certList.end();
}

CertificatePtr CertificateCollection::back() const {
    return m_certList.back();
}

} // namespace ValidationCore

