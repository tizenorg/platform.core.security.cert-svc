/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *
 * @file        CertificateCollection.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Handles certificate chain, make it complete and sort
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <dirent.h>

#include <memory>
#include <functional>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cprimitives.h>

#include <dpl/log/log.h>

#include "vcore/Base64.h"

#include "vcore/CertificateCollection.h"

namespace {

using namespace ValidationCore;

inline std::string toBinaryString(int data)
{
    char buffer[sizeof(int)];
    memcpy(buffer, &data, sizeof(int));
    return std::string(buffer, sizeof(int));
}

CertificatePtr searchCertByHash(const std::string &dir, const CertificatePtr &certPtr)
{
	try {
		std::string hash = certPtr->getNameHash(Certificate::FIELD_ISSUER);

		std::unique_ptr<DIR, std::function<int(DIR*)>> dp(::opendir(dir.c_str()), ::closedir);
		if (dp.get() == NULL) {
			LogError("Failed open dir[" << dir << "]");
			return CertificatePtr();
		}

		size_t len = offsetof(struct dirent, d_name) + pathconf(dir.c_str(), _PC_NAME_MAX) + 1;
		std::unique_ptr<struct dirent, std::function<void(void*)>>
			pEntry(static_cast<struct dirent *>(::malloc(len)), ::free);

		struct dirent *dirp = NULL;
		int ret = 0;
		while ((ret = readdir_r(dp.get(), pEntry.get(), &dirp)) == 0 && dirp) {
			if (dirp->d_type == DT_DIR)
				continue;

			/* filename length should be 10. ex) 1a2b3c4d.1 */
			if (strlen(dirp->d_name) != 10)
				continue;

			if (strncmp(dirp->d_name, hash.c_str(), 8) != 0)
				continue;

			LogDebug("Found hash matched file! : " << (dir + dirp->d_name));

			CertificatePtr candidate = Certificate::createFromFile(dir + dirp->d_name);
			if (candidate->getOneLine().compare(certPtr->getOneLine(Certificate::FIELD_ISSUER)) != 0)
				continue;

			return candidate;
		}

		if (ret != 0) {
			LogError("readdir_r error. ret[" << ret << "]");
			return CertificatePtr();
		}

		LogWarning("cert not found by hash[" << hash << "]");
		return CertificatePtr();

	} catch (const Certificate::Exception::Base &e) {
		VcoreThrowMsg(
			CertificateCollection::Exception::CertificateError,
			"Error in handling certificate : " << e.DumpToString());
	} catch (const std::exception &e) {
		VcoreThrowMsg(
			CertificateCollection::Exception::InternalError,
			"std::exception occured : " << e.what());
	} catch (...) {
		VcoreThrowMsg(
			CertificateCollection::Exception::InternalError,
			"Unknown exception in CertificateCollection.");
	}


}

CertificatePtr getIssuerCertFromStore(const CertificatePtr &certPtr)
{
	return searchCertByHash(SYSTEM_CERT_DIR, certPtr);
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
    if (last->isRootCert())
        return true;

    CertificatePtr rootCert = getIssuerCertFromStore(last);

    if (!rootCert.get())
        return false;

    if (!rootCert->isRootCert())
        return false;

    m_certList.push_back(rootCert);
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

