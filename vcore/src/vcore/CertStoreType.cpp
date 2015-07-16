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
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @file        CertStoreType.cpp
 * @version     1.0
 * @brief       Identification of certificate domain. Certificate domains
 *              were defined in WAC 1.0 documentation. This is a part
 *              should be implemented in wrt-installer.
 */
#include <vcore/CertStoreType.h>

#include <string.h>

namespace ValidationCore {
namespace CertStoreId {

Set::Set()
  : m_certificateStorage(0)
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
  , m_ocspUrl(NULL)
#endif
{}

Set::~Set()
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    delete[] m_ocspUrl;
#endif
}

void Set::add(Type second)
{
    m_certificateStorage |= second;
}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
void Set::add(std::string ocspUrl)
{

    if (ocspUrl.length() == 0)
        return;

    m_ocspUrl = new char[ocspUrl.length() + 1];
    if (m_ocspUrl)
        strncpy(m_ocspUrl, ocspUrl.c_str(), ocspUrl.length() + 1);
}
#endif

bool Set::contains(Type second) const
{
    return static_cast<bool>(m_certificateStorage & second);
}

bool Set::isEmpty() const
{
    return m_certificateStorage == 0;
}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
char* Set::getOcspUrl()
{
    return m_ocspUrl;
}
#endif

} // namespace CertStoreId
} // namespace ValidationCore
