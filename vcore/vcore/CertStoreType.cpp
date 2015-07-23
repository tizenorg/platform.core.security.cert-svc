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

namespace ValidationCore {
namespace CertStoreId {

Set::Set()
  : m_certificateStorage(0)
{}

Set::~Set()
{
}

void Set::setType(Type type)
{
    m_certificateStorage = type;
}

Type Set::getType() const
{
    return m_certificateStorage;
}

std::string Set::getTypeString() const
{
    switch (m_certificateStorage) {
    case TIZEN_DEVELOPER:
        return std::string("TIZEN_DEVELOPER");
    case TIZEN_TEST:
        return std::string("TIZEN_TEST");
    case TIZEN_VERIFY:
        return std::string("TIZEN_VERIFY");
    case TIZEN_STORE:
        return std::string("TIZEN_STORE");
    case VIS_PUBLIC:
        return std::string("VIS_PUBLIC");
    case VIS_PARTNER:
        return std::string("VIS_PARTNER");
    case VIS_PARTNER_OPERATOR:
        return std::string("VIS_PARTNER_OPERATOR");
    case VIS_PARTNER_MANUFACTURER:
        return std::string("VIS_PARTNER_MANUFACTURER");
    case VIS_PLATFORM:
        return std::string("VIS_PLATFORM");
    default:
        return std::string();
    }
}

bool Set::isVisibilityLevel() const
{
    if (m_certificateStorage < VIS_PUBLIC)
        return false;

    return true;
}

bool Set::isEmpty() const
{
    return m_certificateStorage == 0;
}

} // namespace CertStoreId
} // namespace ValidationCore
