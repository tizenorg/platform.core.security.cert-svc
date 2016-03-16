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

void Set::add(Type second)
{
	m_certificateStorage |= second;
}

bool Set::contains(Type second) const
{
	return static_cast<bool>(m_certificateStorage & second);
}

bool Set::isContainsVis() const
{
	Type visType = VIS_PUBLIC;
	visType |= VIS_PARTNER;
	visType |= VIS_PLATFORM;

	visType &= m_certificateStorage;

	if (visType == 0)
		return false;

	return true;
}

bool Set::isEmpty() const
{
	return m_certificateStorage == 0;
}

std::string Set::typeToString() const
{
	std::string ret;

	if (m_certificateStorage & TIZEN_DEVELOPER)
		ret += "TIZEN_DEVELOPER ";
	if (m_certificateStorage & TIZEN_TEST)
		ret += "TIZEN_TEST ";
	if (m_certificateStorage & TIZEN_VERIFY)
		ret += "TIZEN_VERIFY ";
	if (m_certificateStorage & TIZEN_STORE)
		ret += "TIZEN_STORE ";
	if (m_certificateStorage & VIS_PUBLIC)
		ret += "VIS_PUBLIC ";
	if (m_certificateStorage & VIS_PARTNER)
		ret += "VIS_PARTNER ";
	if (m_certificateStorage & VIS_PLATFORM)
		ret += "VIS_PLATFORM ";

	return ret;
}

} // namespace CertStoreId
} // namespace ValidationCore
