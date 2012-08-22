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
 * @file
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief
 */
#ifndef _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTSTORETYPE_H_
#define _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTSTORETYPE_H_

namespace ValidationCore {
namespace CertStoreId {
typedef unsigned int Type;

// RootCA certificates for developer mode.
const Type DEVELOPER = 1;
// RootCA certificates for author signatures.
const Type WAC_PUBLISHER = 1 << 1;
// RootCA certificates for wac-signed widgets.
const Type WAC_ROOT = 1 << 2;
// RootCA certificates for wac-members ie. operators, manufacturers.
const Type WAC_MEMBER = 1 << 3;

class Set
{
  public:
    Set() :
        m_certificateStorage(0)
    {
    }

    void add(Type second)
    {
        m_certificateStorage |= second;
    }

    bool contains(Type second) const
    {
        return static_cast<bool>(m_certificateStorage & second);
    }

    bool isEmpty() const
    {
        return m_certificateStorage == 0;
    }

  private:
    Type m_certificateStorage;
};
} // namespace CertStoreId
} // namespace ValidationCore

#endif //  _WRT_ENGINE_SRC_INSTALLER_CORE_VALIDATION_CORE_CERTSTORETYPE_H_
