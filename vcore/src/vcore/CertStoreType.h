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
 * @file        CertStoreType.h
 * @version     1.0
 * @brief       Identification of certificate domain. Certificate domains
 *              were defined in WAC 1.0 documentation. This is a part
 *              should be implemented in wrt-installer.
 */
#ifndef _VALIDATION_CORE_CERTSTORETYPE_H_
#define _VALIDATION_CORE_CERTSTORETYPE_H_

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
// RootCA certificates for tizen-member ie. samsung and operators
const Type TIZEN_MEMBER = 1 << 4;
// RootCA certificates used by orange
const Type ORANGE_LEGACY = 1 << 5;

class Set
{
  public:
    Set();

    void add(Type second);

    bool contains(Type second) const;

    bool isEmpty() const;

  private:
    Type m_certificateStorage;
};

} // namespace CertStoreId
} // namespace ValidationCore

#endif //  _VALIDATION_CORE_CERTSTORETYPE_H_
