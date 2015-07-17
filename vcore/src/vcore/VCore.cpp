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
 * @file        VCore.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @brief
 */

#include <vcore/VCorePrivate.h>
#include <vcore/Config.h>
#include <openssl/ssl.h>
#include <glib.h>
#include <glib-object.h>

#include <dpl/assert.h>
#include <dpl/log/log.h>

namespace ValidationCore {

void AttachToThreadRO(void)
{
}

void AttachToThreadRW(void)
{
}

void DetachFromThread(void)
{
}

void VCoreInit()
{
    SSL_library_init();

    Config &globalConfig = ConfigSingleton::Instance();

    globalConfig.setXMLConfigPath(std::string(FINGERPRINT_LIST_PATH));
    globalConfig.setXMLSchemaPath(std::string(FINGERPRINT_LIST_SCHEMA_PATH));
}

void VCoreDeinit()
{
}

} // namespace ValidationCore

