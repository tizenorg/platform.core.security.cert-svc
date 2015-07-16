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
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <vcore/Database.h>
#include <database_checksum_vcore.h>
#endif
#include <openssl/ssl.h>
#include <glib.h>
#include <glib-object.h>

#include <dpl/assert.h>
#include <dpl/log/wrt_log.h>

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
namespace {
VcoreDPL::DB::ThreadDatabaseSupport *threadInterface = NULL;
} // namespace anonymous
#endif

namespace ValidationCore {

void AttachToThreadRO(void)
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    Assert(threadInterface);
    static bool check = true;
    threadInterface->AttachToThread(
        VcoreDPL::DB::SqlConnection::Flag::RO);
    // We can have race condition here but CheckTableExist
    // is thread safe and nothing bad will happend.
    if (check) {
        check = false;
        Assert(ThreadInterface().CheckTableExist(DB_CHECKSUM_STR) &&
               "Not a valid vcore database version");    
	}
#endif
}

void AttachToThreadRW(void)
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL	    
	Assert(threadInterface);
    static bool check = true;
    threadInterface->AttachToThread(
        VcoreDPL::DB::SqlConnection::Flag::RW);
    // We can have race condition here but CheckTableExist
    // is thread safe and nothing bad will happend.
    if (check) {
        check = false;
        Assert(ThreadInterface().CheckTableExist(DB_CHECKSUM_STR) &&
               "Not a valid vcore database version");
    }
#endif
}

void DetachFromThread(void){
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    Assert(threadInterface);
    threadInterface->DetachFromThread();
#endif
}
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
VcoreDPL::DB::ThreadDatabaseSupport& ThreadInterface(void) {
    Assert(threadInterface);
    return *threadInterface;
}
#endif

void VCoreInit()
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL    
    if (threadInterface) {
        WrtLogD("Already Initialized");
        return true;
    }

    threadInterface = new VcoreDPL::DB::ThreadDatabaseSupport(
        CERTSVC_VCORE_DB,
        VcoreDPL::DB::SqlConnection::Flag::UseLucene);
#endif

    SSL_library_init();

    Config &globalConfig = ConfigSingleton::Instance();

    globalConfig.setXMLConfigPath(std::string(FINGERPRINT_LIST_PATH));
    globalConfig.setXMLSchemaPath(std::string(FINGERPRINT_LIST_SCHEMA_PATH));
}

void VCoreDeinit()
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    Assert(threadInterface && "Not initialized or already deinitialized");
    delete threadInterface;
    threadInterface = NULL;
#endif
}

} // namespace ValidationCore

