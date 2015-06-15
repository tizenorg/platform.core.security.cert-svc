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
#include <dpl/log/log.h>

namespace {

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
DPL::DB::ThreadDatabaseSupport *threadInterface = NULL;
const std::string DatabasePath              = "/opt/dbspace/.cert_svc_vcore.db";
#endif

const std::string FingerprintListPath       = "/usr/share/ca-certificates/fingerprint/fingerprint_list.xml";
const std::string FingerprintListSchemaPath = "/usr/share/ca-certificates/fingerprint/fingerprint_list.xsd";

} // namespace anonymous

namespace ValidationCore {

void AttachToThreadRO(void)
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    Assert(threadInterface);
    static bool check = true;
    threadInterface->AttachToThread(
        DPL::DB::SqlConnection::Flag::RO);
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
        DPL::DB::SqlConnection::Flag::RW);
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
DPL::DB::ThreadDatabaseSupport& ThreadInterface(void) {
    Assert(threadInterface);
    return *threadInterface;
}
#endif
void VCoreInit()
{
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
	if (threadInterface) {
        LogDebug("Already Initialized");
        return;
    }

    threadInterface = new DPL::DB::ThreadDatabaseSupport(
        DatabasePath.c_str(),
        DPL::DB::SqlConnection::Flag::UseLucene);
#endif

    SSL_library_init();
    g_type_init();

    Config &globalConfig = ConfigSingleton::Instance();

    globalConfig.setXMLConfigPath(FingerprintListPath);
    globalConfig.setXMLSchemaPath(FingerprintListSchemaPath);
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

