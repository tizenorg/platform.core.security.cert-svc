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
#include <string>

#include <openssl/x509.h>

#include <dpl/test/test_runner.h>
#include <dpl/log/log.h>
#include <memory>

#include <api_tests.h>

#include <cert-service.h>

RUNNER_TEST_GROUP_INIT(DEPRECATED_API)

typedef std::unique_ptr<CERT_CONTEXT, std::function<int(CERT_CONTEXT*)>> ScopedCertCtx;

/*
 * author:      ---
 * test:        PEM positive.
 * description: Loading *.pem file.
 * expect:      *.pem should load with no error.
 */
RUNNER_TEST(deprecated_api_test01_pem_positive)
{
    ScopedCertCtx ctx(cert_svc_cert_context_init(), cert_svc_cert_context_final);
    RUNNER_ASSERT(CERT_SVC_ERR_NO_ERROR ==
        cert_svc_load_file_to_context(ctx.get(), "/opt/share/cert-svc/cert-type/cert0.pem"));
}

/*
 * author:      ---
 * test:        DER positive.
 * description: Loading *.der file.
 * expect:      *.der file should load with no error.
 */
RUNNER_TEST(deprecated_api_test02_der_positive)
{
    ScopedCertCtx ctx(cert_svc_cert_context_init(), cert_svc_cert_context_final);
    RUNNER_ASSERT(CERT_SVC_ERR_NO_ERROR ==
        cert_svc_load_file_to_context(ctx.get(), "/opt/share/cert-svc/cert-type/cert1.der"));
}

/*
 * author:      ---
 * test:        PEM negative.
 * description: Loading *.pem file.
 * expect:      *.pom file should not load and return error.
 */
RUNNER_TEST(deprecated_api_test03_pem_negative)
{
    ScopedCertCtx ctx(cert_svc_cert_context_init(), cert_svc_cert_context_final);
    RUNNER_ASSERT(CERT_SVC_ERR_NO_ERROR !=
        cert_svc_load_file_to_context(ctx.get(), "/opt/share/cert-svc/cert-type/cert2fake.pem"));
}

/*
 * author:      ---
 * test:        DER negative.
 * description: Loading *.der file.
 * expect:      *.der file should not load and return error.
 */
RUNNER_TEST(deprecated_api_test03_der_negative)
{
    ScopedCertCtx ctx(cert_svc_cert_context_init(), cert_svc_cert_context_final);
    RUNNER_ASSERT(CERT_SVC_ERR_NO_ERROR !=
        cert_svc_load_file_to_context(ctx.get(), "/opt/share/cert-svc/cert-type/cert3fake.der"));
}
