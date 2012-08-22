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
 * @file        test_cases.cpp
 * @author      Jacek Migacz (j.migacz@samsung.com)
 * @version     1.0
 * @brief       PKCS#12 test cases.
 */
#include <string.h>
#include <dpl/test/test_runner.h>
#include <dpl/log/log.h>
#include <cert-svc/cinstance.h>
#include <cert-svc/ccert.h>
#include <cert-svc/ccrl.h>
#include <cert-svc/cocsp.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cerror.h>
#include <cert-service.h>

static CertSvcInstance instance;

#define CREATE_INSTANCE                                   \
  certsvc_instance_new(&instance);
#define FREE_INSTANCE                                     \
  certsvc_instance_free(instance);

RUNNER_TEST(test01_import_and_remove_pkcs12_container) {
  const char path[] = "/opt/apps/widget/tests/pkcs12/test.p12";
  const char pass[] = "zaq12WSX";
  char tmpn[L_tmpnam], *alias;
  int result;

  CREATE_INSTANCE
  CertSvcString Alias, Path, Pass;
  RUNNER_ASSERT_MSG((tmpnam(tmpn)), "tmpnam(3) failed..");
  alias = strrchr(tmpn, '/');
  ++alias;
  RUNNER_ASSERT_MSG(alias && *alias, "Invalid alias.");
  Alias.privateHandler = (char *)alias;
  Alias.privateLength = strlen(alias);
  Pass.privateHandler = (char *)pass;
  Pass.privateLength = strlen(pass);
  Path.privateHandler = (char *)path;
  Path.privateLength = strlen(path);
  result = certsvc_pkcs12_import_from_file(instance, Path, Pass, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_import_from_file failed.");

  int is_unique;
  result = certsvc_pkcs12_alias_exists(instance, Alias, &is_unique);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && !is_unique, "certsvc_pkcs12_alias_exists failed.");

  char *buf;
  int size;
  result = certsvc_pkcs12_private_key_dup(instance, Alias, &buf, &size);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_private_key_dup failed.");
  certsvc_pkcs12_private_key_free(buf);

  result = certsvc_pkcs12_delete(instance, Alias);
  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS, "certsvc_pkcs12_delete failed.");
  FREE_INSTANCE
}

RUNNER_TEST(test02_pkcs12_has_password) {
  const char with[] = "/opt/apps/widget/tests/pkcs12/with_pass.p12";
  int has_pwd = 0;

  CREATE_INSTANCE
  CertSvcString File;
  File.privateHandler = (char *)with;
  File.privateLength = strlen(with);
  int result = certsvc_pkcs12_has_password(instance, File, &has_pwd);
  FREE_INSTANCE

  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && has_pwd == CERTSVC_TRUE, "Error quering pkcs12/pfx container password.");
}

RUNNER_TEST(test03_pkcs12_has_password) {
  const char without[] = "/opt/apps/widget/tests/pkcs12/without_pass.p12";
  int has_pwd = 0;

  CREATE_INSTANCE
  CertSvcString File;
  File.privateHandler = (char *)without;
  File.privateLength = strlen(without);
  int result = certsvc_pkcs12_has_password(instance, File, &has_pwd);
  FREE_INSTANCE

  RUNNER_ASSERT_MSG(result == CERTSVC_SUCCESS && has_pwd == CERTSVC_FALSE, "Error quering pkcs12/pfx container password.");
}
