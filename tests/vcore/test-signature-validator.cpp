/*
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <iostream>

#include <dpl/test/test_runner.h>
#include <vcore/SignatureFinder.h>
#include <vcore/SignatureValidator.h>

#include "test-common.h"

using namespace ValidationCore;

RUNNER_TEST_GROUP_INIT(T0010_SIGNATURE_VALIDATOR)

RUNNER_TEST(T00101_finder)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");
    RUNNER_ASSERT_MSG(signatureSet.size() == 2, "Some signature has not been found");

    for (auto &fileInfo : signatureSet)
        RUNNER_ASSERT_MSG((
            (fileInfo.getFileName().find("author-signature.xml") != std::string::npos && fileInfo.getFileNumber() == -1) ||
            (fileInfo.getFileName().find("signature1.xml") != std::string::npos && fileInfo.getFileNumber() == 1)),
            "invalid signature xml found: " << fileInfo.getFileName() << " with number: " << fileInfo.getFileNumber());
}

RUNNER_TEST(T00102_positive_public_check_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_path,
                true,
                true,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));

        if (!data.isAuthorSignature() && data.getSignatureNumber() == 1)
            RUNNER_ASSERT_MSG(data.getVisibilityLevel() == CertStoreId::VIS_PUBLIC,
                "visibility check failed.");
    }
}

RUNNER_TEST(T00103_positive_partner_check_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_partner_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_partner_path,
                true,
                true,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                "visibility check failed.");
    }
}

RUNNER_TEST(T00104_positive_public_uncheck_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");


    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_path,
                true,
                false,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));

        if (!data.isAuthorSignature() && data.getSignatureNumber() == 1)
            RUNNER_ASSERT_MSG(data.getVisibilityLevel() == CertStoreId::VIS_PUBLIC,
                "visibility check failed.");
    }
}

RUNNER_TEST(T00105_positive_partner_uncheck_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_partner_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_partner_path,
                true,
                false,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                "visibility check failed.");
    }
}

RUNNER_TEST(T00106_positive_tpk)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::tpk_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::tpk_path,
                true,
                true,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));
    }
}

RUNNER_TEST(T00107_positive_tpk_with_userdata)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::tpk_with_userdata_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    UriList uriList;
    uriList.emplace_back("author-siganture.xml");
    uriList.emplace_back("bin/preference");
    uriList.emplace_back("res/edje/pref_buttons_panel.edj");
    uriList.emplace_back("res/edje/pref_edit_panel.edj");
    uriList.emplace_back("res/edje/preference.edj");
    uriList.emplace_back("res/images/icon_delete.png");
    uriList.emplace_back("res/res.xml");
    uriList.emplace_back("shared/res/preference.png");
    uriList.emplace_back("tizen-manifest.xml");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.checkList(
                true,
                uriList,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "sig validation should be success: "
            << validator.errorToString(result));
    }
}

RUNNER_TEST(T00108_distributor_disregard_check)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_dist22_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_dist22_path,
                true,
                true,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_CHAIN,
                "author sig validation should be fail : "
                << validator.errorToString(result));
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(result == E_SIG_INVALID_CHAIN,
                    "dist1 sig validation should be fail: "
                    << validator.errorToString(result));
            else
                RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                    "dist22 sig validation should be disregarded: "
                    << validator.errorToString(result));
    }
}

RUNNER_TEST(T00151_negative_hash_check_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_negative_hash_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_negative_hash_path,
                true,
                true,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "dist sig shouldn't be success: "
                << validator.errorToString(result));
    }
}

RUNNER_TEST(T00152_negative_hash_uncheck_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_negative_hash_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_negative_hash_path,
                true,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "dist sig shouldn't be success: "
                << validator.errorToString(result));
    }
}

RUNNER_TEST(T00153_negative_signature_check_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_negative_signature_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_negative_signature_path,
                true,
                true,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "dist sig validation should be failed: "
                << validator.errorToString(result));
    }
}

RUNNER_TEST(T00154_negative_signature_uncheck_ref)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_negative_signature_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::widget_negative_signature_path,
                true,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "dist sig should be failed: "
                 << validator.errorToString(result));
    }
}

RUNNER_TEST(T00155_negative_tpk_with_added_malfile)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::attacked_tpk_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.check(
                TestData::attacked_tpk_path,
                true,
                true,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_NONE,
                "author sig validation should be success: "
                << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_REF,
                "dist sig validation should be failed: "
                << validator.errorToString(result));
    }
}

RUNNER_TEST(T00156_negative_tpk_with_userdata_file_changed_in_list)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::attacked_tpk_with_userdata_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    UriList uriList;
    uriList.emplace_back("author-siganture.xml");
    uriList.emplace_back("bin/preference");
    uriList.emplace_back("res/edje/pref_buttons_panel.edj");
    uriList.emplace_back("res/edje/pref_edit_panel.edj");
    uriList.emplace_back("res/edje/preference.edj");
    uriList.emplace_back("res/images/icon_delete.png");
    uriList.emplace_back("res/res.xml");
    uriList.emplace_back("shared/res/preference.png");

    /* this file is modified after signing app */
    uriList.emplace_back("tizen-manifest.xml");

    for (auto &sig : signatureSet) {
        SignatureValidator validator(sig);
        SignatureData data;
        VCerr result = validator.checkList(
                true,
                uriList,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "author sig validation should be failed: "
                << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_SIG,
                "dist sig validation should be failed: "
                << validator.errorToString(result));
    }
}

RUNNER_TEST_GROUP_INIT(T0020_SigVal_errorstring)

RUNNER_TEST(T0021)
{
    SignatureValidator validator(SignatureFileInfo("test-dummy", 1));

    for (VCerr code = E_SCOPE_FIRST; code >= E_SCOPE_LAST; code--) {
        std::cout << "E_SIG code["
            << code << "] : "
            << validator.errorToString(code) << std::endl;
    }

    /* print 10 more error code below last in case of plugin err exist */
    for (VCerr code = E_SCOPE_LAST - 1; code >= E_SCOPE_LAST - 10; code--) {
        std::cout << "VCerr from plugin["
            << code << "] : "
            << validator.errorToString(code) << std::endl;
    }
}
