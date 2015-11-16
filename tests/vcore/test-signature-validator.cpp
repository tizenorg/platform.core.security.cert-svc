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

/*
 * test: Class SignatureFinder
 * description: SignatureFinder should search directory passed as
 * param of constructor.
 * expected: Signature finder should put information about 3
 * signture files in SinatureFileInfoSet.
 */
RUNNER_TEST(T0011_signature_finder)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(TestData::widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");
    RUNNER_ASSERT_MSG(signatureSet.size() == 3, "Some signature has not been found");

    int count = 0;

    auto iter = signatureSet.begin();
    SignatureFileInfo fileInfo = *iter++;
    std::string fileName = fileInfo.getFileName();
    int fileNum = fileInfo.getFileNumber();
    if ((fileName.find("author-signature.xml") != std::string::npos && fileNum == -1)
        || (fileName.find("signature1.xml") != std::string::npos && fileNum == 1)
        || (fileName.find("signature22.xml") != std::string::npos && fileNum == 22))
        count++;
    RUNNER_ASSERT_MSG(iter != signatureSet.end(), "There should be more items");

    fileInfo = *iter++;
    fileName = fileInfo.getFileName();
    fileNum = fileInfo.getFileNumber();
    if ((fileName.find("author-signature.xml") != std::string::npos && fileNum == -1)
        || (fileName.find("signature1.xml") != std::string::npos && fileNum == 1)
        || (fileName.find("signature22.xml") != std::string::npos && fileNum == 22))
        count++;
    RUNNER_ASSERT_MSG(iter != signatureSet.end(), "There should be more items");

    fileInfo = *iter++;
    fileName = fileInfo.getFileName();
    fileNum = fileInfo.getFileNumber();
    if ((fileName.find("author-signature.xml") != std::string::npos && fileNum == -1)
        || (fileName.find("signature1.xml") != std::string::npos && fileNum == 1)
        || (fileName.find("signature22.xml") != std::string::npos && fileNum == 22))
        count++;
    RUNNER_ASSERT_MSG(iter == signatureSet.end(), "It should be last item");

    RUNNER_ASSERT_MSG(count == 3, "Wrong signature file count.");
}

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator
 * description: Directory passed to SignatureFinded constructor should be searched
 * and 3 signature should be find. All signature should be parsed and verified.
 * expected: Verificator should DISREGARD author signature and VERIFY
 * distrubutor signature.
 */
RUNNER_TEST(T0012_signature_validator)
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
                false,
                true,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                    "Validation failed");
            else
                RUNNER_ASSERT_MSG(result == E_SIG_NONE,
                    "Validation failed");
    }
}

RUNNER_TEST(T00121_signature_validator_negative_hash_input)
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
                false,
                true,
                data);
        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_FORMAT,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
    }
}

RUNNER_TEST(T00122_signature_validator_negative_signature_input)
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
                false,
                true,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_FORMAT,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
    }
}

RUNNER_TEST(T00123_signature_validator_partner)
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
                false,
                true,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
        if (!data.isAuthorSignature()) {
            RUNNER_ASSERT_MSG(
                    data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                    "visibility check failed.");
        }
    }
}
/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator
 * description: Directory passed to SignatureFinded constructor should be searched
 * and 3 signature should be find. All signature should be parsed and verified.
 * expected: Verificator should DISREGARD author signature and VERIFY
 * distrubutor signature.
 */
RUNNER_TEST(T0013_signature_validator)
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
                false,
                false,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                        "Validation failed");
            else
                RUNNER_ASSERT_MSG(result == E_SIG_NONE,
                        "Validation failed");
    }
}

RUNNER_TEST(T00131_signature_validator_negative_hash_input)
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
                false,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_FORMAT,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
    }
}

RUNNER_TEST(T00132_signature_validator_negative_signature_input)
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
                false,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_INVALID_FORMAT,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
        else
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Wrong input file but success.. Errorcode : " << validator.errorToString(result));
    }
}

RUNNER_TEST(T00133_signature_validator_partner)
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
                false,
                false,
                data);

        RUNNER_ASSERT_MSG(result == E_SIG_NONE,
            "Wrong input file but success.. Errorcode : " << validator.errorToString(result));

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(data.getVisibilityLevel() == CertStoreId::VIS_PARTNER,
                "visibility check failed.");
    }
}

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator, ReferenceValidator
 * description: As above but this test also checks reference from signatures.
 * expected: All reference checks should return NO_ERROR.
 */
RUNNER_TEST(T0014_signature_reference)
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
                false,
                false,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(result == E_SIG_DISREGARDED,
                    "Validation failed");
            else
                RUNNER_ASSERT_MSG(result == E_SIG_NONE,
                    "Validation failed");
    }
}

/*
 * test: ReferenceValidator::checkReference
 * description: Simple test. File "encoding test.empty" exists.
 * expected: checkReference should return NO_ERROR.
 */
/*
RUNNER_TEST(T00141_signature_reference_encoding_dummy)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("encoding test.empty");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::NO_ERROR == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/

/*
 * test: ReferenceValidator::checkReference
 * description: Negative test. File "encoding test" does not exists.
 * expected: checkReference should return ERROR_REFERENCE_NOT_FOUND
 */
/*
RUNNER_TEST(T00142_signature_reference_encoding_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("encoding test");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::ERROR_REFERENCE_NOT_FOUND == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: File "encoding test.empty" exists. Name set in referenceSet must
 * be encoded first by decodeProcent function.
 * expected: checkReference should return NO_ERROR
 */
/*
RUNNER_TEST(T00143_signature_reference_encoding_space)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("encoding%20test.empty");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::NO_ERROR == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: Negative test. File "encoding test" does not exists. Name set in
 * referenceSet must be encoded first by decodeProcent function.
 * expected: checkReference should return ERROR_REFERENCE_NOT_FOUND
 */
/*
RUNNER_TEST(T00144_signature_reference_encoding_space_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("encoding%20test");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::ERROR_REFERENCE_NOT_FOUND == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: File "encoding test.empty" exists. Name set in
 * referenceSet must be encoded first by decodeProcent function.
 * expected: checkReference should return NO_ERROR
 */
/*
RUNNER_TEST(T00145_signature_reference_encoding)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("e%6Ec%6Fding%20te%73%74.e%6d%70ty");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::NO_ERROR == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/

/*
 * test: ReferenceValidator::checkReference, ReferenceValidator::decodeProcent
 * description: Negative test. "%%" is illegal combination of char. decodeProcent
 * should throw exception.
 * expected: checkReference should return ERROR_DECODING_URL
 */
/*
RUNNER_TEST(T00146_signature_reference_encoding_negative)
{
    ReferenceSet referenceSet;
    SignatureData data;
    ReferenceValidator val("/usr/apps/widget/tests/reference");
    referenceSet.insert("e%6Ec%6Fding%%0test%2ete%73%74");
    data.setReference(referenceSet);

    int temp = val.checkReferences(data);
    RUNNER_ASSERT_MSG(ReferenceValidator::ERROR_DECODING_URL == temp,
            "Errorcode : " << refValidatorErrorToString(temp));
}
*/


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

RUNNER_TEST_GROUP_INIT(T0030_Certificate)

/*
 * test: class Certificate
 * description: Certificate should parse data passed to object constructor.
 * expected: Getters should be able to return certificate information.
 */
RUNNER_TEST(T0031_Certificate)
{
    Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);
    std::string result;

    result = cert.getCommonName(Certificate::FIELD_SUBJECT);
    RUNNER_ASSERT_MSG(!result.empty(), "No common name");
    RUNNER_ASSERT_MSG(!result.compare("www.verisign.com"), "CommonName mismatch");

    result = cert.getCommonName(Certificate::FIELD_ISSUER);
    RUNNER_ASSERT_MSG(!result.empty(), "No common name");
    RUNNER_ASSERT_MSG(!result.compare("VeriSign Class 3 Extended Validation SSL SGC CA"),
            "CommonName mismatch");

    result = cert.getCountryName();
    RUNNER_ASSERT_MSG(!result.empty(), "No country");
    RUNNER_ASSERT_MSG(!result.compare("US"), "Country mismatch");
}

/*
 * test: Certificate::getFingerprint
 * description: Certificate should parse data passed to object constructor.
 * expected: Function fingerprint should return valid fingerprint.
 */
RUNNER_TEST(T0032_Certificate)
{
    Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);

    Certificate::Fingerprint fin =
        cert.getFingerprint(Certificate::FINGERPRINT_SHA1);

    unsigned char buff[20] = {
        0xb9, 0x72, 0x1e, 0xd5, 0x49,
        0xed, 0xbf, 0x31, 0x84, 0xd8,
        0x27, 0x0c, 0xfe, 0x03, 0x11,
        0x19, 0xdf, 0xc2, 0x2b, 0x0a};
    RUNNER_ASSERT_MSG(fin.size() == 20, "Wrong size of fingerprint");

    for (size_t i = 0; i<20; ++i) {
        RUNNER_ASSERT_MSG(fin[i] == buff[i], "Fingerprint mismatch");
    }
}

/*
 * test: Certificate::getAlternativeNameDNS
 * description: Certificate should parse data passed to object constructor.
 * expected: Function getAlternativeNameDNS should return list of
 * alternativeNames hardcoded in certificate.
 */
RUNNER_TEST(T0033_Certificate)
{
    Certificate cert(TestData::certVerisign, Certificate::FORM_BASE64);

    Certificate::AltNameSet nameSet = cert.getAlternativeNameDNS();

    RUNNER_ASSERT(nameSet.size() == 8);

    std::string str("verisign.com");
    RUNNER_ASSERT(nameSet.find(str) != nameSet.end());

    str = std::string("fake.com");
    RUNNER_ASSERT(nameSet.find(str) == nameSet.end());

}

/*
 * test: Certificate::isCA
 * description: Certificate should parse data passed to object constructor.
 * expected: 1st and 2nd certificate should be identified as CA.
 */
RUNNER_TEST(T0034_Certificate_isCA)
{
    Certificate cert1(TestData::googleCA, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert1.isCA() > 0);

    Certificate cert2(TestData::google2nd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert2.isCA() > 0);

    Certificate cert3(TestData::google3rd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert3.isCA() == 0);
}
