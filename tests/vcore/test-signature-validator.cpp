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

#include <dpl/test/test_runner.h>
#include <vcore/SignatureFinder.h>
#include <vcore/SignatureValidator.h>

#include "test-common.h"

namespace {

const std::string widget_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed/";
const std::string widget_negative_hash_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed_negative_hash/";
const std::string widget_negative_signature_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed_negative_signature/";
const std::string widget_negative_certificate_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed_negative_certificate/";
const std::string widget_partner_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed_partner/";
const std::string widget_partner_operator_path =
    "/usr/apps/widget/tests/vcore_widget_uncompressed_partner_operator/";

const std::string googleCA =
"MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG"
"A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz"
"cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2"
"MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV"
"BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt"
"YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
"ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE"
"BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is"
"I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G"
"CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do"
"lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc"
"AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k";

const std::string google2nd =
"MIIDIzCCAoygAwIBAgIEMAAAAjANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJV"
"UzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsTLkNsYXNzIDMgUHVi"
"bGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDQwNTEzMDAw"
"MDAwWhcNMTQwNTEyMjM1OTU5WjBMMQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhh"
"d3RlIENvbnN1bHRpbmcgKFB0eSkgTHRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBD"
"QTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1NNn0I0Vf67NMf59HZGhPwtx"
"PKzMyGT7Y/wySweUvW+Aui/hBJPAM/wJMyPpC3QrccQDxtLN4i/1CWPN/0ilAL/g"
"5/OIty0y3pg25gqtAHvEZEo7hHUD8nCSfQ5i9SGraTaEMXWQ+L/HbIgbBpV8yeWo"
"3nWhLHpo39XKHIdYYBkCAwEAAaOB/jCB+zASBgNVHRMBAf8ECDAGAQH/AgEAMAsG"
"A1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAX"
"BgNVBAMTEFByaXZhdGVMYWJlbDMtMTUwMQYDVR0fBCowKDAmoCSgIoYgaHR0cDov"
"L2NybC52ZXJpc2lnbi5jb20vcGNhMy5jcmwwMgYIKwYBBQUHAQEEJjAkMCIGCCsG"
"AQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMDQGA1UdJQQtMCsGCCsGAQUF"
"BwMBBggrBgEFBQcDAgYJYIZIAYb4QgQBBgpghkgBhvhFAQgBMA0GCSqGSIb3DQEB"
"BQUAA4GBAFWsY+reod3SkF+fC852vhNRj5PZBSvIG3dLrWlQoe7e3P3bB+noOZTc"
"q3J5Lwa/q4FwxKjt6lM07e8eU9kGx1Yr0Vz00YqOtCuxN5BICEIlxT6Ky3/rbwTR"
"bcV0oveifHtgPHfNDs5IAn8BL7abN+AqKjbc1YXWrOU/VG+WHgWv";

const std::string google3rd =
"MIIDIjCCAougAwIBAgIQK59+5colpiUUIEeCdTqbuTANBgkqhkiG9w0BAQUFADBM"
"MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg"
"THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x"
"MzA5MzAyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh"
"MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRgw"
"FgYDVQQDFA9tYWlsLmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ"
"AoGBAK85FZho5JL+T0/xu/8NLrD+Jaq9aARnJ+psQ0ynbcvIj36B7ocmJRASVDOe"
"qj2bj46Ss0sB4/lKKcMP/ay300yXKT9pVc9wgwSvLgRudNYPFwn+niAkJOPHaJys"
"Eb2S5LIbCfICMrtVGy0WXzASI+JMSo3C2j/huL/3OrGGvvDFAgMBAAGjgecwgeQw"
"DAYDVR0TAQH/BAIwADA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLnRoYXd0"
"ZS5jb20vVGhhd3RlU0dDQ0EuY3JsMCgGA1UdJQQhMB8GCCsGAQUFBwMBBggrBgEF"
"BQcDAgYJYIZIAYb4QgQBMHIGCCsGAQUFBwEBBGYwZDAiBggrBgEFBQcwAYYWaHR0"
"cDovL29jc3AudGhhd3RlLmNvbTA+BggrBgEFBQcwAoYyaHR0cDovL3d3dy50aGF3"
"dGUuY29tL3JlcG9zaXRvcnkvVGhhd3RlX1NHQ19DQS5jcnQwDQYJKoZIhvcNAQEF"
"BQADgYEANYARzVI+hCn7wSjhIOUCj19xZVgdYnJXPOZeJWHTy60i+NiBpOf0rnzZ"
"wW2qkw1iB5/yZ0eZNDNPPQJ09IHWOAgh6OKh+gVBnJzJ+fPIo+4NpddQVF4vfXm3"
"fgp8tuIsqK7+lNfNFjBxBKqeecPStiSnJavwSI4vw6e7UN0Pz7A=";

const std::string certVerisign =
"MIIG+DCCBeCgAwIBAgIQU9K++SSnJF6DygHkbKokdzANBgkqhkiG9w0BAQUFADCB"
"vjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL"
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2Ug"
"YXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE4MDYGA1UEAxMv"
"VmVyaVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBTR0MgQ0Ew"
"HhcNMTAwNTI2MDAwMDAwWhcNMTIwNTI1MjM1OTU5WjCCASkxEzARBgsrBgEEAYI3"
"PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxGzAZBgNVBA8TElYx"
"LjAsIENsYXVzZSA1LihiKTEQMA4GA1UEBRMHMjQ5Nzg4NjELMAkGA1UEBhMCVVMx"
"DjAMBgNVBBEUBTk0MDQzMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHFA1N"
"b3VudGFpbiBWaWV3MSIwIAYDVQQJFBk0ODcgRWFzdCBNaWRkbGVmaWVsZCBSb2Fk"
"MRcwFQYDVQQKFA5WZXJpU2lnbiwgSW5jLjEmMCQGA1UECxQdIFByb2R1Y3Rpb24g"
"U2VjdXJpdHkgU2VydmljZXMxGTAXBgNVBAMUEHd3dy52ZXJpc2lnbi5jb20wggEi"
"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCj+PvvK+fZOXwno0yT/OTy2Zm9"
"ehnZjTtO/X2IWBEa3jG30C52uHFQI4NmXiQVNvJHkBaAj0ilVjvGdxXmkyyFsugt"
"IWOTZ8pSKdX1tmGFIon6Ko9+lBFkVkudA1ogAUbtTB8IcdeOlpK78T4SjdVMhY18"
"150YzSw6hRKlw52wBaDxtGZElvOth41K7TUcaDnQVzz5SBPW5MUhi7AWrdoSk17O"
"BozOzmB/jkYDVDnwLcbR89SLHEOle/idSYSDQUmab3y0JS8RyQV1+DB70mnFALnD"
"fLiL47nMQQCGxXgp5voQ2YmSXhevKmEJ9vvtC6C7yv2W6yomfS/weUEce9pvAgMB"
"AAGjggKCMIICfjCBiwYDVR0RBIGDMIGAghB3d3cudmVyaXNpZ24uY29tggx2ZXJp"
"c2lnbi5jb22CEHd3dy52ZXJpc2lnbi5uZXSCDHZlcmlzaWduLm5ldIIRd3d3LnZl"
"cmlzaWduLm1vYmmCDXZlcmlzaWduLm1vYmmCD3d3dy52ZXJpc2lnbi5ldYILdmVy"
"aXNpZ24uZXUwCQYDVR0TBAIwADAdBgNVHQ4EFgQU8oBwK/WBXCZDWi0dbuDgPyTK"
"iJIwCwYDVR0PBAQDAgWgMD4GA1UdHwQ3MDUwM6AxoC+GLWh0dHA6Ly9FVkludGwt"
"Y3JsLnZlcmlzaWduLmNvbS9FVkludGwyMDA2LmNybDBEBgNVHSAEPTA7MDkGC2CG"
"SAGG+EUBBxcGMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlzaWduLmNv"
"bS9ycGEwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEw"
"HwYDVR0jBBgwFoAUTkPIHXbvN1N6T/JYb5TzOOLVvd8wdgYIKwYBBQUHAQEEajBo"
"MCsGCCsGAQUFBzABhh9odHRwOi8vRVZJbnRsLW9jc3AudmVyaXNpZ24uY29tMDkG"
"CCsGAQUFBzAChi1odHRwOi8vRVZJbnRsLWFpYS52ZXJpc2lnbi5jb20vRVZJbnRs"
"MjAwNi5jZXIwbgYIKwYBBQUHAQwEYjBgoV6gXDBaMFgwVhYJaW1hZ2UvZ2lmMCEw"
"HzAHBgUrDgMCGgQUS2u5KJYGDLvQUjibKaxLB4shBRgwJhYkaHR0cDovL2xvZ28u"
"dmVyaXNpZ24uY29tL3ZzbG9nbzEuZ2lmMA0GCSqGSIb3DQEBBQUAA4IBAQB9VZxB"
"wDMRGyhFWYkY5rwUVGuDJiGeas2xRJC0G4+riQ7IN7pz2a2BhktmZ5HbxXL4ZEY4"
"yMN68DEVErhtKiuL02ng27alhlngadKQzSL8pLdmQ+3jEwm9nva5C/7pbeqy+qGF"
"is4IWNYOc4HKNkABxXm5v0ouys8HPNkTLFLep0gLqRXW3gYN2XbKUWMs7z7hJpkY"
"GxP8YQSxi513O2dWVCXB8S6erIz9E/bcfdXoCPyQdn42y3IEoJvPvBS3S55fD4+Q"
"Q43GPhumSg9a6S3hnyw8DX5OiUGmqgQrtSeDRsNmWqtWizEQbe+fotZpEn/7zYTa"
"tk1ni/k5jDH/QeuG";

} // namespace anonymous

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
    SignatureFinder signatureFinder(widget_path);
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
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_path,
                false,
                true,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                    "Validation failed");
            else
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_VERIFIED,
                    "Validation failed");
    }
}

RUNNER_TEST(T00121_signature_validator_negative_hash_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_hash_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_negative_hash_path,
                false,
                true,
                data);
        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_INVALID,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
        else
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(T00122_signature_validator_negative_signature_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_signature_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_negative_signature_path,
                false,
                true,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_INVALID,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
        else
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(T00123_signature_validator_partner)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_partner_path,
                false,
                true,
                data);

        RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_VERIFIED,
            "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
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
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_path,
                false,
                false,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                        "Validation failed");
            else
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_VERIFIED,
                        "Validation failed");
    }
}

RUNNER_TEST(T00131_signature_validator_negative_hash_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_hash_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_negative_hash_path,
                false,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_INVALID,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
        else
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(T00132_signature_validator_negative_signature_input)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_negative_signature_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_negative_signature_path,
                false,
                false,
                data);

        if (!data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_INVALID,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
        else
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(T00133_signature_validator_partner)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_partner_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_partner_path,
                false,
                false,
                data);

        RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_VERIFIED,
            "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));

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
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");

    for (SignatureFileInfoSet::reverse_iterator iter = signatureSet.rbegin();
        iter != signatureSet.rend();
        ++iter) {
        SignatureData data;
        SignatureValidator::Result valResult = SignatureValidator::check(
                *iter,
                widget_path,
                false,
                false,
                data);

        if (data.isAuthorSignature())
            RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Validation failed");
        else
            if (data.getSignatureNumber() == 1)
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_DISREGARD,
                    "Validation failed");
            else
                RUNNER_ASSERT_MSG(valResult == SignatureValidator::SIGNATURE_VERIFIED,
                    "Validation failed");

/*
        ReferenceValidator val(widget_path);
        int temp = val.checkReferences(data);
        RUNNER_ASSERT_MSG(ReferenceValidator::NO_ERROR == temp,
                "File[" << iter->getFileName()
                << "] FileNumber[" << iter->getFileNumber()
                << "] Errorcode : " << refValidatorErrorToString(temp));
*/
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


RUNNER_TEST_GROUP_INIT(T0020_Certificate)

/*
 * test: class Certificate
 * description: Certificate should parse data passed to object constructor.
 * expected: Getters should be able to return certificate information.
 */
RUNNER_TEST(T0021_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);
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
RUNNER_TEST(T0022_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);

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
RUNNER_TEST(T0023_Certificate)
{
    Certificate cert(certVerisign, Certificate::FORM_BASE64);

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
RUNNER_TEST(T0024_Certificate_isCA)
{
    Certificate cert1(googleCA, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert1.isCA() > 0);

    Certificate cert2(google2nd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert2.isCA() > 0);

    Certificate cert3(google3rd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert3.isCA() == 0);
}
