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
#include <cstring>
#include <openssl/x509.h>
#include <dpl/test/test_runner.h>

#include <cert-svc/ccert.h>
#include <cert-svc/cpkcs12.h>
#include <cert-svc/cprimitives.h>

#include <api_tests.h>

RUNNER_TEST_GROUP_INIT(CAPI)

/*
 * author:      ---
 * test:        New certificate from file.
 * description: Creating new certificate using *.pem file.
 * expect:      Certificate should be created and has correct string inside..
 */
RUNNER_TEST(test01_certificate_new_from_file)
{
    CertSvcCertificate cert;
    int result = certsvc_certificate_new_from_file(
        vinstance,
        "/usr/share/cert-svc/cert-type/root_cacert0.pem",
        &cert);
    RUNNER_ASSERT_MSG(CERTSVC_TRUE == result, "Error reading certificate");

    CertSvcString string;

    certsvc_certificate_get_string_field(
        cert,
        CERTSVC_SUBJECT_COMMON_NAME,
        &string);

    const char *ptr = "Samsung";

    const char *buffer;
    int len;

    certsvc_string_to_cstring(string, &buffer, &len);

    result = strncmp(
        buffer,
        ptr,
        strlen(ptr));

    RUNNER_ASSERT_MSG(0 == result, "Error reading common name");

    certsvc_certificate_free(cert);
}

/*
 * author:      ---
 * test:        Searching certificate.
 * description: Searching for certificate with specified value.
 * expect:      Found certificate should had correct string inside.
 */
RUNNER_TEST(test02_certificate_search)
{
    CertSvcCertificateList handler;
    int result = certsvc_certificate_search(vinstance,
                                          CERTSVC_SUBJECT_COMMON_NAME,
                                          "WAC Application Services Ltd",
                                          &handler);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in search method. errcode : " << result);

    CertSvcCertificate cert;

    result = certsvc_certificate_list_get_one(handler, 0, &cert);

    RUNNER_ASSERT_MSG(CERTSVC_TRUE == result, "Error reading certificate. errcode : " << result);

    CertSvcString string;

    certsvc_certificate_get_string_field(
        cert,
        CERTSVC_SUBJECT_COUNTRY_NAME,
        &string);

    const char *ptr = "GB";
    const char *buffer;

    certsvc_string_to_cstring(string, &buffer, NULL);

    result = strncmp(
            buffer,
            ptr,
            strlen(ptr));

    RUNNER_ASSERT_MSG(0 == result, "Country does not match. result : " << result);
}

/*
 * author:      ---
 * test:        Testing certificate sign.
 * description: Testing if certificate is signed by proper CA.
 * expect:      Chain verification should return success.
 */
RUNNER_TEST(test03_is_signed_by)
{
    int result;
    std::string googleCA =
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

    std::string google2nd =
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

    CertSvcCertificate cert1, cert2;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)googleCA.c_str(),
        googleCA.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert1);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)google2nd.c_str(),
        google2nd.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert2);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

    int status;
    result = certsvc_certificate_is_signed_by(cert2, cert1, &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Chain verification failed");
    RUNNER_ASSERT_MSG(CERTSVC_TRUE == status, "Chain verification failed");
}

/*
 * author:      ---
 * test:        Certificate expiring test.
 * description: Testing if certificate is valid before / after specified date.
 * expect:      Certificate should be valid before / after specified date.
 */
RUNNER_TEST(test04_not_before_not_after)
{
    std::string google2nd =
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

    CertSvcCertificate cert;
    int result;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char *)google2nd.c_str(),
        google2nd.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");

    time_t before, after;
    result = certsvc_certificate_get_not_before(cert, &before);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error extracting NOT_BEFORE");
    RUNNER_ASSERT_MSG(before == 1084406400, "TODO");

    result = certsvc_certificate_get_not_after(cert, &after);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error extracting NOT_AFTER");
    //extracted: date --date="May 12 23:59:59 2014 GMT" +%s
    RUNNER_ASSERT_MSG(after == 1399939199, "TODO");
}

/*
 * author:      ---
 * test:        Import fields from certificate.
 * description: Getting common name from certificate.
 * expect:      It should be possible to get common name from certificate.
 */
RUNNER_TEST(test06_cert_get_field)
{
    std::string google2nd =
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

    CertSvcCertificate cert;

    int result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)google2nd.c_str(),
        google2nd.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    CertSvcString subject, issuer;

    result = certsvc_certificate_get_string_field(
        cert,
        CERTSVC_SUBJECT,
        &subject);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading SUBJECT field.");

    result = certsvc_certificate_get_string_field(
        cert,
        CERTSVC_ISSUER,
        &issuer);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading ISSUER field.");

    int size;
    const char *ptr;

    certsvc_string_to_cstring(subject, &ptr, &size);
    RUNNER_ASSERT_MSG(0 == strncmp(ptr, "/C=ZA/O=Thawte Consulting (Pty) Ltd./CN=Thawte SGC CA", size), "Subject does not match.");

    certsvc_string_to_cstring(issuer, &ptr, &size);
    RUNNER_ASSERT_MSG(0 == strncmp(ptr, "/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority", size), "Issuer does not match.");
}

/*
 * author:      ---
 * test:        Sorting certificates chain.
 * description: Certificate chain is being sorted.
 * expect:      It is possible to sor certificates chain.
 */
RUNNER_TEST(test07_chain_sort)
{
    std::string certEE =
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

    std::string certCA =
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

    std::string certRCA =
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

    CertSvcCertificate cert1, cert2, cert3;

    int result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)certEE.c_str(),
        certEE.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert1);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)certCA.c_str(),
        certCA.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert2);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)certRCA.c_str(),
        certRCA.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert3);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    CertSvcCertificate collection[3];
    collection[0] = cert1;
    collection[1] = cert3;
    collection[2] = cert2;

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == certsvc_certificate_chain_sort(collection, 3), "FAIL TO SORT CERTIFICATE");

    RUNNER_ASSERT_MSG(collection[2].privateHandler == cert3.privateHandler, "certsvc_certificate_chain_sort failed");

    collection[0] = cert1;
    collection[1] = cert3;

    RUNNER_ASSERT_MSG(CERTSVC_FAIL == certsvc_certificate_chain_sort(collection, 2), "certsvc_certificate_chain_sort failed");
}

/*
 * author:      ---
 * test:        Verification of DSA SHA1.
 * description: Testing certificate DSA SH1.
 * expect:      Certificate DSA SH1 should be correct.
 */
RUNNER_TEST(test08_message_verify_dsa_sha1)
{
    std::string magda =
      "MIIEDzCCA3igAwIBAgIJAMdKgvadG/Z/MA0GCSqGSIb3DQEBBQUAMHIxCzAJBgNV"
      "BAYTAlBMMQwwCgYDVQQIEwNNYXoxEDAOBgNVBAoTB1NhbXN1bmcxDTALBgNVBAsT"
      "BFNQUkMxEDAOBgNVBAMTB1NhbXN1bmcxIjAgBgkqhkiG9w0BCQEWE3NhbXN1bmdA"
      "c2Ftc3VuZy5jb20wHhcNMTExMDA1MTIxMTMzWhcNMjExMDAyMTIxMTMzWjCBijEL"
      "MAkGA1UEBhMCUEwxFDASBgNVBAgTC01hem93aWVja2llMRIwEAYDVQQHEwlsZWdp"
      "b25vd28xEDAOBgNVBAoTB3NhbXN1bmcxDTALBgNVBAsTBHNwcmMxDjAMBgNVBAMT"
      "BW1hZ2RhMSAwHgYJKoZIhvcNAQkBFhFtYWdkYUBzYW1zdW5nLmNvbTCCAbcwggEr"
      "BgcqhkjOOAQBMIIBHgKBgQC1PCOasFhlfMc1yjdcp7zkzXGiW+MpVuFlsdYwkAa9"
      "sIvNrQLi2ulxcnNBeCHKDbk7U+J3/QwO2XanapQMUqvfjfjL1QQ5Vf7ENUWPNP7c"
      "Evx82Nb5jWdHyRfV//TciBZN8GLNEbfhtWlhI6CbDW1AaY0nPZ879rSIk7/aNKZ3"
      "FQIVALcr8uQAmnV+3DLIA5nTo0Bg0bjLAoGAJG7meUtQbMulRMdjzeCoya2FXdm+"
      "4acvInE9/+MybXTB3bFANMyw6WTvk4K9RK8tm52N95cykTjpAbxqTMaXwkdWbOFd"
      "VKAKnyxi/UKtY9Q6NmwJB2hbA1GUzhPko8rEda66CGl0VbyM1lKMJjA+wp9pG110"
      "L0ov19Q9fvqKp5UDgYUAAoGBAKxAQg7MqCgkC0MJftYjNaKM5n1iZv4j1li49zKf"
      "Y5nTLP+vYAvg0owLNYvJ5ncKfY1DACPU4/+tC7TTua95wgj5rwvAXnzgSyOGuSr0"
      "fK9DyrH6E0LfXT+WuIQHahm2iSbxqPrChlnp5/EXDTBaO6Qfdpq0BP48ClZebxcA"
      "+TYFo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVy"
      "YXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUmSpShswvWtEABd+l3WxccRcCydUw"
      "HwYDVR0jBBgwFoAUggh/2wAChuhTKqX6WK5nfxQ4yGAwDQYJKoZIhvcNAQEFBQAD"
      "gYEAgfnAu/gMJRC/BFwkgvrHL0TV4ffPVAf7RSnZS6ib4IHGgrvXJvL+Qh7vHykv"
      "ZIqD2L96nY2EaSNr0yXrT81YROndOQUJNx4Y/W8m6asu4hzANNZqWCbApPDIMK6V"
      "cPA1wrKgZqbWp218WBqI2v9pXV0O+jpzxq1+GeQV2UsbRwc=";

    std::string message = "c2lnbmVkIGRhdGEK";
    std::string signature = "MC0CFQCL2pDA4S/zsHkDUCWOq7K6ebG14gIUHHoLsbeUd+BEqBXB6XjmcTncBRA=";

    CertSvcString msgb64, sigb64, msg, sig;

    int result = certsvc_string_new(vinstance, message.c_str(), message.size(), &msgb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

    result = certsvc_string_new(vinstance, signature.c_str(), signature.size(), &sigb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

    CertSvcCertificate cert;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)magda.c_str(),
        magda.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    result = certsvc_base64_decode(msgb64, &msg);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");
    result = certsvc_base64_decode(sigb64, &sig);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    int status;
    result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
    RUNNER_ASSERT_MSG(status == CERTSVC_TRUE, "Error in verify message.");
}

/*
 * author:      ---
 * test:        Verification of RSA SHA1.
 * description: Testing certificate RSA SH1.
 * expect:      Certificate RSA SH1 should be correct.
 */
RUNNER_TEST(test09_message_verify_rsa_sha1)
{
    std::string filip =
      "MIIC4zCCAkygAwIBAgIJAMdKgvadG/Z+MA0GCSqGSIb3DQEBBQUAMHIxCzAJBgNV"
      "BAYTAlBMMQwwCgYDVQQIEwNNYXoxEDAOBgNVBAoTB1NhbXN1bmcxDTALBgNVBAsT"
      "BFNQUkMxEDAOBgNVBAMTB1NhbXN1bmcxIjAgBgkqhkiG9w0BCQEWE3NhbXN1bmdA"
      "c2Ftc3VuZy5jb20wHhcNMTExMDA1MTIwMDUxWhcNMjExMDAyMTIwMDUxWjB4MQsw"
      "CQYDVQQGEwJQTDEMMAoGA1UECBMDTUFaMQwwCgYDVQQHEwNMZWcxDDAKBgNVBAoT"
      "A1NhbTENMAsGA1UECxMEU1BSQzEOMAwGA1UEAxMFRmlsaXAxIDAeBgkqhkiG9w0B"
      "CQEWEWZpbGlwQHNhbXN1bmcuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
      "gQDS/sS0wXSCb34ojN8bWFd4Pl9eTLHh18UNGsPpLpp4itdfuc/OgyqaSoDwBzVh"
      "EWAVLCTxexUa4Ncva+41NbkW4RCsFzeGs0ktpu1+8Q+v0QEOGqVF2rQkgilzDF/o"
      "O56Fxw9vG1OA+qdQd3yOAV2EqLNBPrEYB9K5GFyffrakSQIDAQABo3sweTAJBgNV"
      "HRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZp"
      "Y2F0ZTAdBgNVHQ4EFgQUeyy3iV75KtOkpPFd6mnR9dFGZMwwHwYDVR0jBBgwFoAU"
      "ggh/2wAChuhTKqX6WK5nfxQ4yGAwDQYJKoZIhvcNAQEFBQADgYEADtv0CBrQ1QCM"
      "H9jKFjpSpq7zFKMXQeVtb/Zie823//woicg8kxnP5sS4dJWNXNb1iMLdhgV80g1y"
      "t3gTWPxTtFzprQyNiJHTmrbNWXLX1roRVGUE/I8Q4xexqpbNlJIW2Jjm/kqoKfnK"
      "xORG6HNPXZV29NY2fDRPPOIYoFQzrXI=";

    std::string message = "Q3plZ28gdHUgc3p1a2Fzej8K";
    std::string signature =
      "xEIpVjEIUoDkYGtX2ih6Gbya0/gr7OMdvbBKmjqzfNh9GHqwrgjglByeC5sspUzPBUF4Vmg/hZqL"
      "gSsxXw9bKEa8c6mTQoNX51IC0ELPsoUMIJF1gGdFu0SzKptvU0+ksiiOM+70+s5t8s3z0G5PeA7O"
      "99oq8UlrX7GDlxaoTU4=";

    CertSvcString msgb64, sigb64, msg, sig;

    int result = certsvc_string_new(vinstance, message.c_str(), message.size(), &msgb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

    result = certsvc_string_new(vinstance, signature.c_str(), signature.size(), &sigb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

    CertSvcCertificate cert;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)filip.c_str(),
        filip.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    result = certsvc_base64_decode(msgb64, &msg);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    result = certsvc_base64_decode(sigb64, &sig);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    int status;
    result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
    RUNNER_ASSERT_MSG(status == CERTSVC_SUCCESS, "Error in verify message.");

    message[0] = 'q';

    result = certsvc_string_new(vinstance, message.c_str(), message.size(), &msgb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

    result = certsvc_base64_decode(msgb64, &msg);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    result = certsvc_message_verify(cert, msg, sig, "sha1", &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
    RUNNER_ASSERT_MSG(status == CERTSVC_INVALID_SIGNATURE, "Error in verify message.");
}

/*
 * author:      ---
 * test:        Verification of RSA SHA1.
 * description: Testing certificate RSA SHA256.
 * expect:      Certificate RSA SH256 should be correct.
 */
RUNNER_TEST(test10_message_verify_rsa_sha256)
{
    std::string filip =
      "MIIC4zCCAkygAwIBAgIJAMdKgvadG/Z+MA0GCSqGSIb3DQEBBQUAMHIxCzAJBgNV"
      "BAYTAlBMMQwwCgYDVQQIEwNNYXoxEDAOBgNVBAoTB1NhbXN1bmcxDTALBgNVBAsT"
      "BFNQUkMxEDAOBgNVBAMTB1NhbXN1bmcxIjAgBgkqhkiG9w0BCQEWE3NhbXN1bmdA"
      "c2Ftc3VuZy5jb20wHhcNMTExMDA1MTIwMDUxWhcNMjExMDAyMTIwMDUxWjB4MQsw"
      "CQYDVQQGEwJQTDEMMAoGA1UECBMDTUFaMQwwCgYDVQQHEwNMZWcxDDAKBgNVBAoT"
      "A1NhbTENMAsGA1UECxMEU1BSQzEOMAwGA1UEAxMFRmlsaXAxIDAeBgkqhkiG9w0B"
      "CQEWEWZpbGlwQHNhbXN1bmcuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
      "gQDS/sS0wXSCb34ojN8bWFd4Pl9eTLHh18UNGsPpLpp4itdfuc/OgyqaSoDwBzVh"
      "EWAVLCTxexUa4Ncva+41NbkW4RCsFzeGs0ktpu1+8Q+v0QEOGqVF2rQkgilzDF/o"
      "O56Fxw9vG1OA+qdQd3yOAV2EqLNBPrEYB9K5GFyffrakSQIDAQABo3sweTAJBgNV"
      "HRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZp"
      "Y2F0ZTAdBgNVHQ4EFgQUeyy3iV75KtOkpPFd6mnR9dFGZMwwHwYDVR0jBBgwFoAU"
      "ggh/2wAChuhTKqX6WK5nfxQ4yGAwDQYJKoZIhvcNAQEFBQADgYEADtv0CBrQ1QCM"
      "H9jKFjpSpq7zFKMXQeVtb/Zie823//woicg8kxnP5sS4dJWNXNb1iMLdhgV80g1y"
      "t3gTWPxTtFzprQyNiJHTmrbNWXLX1roRVGUE/I8Q4xexqpbNlJIW2Jjm/kqoKfnK"
      "xORG6HNPXZV29NY2fDRPPOIYoFQzrXI=";

    std::string message = "Q3plZ28gdHUgc3p1a2Fzej8K";
    std::string signature =
      "a5nGT6wnbQ8MLwLkG965E4e1Rv983E+v3nolLvvjuAKnfgWYb+70Da+T9ggYDTjngq+EBgC30w1p"
      "EScrwye8ELefvRxDWy1+tWR4QRW/Nd4oN2U/pvozoabDSpe9Cvt0ECEOWKDqIYYnoWFjOiXg9VwD"
      "HVVkQXvsSYu6thX/Xsk=";

    CertSvcString msgb64, sigb64, msg, sig;

    int result = certsvc_string_new(vinstance, message.c_str(), message.size(), &msgb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

    result = certsvc_string_new(vinstance, signature.c_str(), signature.size(), &sigb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading signature.");

    CertSvcCertificate cert;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)filip.c_str(),
        filip.size(),
        CERTSVC_FORM_DER_BASE64,
        &cert);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading certificate.");

    result = certsvc_base64_decode(msgb64, &msg);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    result = certsvc_base64_decode(sigb64, &sig);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    int status;
    result = certsvc_message_verify(cert, msg, sig, "sha256", &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
    RUNNER_ASSERT_MSG(status == CERTSVC_SUCCESS, "Error in verify message.");

    message[0] = 'q';

    result = certsvc_string_new(vinstance, message.c_str(), message.size(), &msgb64);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in reading messsage.");

    result = certsvc_base64_decode(msgb64, &msg);
    RUNNER_ASSERT_MSG(result == CERTSVC_TRUE, "Error in decoding base64.");

    result = certsvc_message_verify(cert, msg, sig, "sha256", &status);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in verify message.");
    RUNNER_ASSERT_MSG(status == CERTSVC_INVALID_SIGNATURE, "Error in verify message.");
}

/*
 * author:      ---
 * test:        Certificate verification.
 * description: Verification of certificates.
 * expect:      Verification should return expected results.
 */
RUNNER_TEST(test14_certificate_verify)
{
    const int MAXC = 3;
    std::string cert[MAXC];
    cert[0] = // aia_signer
    "MIIDXTCCAsagAwIBAgIBAjANBgkqhkiG9w0BAQUFADB6MQswCQYDVQQGEwJLUjEO"
    "MAwGA1UECAwFU2VvdWwxEDAOBgNVBAoMB1NhbXN1bmcxEzARBgNVBAsMClRpemVu"
    "IFRlc3QxFzAVBgNVBAMMDlRlc3QgU2Vjb25kIENBMRswGQYJKoZIhvcNAQkBFgx0"
    "dEBnbWFpbC5jb20wHhcNMTQwNjE4MDgxMTA0WhcNMTUwNjE4MDgxMTA0WjB7MQsw"
    "CQYDVQQGEwJLUjEOMAwGA1UECAwFU2VvdWwxEDAOBgNVBAoMB1NhbXN1bmcxFzAV"
    "BgNVBAsMDlRpemVuIFRlc3QgQUlBMRQwEgYDVQQDDAtUZXN0IFNpZ25lcjEbMBkG"
    "CSqGSIb3DQEJARYMdHRAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB"
    "iQKBgQCwgKw+/71jWXnx4bLLZrTPmE+NrDfHSfZx8yTGYeewMzP6ZlXM8WduxNiq"
    "pqm7G2XN182GEXsdoxwa09HtMVGqSGA/BCamD1Z6liHOEb4UTB3ROJ1lZDDkyJ9a"
    "gZOfoZst/Aj8+bwV3x3ie+p4a2w/8eSsalrfef2gX6khaSsJOwIDAQABo4HxMIHu"
    "MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl"
    "cnRpZmljYXRlMB0GA1UdDgQWBBRL0nKiNUjzh1/LPvZoqLvnVfOZqjAfBgNVHSME"
    "GDAWgBSpSfNbE0V2NHn/V5f660v2cWwYgDBzBggrBgEFBQcBAQRnMGUwIQYIKwYB"
    "BQUHMAGGFWh0dHA6Ly8xMjcuMC4wLjE6ODg4ODBABggrBgEFBQcwAoY0aHR0cDov"
    "L1NWUlNlY3VyZS1HMy1haWEudmVyaXNpZ24uY29tL1NWUlNlY3VyZUczLmNlcjAN"
    "BgkqhkiG9w0BAQUFAAOBgQABP+yru9/2auZ4ekjV03WRg5Vq/rqmOHDruMNVbZ4H"
    "4PBLRLSpC//OGahgEgUKe89BcB10lUi55D5YME3Do89I+hFugv0BPGaA201iLOhL"
    "/0u0aVm1yJxNt1YjW2fMKqnCHgjoHzh0wQC1pIb5vxJrYCn3Pbhml7W6JPDDJHfm"
    "XQ==";

    cert[1] = // second_ca
    "MIIDLzCCApigAwIBAgIBATANBgkqhkiG9w0BAQUFADB4MQswCQYDVQQGEwJLUjEO"
    "MAwGA1UECAwFU2VvdWwxEDAOBgNVBAoMB1NhbXN1bmcxEzARBgNVBAsMClRpemVu"
    "IFRlc3QxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTEbMBkGCSqGSIb3DQEJARYMdHRA"
    "Z21haWwuY29tMB4XDTE0MDYxODA4MTA1OVoXDTE1MDYxODA4MTA1OVowejELMAkG"
    "A1UEBhMCS1IxDjAMBgNVBAgMBVNlb3VsMRAwDgYDVQQKDAdTYW1zdW5nMRMwEQYD"
    "VQQLDApUaXplbiBUZXN0MRcwFQYDVQQDDA5UZXN0IFNlY29uZCBDQTEbMBkGCSqG"
    "SIb3DQEJARYMdHRAZ21haWwuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
    "gQDLJrMAF/JzxIIrQzQ/3FGt7cGAUEYaEFSo+hcDKYRXaZC33/kkVANYFh+log9e"
    "MJUUlt0TBOg79tOnS/5MBwWaVLEOLalv0Uj2FfjEMpGd/xEF6Vv34mSTcWadMHyD"
    "wYwDZVwdFkrvOkA6WwgwS8XSrpbH/nkKUkKpk+YYljKEzQIDAQABo4HGMIHDMB0G"
    "A1UdDgQWBBSpSfNbE0V2NHn/V5f660v2cWwYgDAfBgNVHSMEGDAWgBRkHk9Lnhgv"
    "vOIwxHOma54FGt8SCDAMBgNVHRMEBTADAQH/MHMGCCsGAQUFBwEBBGcwZTAhBggr"
    "BgEFBQcwAYYVaHR0cDovLzEyNy4wLjAuMTo4ODg4MEAGCCsGAQUFBzAChjRodHRw"
    "Oi8vU1ZSU2VjdXJlLUczLWFpYS52ZXJpc2lnbi5jb20vU1ZSU2VjdXJlRzMuY2Vy"
    "MA0GCSqGSIb3DQEBBQUAA4GBAFonDQzs/Ts1sEDW3f5EmuKVZlpH9sLstSLJxZK8"
    "+v88Jbz451/Lf8hxvnMv3MwExXr9qPKPlvKRfj+bbLB5KTEcZ5zhDpJ7SDYesdUd"
    "RKOMSN0JIRL3JOCdYHOnJk6o+45vZ/TNv0lsiK90vxH2jo2EXnNG+jeyBGwp+3H6"
    "RWHw";

    cert[2] = // root_ca
    "MIIDLTCCApagAwIBAgIBADANBgkqhkiG9w0BAQUFADB4MQswCQYDVQQGEwJLUjEO"
    "MAwGA1UECAwFU2VvdWwxEDAOBgNVBAoMB1NhbXN1bmcxEzARBgNVBAsMClRpemVu"
    "IFRlc3QxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTEbMBkGCSqGSIb3DQEJARYMdHRA"
    "Z21haWwuY29tMB4XDTE0MDYxODA4MTA1MVoXDTE1MDYxODA4MTA1MVoweDELMAkG"
    "A1UEBhMCS1IxDjAMBgNVBAgMBVNlb3VsMRAwDgYDVQQKDAdTYW1zdW5nMRMwEQYD"
    "VQQLDApUaXplbiBUZXN0MRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0ExGzAZBgkqhkiG"
    "9w0BCQEWDHR0QGdtYWlsLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"
    "o6ZegsQ9hScM1yD7ejv44xUTJDjTlcGweHh76Im22x6yAljM2+dKdj3EIVGt0BA3"
    "6qdZFl8WOxzQGcAzQY7GFOXQVog4UjqHMxmWwAx5jQyBzIieAj4HZ2lquPBiyiIe"
    "HAo6sCSWsxnh7PqvWaAypPZVEqOJ3ga5rXyDCcjzQ8ECAwEAAaOBxjCBwzAdBgNV"
    "HQ4EFgQUZB5PS54YL7ziMMRzpmueBRrfEggwHwYDVR0jBBgwFoAUZB5PS54YL7zi"
    "MMRzpmueBRrfEggwDAYDVR0TBAUwAwEB/zBzBggrBgEFBQcBAQRnMGUwIQYIKwYB"
    "BQUHMAGGFWh0dHA6Ly8xMjcuMC4wLjE6ODg4ODBABggrBgEFBQcwAoY0aHR0cDov"
    "L1NWUlNlY3VyZS1HMy1haWEudmVyaXNpZ24uY29tL1NWUlNlY3VyZUczLmNlcjAN"
    "BgkqhkiG9w0BAQUFAAOBgQAyRJXTZcwRCkRNGZQCO8txHvrmgv8vQwnZZF6SwyY/"
    "Bry0fmlehtN52NLjjPEG6u9YFYfzSkjQlVR0qfQ2mNs3d6AKFlOdZOT6cuEIZuKe"
    "pDb2Tx5JJbIN6N3fE/lVSW88K9aSCF2n15gYTSVmD0juHuLAoWnIicaa+Sbe2Tsj"
    "AQ==";

    CertSvcCertificate certificate[MAXC];

    int result, status;

    for (int i=0; i<MAXC; ++i) {
        int result = certsvc_certificate_new_from_memory(
            vinstance,
            (const unsigned char*)cert[i].c_str(),
            cert[i].size(),
            CERTSVC_FORM_DER_BASE64,
            &certificate[i]);
        RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");
    }

    result = certsvc_certificate_verify(certificate[0], &certificate[1], MAXC-1, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify(certificate[0], certificate, MAXC-1, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify(certificate[0], certificate, 1, certificate, MAXC, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify(certificate[0], &certificate[2], 1, certificate, MAXC, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");


    // certsvc_certificate_verify_with_caflag
    result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC-1, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, 1, certificate, MAXC, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify_with_caflag(certificate[0], &certificate[2], 1, certificate, MAXC, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");
}

/*
 * author:      ---
 * test:        Testing certificate primitives.
 * description: Certificate structure is tested.
 * expect:      Certificate should contain cexpected informations.
 */
RUNNER_TEST(test15_cprimitives)
{
    const int MAXB = 1024;
    const std::string cert =
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

    CertSvcCertificate certificate;

    int result;

    result = certsvc_certificate_new_from_memory(
        vinstance,
        (const unsigned char*)cert.c_str(),
        cert.size(),
        CERTSVC_FORM_DER_BASE64,
        &certificate);

    X509 *x509 = NULL;
    result = certsvc_certificate_dup_x509(certificate, &x509);

    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certsvc_certificate_dup_x509.");
    RUNNER_ASSERT_MSG(x509 != NULL, "Error in certsvc_certificate_dup_x509.");

    X509_NAME *name = X509_get_subject_name(x509);
    char buffer[MAXB];
    X509_NAME_oneline(name, buffer, MAXB);
    std::string expected = "/C=US/O=VeriSign, Inc./OU=Class 3 Public Primary Certification Authority";

    RUNNER_ASSERT_MSG(expected == buffer, "Content does not match");

    certsvc_certificate_free_x509(x509);
}


/*
 * author:      ---
 * test:        Certificate verification.
 * description: Verification of certificates.
 * expect:      Verification should return expected results.
 */
RUNNER_TEST(test16_certificate_verify_with_caflag_selfsign_root)
{
    const int MAXC = 2;
    std::string cert[MAXC];
    cert[0] = // v1_signer
      "MIICdzCCAeACAQcwDQYJKoZIhvcNAQEFBQAwgYIxCzAJBgNVBAYTAktSMQ4wDAYD"
      "VQQIDAVTZW91bDEQMA4GA1UECgwHU2Ftc3VuZzETMBEGA1UECwwKVGl6ZW4gVGVz"
      "dDEfMB0GA1UEAwwWVGVzdCBSb290IENBIFZlcnNpb24gMTEbMBkGCSqGSIb3DQEJ"
      "ARYMdHRAZ21haWwuY29tMB4XDTE0MDYxNDA4MTI1MFoXDTE1MDYxNDA4MTI1MFow"
      "gYQxCzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UECgwHU2Ftc3Vu"
      "ZzETMBEGA1UECwwKVGl6ZW4gVGVzdDEhMB8GA1UEAwwYVGVzdCBTZWNvbmQgQ0Eg"
      "VmVyc2lvbiAxMRswGQYJKoZIhvcNAQkBFgx0dEBnbWFpbC5jb20wgZ8wDQYJKoZI"
      "hvcNAQEBBQADgY0AMIGJAoGBAKOqFNxvO2jYcq5kqVehHH5k1D1dYwhBnH/SReWE"
      "OTSbH+3lbaKhJQHPHjsndENUxPInF6r0prO3TqoMB6774Pmc+znoVfLsHvWorhyr"
      "8iQNyaSgVWt0+8L0FU8iReqr5BR6YcZpnVRCV9dAIcf6FIVGUGZhTs/NvZDzIc4T"
      "9RrLAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAGDDvWhdMFg4GtDdytrK/GJ9TxX5F"
      "9iA/8qCl0+JU1U7jUVIcX77AxeZGBtq02X+DtjEWqnepS1iYO2TUHZBKRRCB2+wF"
      "ZsQ5XWngLSco+UvqUzMpWIQqslDXixWSR+Bef2S7iND3u8HJLjTncMcuJNpoXsFK"
      "bUiLqMVGQCkGZMo=";

    cert[1] = // v1_root
      "MIICdTCCAd4CAQYwDQYJKoZIhvcNAQEFBQAwgYIxCzAJBgNVBAYTAktSMQ4wDAYD"
      "VQQIDAVTZW91bDEQMA4GA1UECgwHU2Ftc3VuZzETMBEGA1UECwwKVGl6ZW4gVGVz"
      "dDEfMB0GA1UEAwwWVGVzdCBSb290IENBIFZlcnNpb24gMTEbMBkGCSqGSIb3DQEJ"
      "ARYMdHRAZ21haWwuY29tMB4XDTE0MDYxNDA4MTIzNVoXDTE1MDYxNDA4MTIzNVow"
      "gYIxCzAJBgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UECgwHU2Ftc3Vu"
      "ZzETMBEGA1UECwwKVGl6ZW4gVGVzdDEfMB0GA1UEAwwWVGVzdCBSb290IENBIFZl"
      "cnNpb24gMTEbMBkGCSqGSIb3DQEJARYMdHRAZ21haWwuY29tMIGfMA0GCSqGSIb3"
      "DQEBAQUAA4GNADCBiQKBgQDtxGjhpaUK6xa4+sjMQfkKRAtjFkjZasVIt7uKUy/g"
      "GcC5i5aoorfyX/NBQLAVoIHMogHLgitehKL5l13tLR7DSETrG9V3Yx9bkWRcjyqH"
      "1TkD+NDOmhTtVuqIh4hrGKITlZK35hOh0IUEfYNNL8uq/11fVPpR3Yx97PT/j4w1"
      "uwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAOHjfa7nbPKhqR0mGfsscPQZZAZzKq9y"
      "ttdjTaNbnybzcJzcN3uwOdYKMf26Dn968nAPkukWe8j6GyMJ1C9LMAWqMn5hl0rI"
      "x6mUBfKZrl33BKH4KTYOrt0vnHdrCM2TwMkwMZ5ja5bBnbNrfF4e0HIAMor4rnVP"
      "WDSlESMMmtTm";

    CertSvcCertificate certificate[MAXC];

    int result, status;

    for (int i=0; i<MAXC; ++i) {
        int result = certsvc_certificate_new_from_memory(
            vinstance,
            (const unsigned char*)cert[i].c_str(),
            cert[i].size(),
            CERTSVC_FORM_DER_BASE64,
            &certificate[i]);
        RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error reading certificate");
    }

    result = certsvc_certificate_verify(certificate[0], certificate, MAXC, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == status, "Error in certificate verification process.");

    result = certsvc_certificate_verify_with_caflag(certificate[0], certificate, MAXC, NULL, 0, &status);
    RUNNER_ASSERT_MSG(CERTSVC_SUCCESS == result, "Error in certificate verification function.");
    RUNNER_ASSERT_MSG(CERTSVC_FAIL == status, "Error in certificate verification process.");
}
