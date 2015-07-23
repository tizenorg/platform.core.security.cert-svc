/*
 *
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

#include <dpl/test/test_runner.h>
#include <vcore/SignatureFinder.h>
#include <vcore/SignatureValidator.h>
#include "TestEnv.h"

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


const std::string keys_path = "/usr/apps/widget/tests/vcore_keys/";
const std::string widget_store_path = "/usr/apps/widget/tests/vcore_widgets/";
const std::string cert_store_path = "/usr/apps/widget/tests/vcore_certs/";

const std::string anka_ec_key_type = "urn:oid:1.2.840.10045.3.1.7";
const std::string anka_ec_public_key =
        "BGi9RmTUjpqCpQjx6SSiKdfmtjQBFNSN7ghm6TuaH9r4x73WddeLxLioH3VEmFLC+QLiR"\
        "kPxDxL/6YmQdgfGrqk=";

const std::string rsa_modulus =
        "ocwjKEFaPxLNcPTz2PtT2Gyu5jzkWaPo4thjZo3rXuNbD4TzjY02UGnTxvflNeORLpSS1"\
        "PeYr/1E/Nhr7qQAzj9g0DwW7p8zQEdOUi3v76VykeB0pFJH+0Fxp6LVBX9Z+EvZk+dbOy"\
        "GJ4Njm9B6M09axXlV11Anj9B/HYUDfDX8=";
const std::string rsa_exponent = "AQAB";

const std::string magda_dsa_p =
        "2BYIQj0ePUVxzrdBT41eCblraa9Dqag7QXFMCRM2PtyS22JPDKuV77tBc/jg0V3htHWdR"\
        "q9n6/kQDwrP7FIPoLATLIiC3oAYWj46Mr6d9k/tt/JZU6PvULmB2k1wrrmvKUi+U+I5Ro"\
        "qe8ui8lqR9pp9u2WCh2QmFfCohKNjN5qs=";
const std::string magda_dsa_q = "4p4JcDqz+S7CbWyd8txApZw0sik=";
const std::string magda_dsa_g =
        "AQrLND1ZGFvzwBpPPXplmPh1ijPx1O2gQEvPvyjR88guWcGqQc0m7dTb6PEvbI/oZ0o91"\
        "k7VEkfthURnNR1WtOLT8dmAuKQfwTQLPwCwUM/QiuWSlCyKLTE4Ev8aOG7ZqWudsKm/td"\
        "n9pUNGtcod1wo1ZtP7PfEJ6rYZGQDOlz8=";

const std::string tizen_partner =
"MIICozCCAgwCCQD9IBoOxzq2hjANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMC"
"S1IxDjAMBgNVBAgMBVN1d29uMQ4wDAYDVQQHDAVTdXdvbjEWMBQGA1UECgwNVGl6"
"ZW4gVGVzdCBDQTEiMCAGA1UECwwZVGl6ZW4gRGlzdHJpYnV0b3IgVGVzdCBDQTEq"
"MCgGA1UEAwwhVGl6ZW4gUGFydG5lciBEaXN0cmlidXRvciBSb290IENBMB4XDTEy"
"MTAyNjA4MTIzMVoXDTIyMTAyNDA4MTIzMVowgZUxCzAJBgNVBAYTAktSMQ4wDAYD"
"VQQIDAVTdXdvbjEOMAwGA1UEBwwFU3V3b24xFjAUBgNVBAoMDVRpemVuIFRlc3Qg"
"Q0ExIjAgBgNVBAsMGVRpemVuIERpc3RyaWJ1dG9yIFRlc3QgQ0ExKjAoBgNVBAMM"
"IVRpemVuIFBhcnRuZXIgRGlzdHJpYnV0b3IgUm9vdCBDQTCBnzANBgkqhkiG9w0B"
"AQEFAAOBjQAwgYkCgYEAnIBA2qQEaMzGalP0kzvwUxdCC6ybSC/fb+M9iGvt8QXp"
"ic2yARQB+bIhfbEu1XHwE1jCAGxKd6uT91b4FWr04YwnBPoRX4rBGIYlqo/dg+pS"
"rGyFjy7vfr0BOdWp2+WPlTe7SOS6bVauncrSoHxX0spiLaU5LU686BKr7YaABV0C"
"AwEAATANBgkqhkiG9w0BAQUFAAOBgQAX0Tcfmxcs1TUPBdr1U1dx/W/6Y4PcAF7n"
"DnMrR0ZNRPgeSCiVLax1bkHxcvW74WchdKIb24ZtAsFwyrsmUCRV842YHdfddjo6"
"xgUu7B8n7hQeV3EADh6ft/lE8nalzAl9tALTxAmLtYvEYA7thvDoKi1k7bN48izL"
"gS9G4WEAUg==";

const std::string tizen_partner_operator =
"MIICzDCCAjWgAwIBAgIJAJrv22F9wyp/MA0GCSqGSIb3DQEBBQUAMIGeMQswCQYD"
"VQQGEwJLUjEOMAwGA1UECAwFU3V3b24xDjAMBgNVBAcMBVN1d29uMRYwFAYDVQQK"
"DA1UaXplbiBUZXN0IENBMSIwIAYDVQQLDBlUaXplbiBEaXN0cmlidXRvciBUZXN0"
"IENBMTMwMQYDVQQDDCpUaXplbiBQYXJ0bmVyLU9wZXJhdG9yIERpc3RyaWJ1dG9y"
"IFJvb3QgQ0EwHhcNMTIxMjEzMDUzOTMyWhcNMjIxMjExMDUzOTMyWjCBnjELMAkG"
"A1UEBhMCS1IxDjAMBgNVBAgMBVN1d29uMQ4wDAYDVQQHDAVTdXdvbjEWMBQGA1UE"
"CgwNVGl6ZW4gVGVzdCBDQTEiMCAGA1UECwwZVGl6ZW4gRGlzdHJpYnV0b3IgVGVz"
"dCBDQTEzMDEGA1UEAwwqVGl6ZW4gUGFydG5lci1PcGVyYXRvciBEaXN0cmlidXRv"
"ciBSb290IENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9X0Hw0EfAuagg"
"De9h6Jtvh8Df4fyVbvLm9VNea/iVP3/qTbG8tNqoQ32lu0SwzAZBnjpvpbxzsWs9"
"pSYo7Ys1fymHlu+gf+kmTGTVscBrAHWkr4O0m33x2FYfy/wmu+IImnRDYDud83rN"
"tjQmMO6BihN9Lb6kLiEtVIa8ITwdQwIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0G"
"CSqGSIb3DQEBBQUAA4GBAHS2M2UnfEsZf80/sT84xTcfASXgpFL/1M5HiAVpR+1O"
"UwLpLyqHiGQaASuADDeGEfcIqEf8gP1SzvnAZqLx9GchbOrOKRleooVFH7PRxFBS"
"VWJ5Fq46dJ1mCgTWSkrL6dN5j9hWCzzGfv0Wco+NAf61n9kVbCv7AScIJwQNltOy";

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

const std::string crlExampleCertificate =
"MIIFlDCCBHygAwIBAgIBADANBgkqhkiG9w0BAQUFADBDMRIwEAYKCZImiZPyLGQB"
"GRYCZXMxGDAWBgoJkiaJk/IsZAEZFghpcmlzZ3JpZDETMBEGA1UEAxMKSVJJU0dy"
"aWRDQTAeFw0wNTA2MjgwNTAyMjhaFw0xNTA2MjYwNTAyMjhaMEMxEjAQBgoJkiaJ"
"k/IsZAEZFgJlczEYMBYGCgmSJomT8ixkARkWCGlyaXNncmlkMRMwEQYDVQQDEwpJ"
"UklTR3JpZENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1CQiWlff"
"ajoMSTuismKqLQ+Mt33Tq4bBpCZvCBXhqan1R0ksILPtK1L7C8QWqPk6AZZpuNmY"
"cNVtJGc8ksgDWvX0EB3GKwZTZ8RrSRlSEe9Otq+Ur7S9uxM1JMmCr6zZTMFANzBS"
"4btnduV78C09IhFYG4OW8IPhNrbfPaeOR+PRPAa/qdSONAwTrM1sZkIvGpAkBWM6"
"Pn7TK9BAK6GLvwgii780fWj3Cwgmp8EDCTievBbWj+z8/apMEy9R0vyB2dWNNCnk"
"6q8VvrjgMsJt33O3BqOoBuZ8R/SS9OFWLFSU3s7cfrRaUSJk/Mx8OGFizRkcXSzX"
"0Nidcg7hX5i78wIDAQABo4ICkTCCAo0wDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E"
"FgQUnUJkLlupXvH/bMg8NtPxtkOYrRowawYDVR0jBGQwYoAUnUJkLlupXvH/bMg8"
"NtPxtkOYrRqhR6RFMEMxEjAQBgoJkiaJk/IsZAEZFgJlczEYMBYGCgmSJomT8ixk"
"ARkWCGlyaXNncmlkMRMwEQYDVQQDEwpJUklTR3JpZENBggEAMA4GA1UdDwEB/wQE"
"AwIBxjARBglghkgBhvhCAQEEBAMCAAcwOwYJYIZIAYb4QgENBC4WLElSSVNHcmlk"
"IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IENlcnRpZmljYXRlMIGZBgNVHR8EgZEw"
"gY4wLqAsoCqGKGh0dHA6Ly93d3cuaXJpc2dyaWQuZXMvcGtpL2NybC9jYWNybC5w"
"ZW0wXKBaoFiGVmxkYXA6Ly9sZGFwLmlyaXNncmlkLmVzOjEzODAvY249SVJJU0dy"
"aWRDQSxkYz1pcmlzZ3JpZCxkYz1lcz9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0"
"MDcGCWCGSAGG+EIBAwQqFihodHRwOi8vd3d3LmlyaXNncmlkLmVzL3BraS9jcmwv"
"Y2FjcmwucGVtME4GCWCGSAGG+EIBCARBFj9odHRwOi8vd3d3LmlyaXNncmlkLmVz"
"L3BraS9wb2xpY3kvMS4zLjYuMS40LjEuNzU0Ny4yLjIuNC4xLjEuMS8waQYDVR0g"
"BGIwYDBeBg0rBgEEAbp7AgIEAQEBME0wSwYIKwYBBQUHAgEWP2h0dHA6Ly93d3cu"
"aXJpc2dyaWQuZXMvcGtpL3BvbGljeS8xLjMuNi4xLjQuMS43NTQ3LjIuMi40LjEu"
"MS4xLzANBgkqhkiG9w0BAQUFAAOCAQEAaqRfyLER+P2QOZLLdz66m7FGsgtFsAEx"
"wiNrIChFWfyHVZG7Ph1fn/GDD5LMsrU23lx3NBN5/feHuut1XNYKNs8vtV07D70r"
"DKjUlPbmWV0B+/GDxe1FDGop/tKQfyHSUaBuauXChFU/2INu5lhBerNl7QxNJ1ws"
"cWGiT7R+L/2EjgzWgH1V/0zmIOMep6kY7MUs8rlyF0O5MNFs232cA1trl9kvhAGU"
"9p58Enf5DWMrh17SPH586yIJeiWZtPez9G54ftY+XIqfn0X0zso0dnoXNJQYS043"
"/5vSnoHdRx/EmN8yjeEavZtC48moN0iJ38eB44uKgCD77rZW5s1XqA==";

} // namespace anonymous

using namespace ValidationCore;

/*
 * test: Class SignatureFinder
 * description: SignatureFinder should search directory passed as
 * param of constructor.
 * expected: Signature finder should put information about 3
 * signture files in SinatureFileInfoSet.
 */
RUNNER_TEST(test01_signature_finder)
{
    SignatureFileInfoSet signatureSet;
    SignatureFinder signatureFinder(widget_path);
    RUNNER_ASSERT_MSG(
        SignatureFinder::NO_ERROR == signatureFinder.find(signatureSet),
        "SignatureFinder failed");
    RUNNER_ASSERT_MSG(signatureSet.size() == 3,
                      "Some signature has not been found");

    SignatureFileInfo first = *(signatureSet.begin());
    RUNNER_ASSERT_MSG(
        std::string("author-signature.xml") == first.getFileName(),
        "Author Signature");
    RUNNER_ASSERT_MSG(-1 == first.getFileNumber(), "Wrong signature number.");
    first = *(signatureSet.rbegin());
    RUNNER_ASSERT_MSG(std::string("signature22.xml") == first.getFileName(),
                      "Wrong signature fileName.");
    RUNNER_ASSERT_MSG(22 == first.getFileNumber(), "Wrong signature number.");
}

/*
 * test: Integration test of SignatureFinder, SignatureReader,
 * SignatureValidator
 * description: Directory passed to SignatureFinded constructor should be searched
 * and 3 signature should be find. All signature should be parsed and verified.
 * expected: Verificator should DISREGARD author signature and VERIFY
 * distrubutor signature.
 */
RUNNER_TEST(test03t01_signature_validator)
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

RUNNER_TEST(test03t02_signature_validator_negative_hash_input)
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

        RUNNER_ASSERT_MSG(
            valResult == SignatureValidator::SIGNATURE_INVALID
            || valResult == SignatureValidator::SIGNATURE_DISREGARD,
            "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(test03t03_signature_validator_negative_signature_input)
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

        RUNNER_ASSERT_MSG(
            valResult == SignatureValidator::SIGNATURE_INVALID
            || valResult == SignatureValidator::SIGNATURE_DISREGARD,
            "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(test03t04_signature_validator_partner)
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

        RUNNER_ASSERT_MSG(
            valResult == SignatureValidator::SIGNATURE_VERIFIED,
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
RUNNER_TEST(test04t01_signature_validator)
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

RUNNER_TEST(test04t02_signature_validator_negative_hash_input)
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

        RUNNER_ASSERT_MSG(
            valResult == SignatureValidator::SIGNATURE_INVALID
            || valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(test04t03_signature_validator_negative_signature_input)
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

        RUNNER_ASSERT_MSG(
            valResult == SignatureValidator::SIGNATURE_INVALID
            || valResult == SignatureValidator::SIGNATURE_DISREGARD,
                "Wrong input file but success.. Errorcode : " << validatorErrorToString(valResult));
    }
}

RUNNER_TEST(test04t04_signature_validator_partner)
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
RUNNER_TEST(test05t01_signature_reference)
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
RUNNER_TEST(test05t02_signature_reference_encoding_dummy)
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
RUNNER_TEST(test05t03_signature_reference_encoding_negative)
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
RUNNER_TEST(test05t04_signature_reference_encoding_space)
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
RUNNER_TEST(test05t05_signature_reference_encoding_space_negative)
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
RUNNER_TEST(test05t06_signature_reference_encoding)
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
RUNNER_TEST(test05t07_signature_reference_encoding_negative)
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

/*
 * test: class Certificate
 * description: Certificate should parse data passed to object constructor.
 * expected: Getters should be able to return certificate information.
 */
RUNNER_TEST(test08t01_Certificate)
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
RUNNER_TEST(test08t02_Certificate)
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
RUNNER_TEST(test08t03_Certificate)
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
RUNNER_TEST(test08t04_Certificate_isCA)
{
    Certificate cert1(googleCA, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert1.isCA() > 0);

    Certificate cert2(google2nd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert2.isCA() > 0);

    Certificate cert3(google3rd, Certificate::FORM_BASE64);
    RUNNER_ASSERT(cert3.isCA() == 0);
}

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test90_certificate_identifier_find_fingerprint)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(googleCA, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/

/*
 * test: CertificateIdentifier::find(CertificatePtr)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test91_certificate_identifier_find_cert)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    CertificatePtr cert(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertStoreId::Set domain = certIdent.find(cert);

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: google2nd certificate was not added to any group so
 * no domain should be found.
 */
/*
RUNNER_TEST(test92_certificate_identifier_negative)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(google2nd, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!domain.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(!domain.contains(CertStoreId::ORANGE_LEGACY));
}
*/
/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test93_certificate_identifier_find_fingerprint)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(googleCA, Certificate::FORM_BASE64);

    CertStoreId::Set visibilityLevel =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::ORANGE_LEGACY));

    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::VIS_PUBLIC));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_OPERATOR));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_MANUFACTURER));
}
*/

/*
 * test: CertificateIdentifier::find(CertificatePtr)
 * description: Check implementation of fingerprint_list.
 * expected: Google CA certificate was added to TIZEN_MEMBER group
 * and ORANGE_LEGACY. Both domain should be found.
 */
/*
RUNNER_TEST(test94_certificate_identifier_find_cert)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    CertificatePtr cert(new Certificate(googleCA, Certificate::FORM_BASE64));

    CertStoreId::Set visibilityLevel = certIdent.find(cert);

    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_PUBLISHER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::DEVELOPER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_ROOT));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::WAC_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::TIZEN_MEMBER));
    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::ORANGE_LEGACY));

    RUNNER_ASSERT(visibilityLevel.contains(CertStoreId::VIS_PUBLIC));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_OPERATOR));
    RUNNER_ASSERT(!visibilityLevel.contains(CertStoreId::VIS_PARTNER_MANUFACTURER));
}
*/

/*
 * test: CertificateIdentifier::find(Fingerprint)
 * description: Check implementation of fingerprint_list.
 * expected: google2nd certificate was not added to any group so
 * no domain should be found.
 */
/*
RUNNER_TEST(test95_certificate_identifier_negative)
{
    CertificateIdentifier certIdent;
    CertificateConfigReader reader;
    reader.initialize(
        "/usr/apps/widget/tests/vcore_config/fin_list.xml",
        "/usr/apps/widget/tests/vcore_config/fin_list.xsd");
    reader.read(certIdent);

    Certificate cert(google2nd, Certificate::FORM_BASE64);

    CertStoreId::Set domain =
        certIdent.find(cert.getFingerprint(Certificate::FINGERPRINT_SHA1));

    RUNNER_ASSERT_MSG(domain.getTypeString().empty(), "Domain should be empty.");
}
*/
