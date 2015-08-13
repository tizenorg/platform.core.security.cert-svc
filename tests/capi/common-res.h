/*
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
/*
 * @file        common-res.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       This file is the common resource for certsvc capi test
 */
#pragma once

#include <vector>
#include <string>

#include <cert-svc/cinstance.h>

extern CertSvcInstance vinstance;

namespace TestData {

class SigComponents {
public:
	SigComponents(std::string &cert, std::string &mes, std::string &sig)
	  : certificate(cert)
	  , message(mes)
	  , signature(sig) {}

	std::string certificate;
	std::string message;
	std::string signature;
};

extern const std::string subjectGoogleCA;
/*
 *  Not Before: Jan 29 00:00:00 1996 GMT
 *  Not After : Aug  1 23:59:59 2028 GMT
 */
extern const std::string googleCA;

/*
 *  Signed by googleCA
 *  Not Before: May 13 00:00:00 2004 GMT
 *  Not After : May 12 23:59:59 2014 GMT
 */
extern const std::string google2nd;

/*
 *  Signed by google2nd
 *  Not Before: Oct 26 00:00:00 2011 GMT
 *  Not After : Sep 30 23:59:59 2013 GMT
 */
extern const std::string certEE;

/*
 *  Issuer  : /C=KO/ST=Kyeongkido/L=Suwon/O=Samsung/OU=SoftwareCenter/CN=TizenSecurity/emailAddress=k.tak@samsung.com
 *  Subject : /C=PO/ST=SeoulState/L=Seoul/O=SamsungSecond/OU=SoftwareCenterSecond/CN=TizenSecuritySecond/emailAddress=kyungwook.tak@gmail.com
 */
extern const std::string certFullField;

/*
 *  Not Before: Oct  5 12:11:33 2011 GMT
 *  Not After : Oct  2 12:11:33 2021 GMT
 */
extern const SigComponents magda;

/*
 *  Not Before: Oct  5 12:00:51 2011 GMT
 *  Not After : Oct  2 12:00:51 2021 GMT
 */
extern const SigComponents filipSHA1;
extern const SigComponents filipSHA256;

/*
 *  Signer
 *  Not Before: Jun 18 08:11:04 2014 GMT
 *  Not After : Jun 18 08:11:04 2015 GMT
 *
 *  Second CA
 *  Not Before: Jun 18 08:10:59 2014 GMT
 *  Not After : Jun 18 08:10:59 2015 GMT
 *
 *  Root CA
 *  Not Before: Jun 18 08:10:51 2014 GMT
 *  Not After : Jun 18 08:10:51 2015 GMT
 */
extern std::vector<std::string> certChain;

/*
 *  Second CA
 *  Not Before: Jun 14 08:12:50 2014 GMT
 *  Not After : Jun 14 08:12:50 2015 GMT
 *
 *  Root CA
 *  Not Before: Jun 14 08:12:35 2014 GMT
 *  Not After : Jun 14 08:12:35 2015 GMT
 */
extern std::vector<std::string> certChainSelfSigned;

}
