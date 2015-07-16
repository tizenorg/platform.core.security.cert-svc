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
 * @file        SignatureValidator.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementatin of tizen signature validation protocol.
 */
#include <vcore/SignatureValidator.h>
#include <vcore/CertificateCollection.h>
#include <vcore/Certificate.h>
#include <vcore/OCSPCertMgrUtil.h>
#include <vcore/ReferenceValidator.h>
#include <vcore/ValidatorFactories.h>
#include <vcore/XmlsecAdapter.h>
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
#include <vcore/CertificateVerifier.h>
#endif

#include <dpl/log/wrt_log.h>

namespace {
const time_t TIMET_DAY = 60 * 60 * 24;

const std::string TOKEN_ROLE_AUTHOR_URI =
    "http://www.w3.org/ns/widgets-digsig#role-author";
const std::string TOKEN_ROLE_DISTRIBUTOR_URI =
    "http://www.w3.org/ns/widgets-digsig#role-distributor";
const std::string TOKEN_PROFILE_URI =
    "http://www.w3.org/ns/widgets-digsig#profile";

} // namespace anonymouse


static tm _ASN1_GetTimeT(ASN1_TIME* time)
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) /* two digit year */
    {
        t.tm_year = (str[i] - '0') * 10 + (str[i+1] - '0');
        i += 2;
        if (t.tm_year < 70)
            t.tm_year += 100;
    }
    else if (time->type == V_ASN1_GENERALIZEDTIME) /* four digit year */
    {
        t.tm_year =
            (str[i] - '0') * 1000
            + (str[i+1] - '0') * 100
            + (str[i+2] - '0') * 10
            + (str[i+3] - '0');
        i += 4;
        t.tm_year -= 1900;
    }
    t.tm_mon = ((str[i] - '0') * 10 + (str[i+1] - '0')) - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i+2] - '0') * 10 + (str[i+3] - '0');
    t.tm_hour = (str[i+4] - '0') * 10 + (str[i+5] - '0');
    t.tm_min  = (str[i+6] - '0') * 10 + (str[i+7] - '0');
    t.tm_sec  = (str[i+8] - '0') * 10 + (str[i+9] - '0');

    /* Note: we did not adjust the time based on time zone information */
    return t;
}


namespace ValidationCore {

class SignatureValidator::ImplSignatureValidator {
public:
    virtual SignatureValidator::Result check(
        SignatureData &data,
        const std::string &widgetContentPath) = 0;

    virtual SignatureValidator::Result checkList(
        SignatureData &data,
        const std::string &widgetContentPath,
        const std::list<std::string>& uriList) = 0;

    explicit ImplSignatureValidator(bool ocspEnable,
                  bool crlEnable,
                  bool complianceMode)
      : m_complianceModeEnabled(complianceMode)
    {
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
        m_ocspEnable = ocspEnable;
        m_crlEnable = crlEnable;
#else
        (void) ocspEnable;
        (void) crlEnable;
#endif
    }

    virtual ~ImplSignatureValidator(){ }

    bool checkRoleURI(const SignatureData &data) {
        std::string roleURI = data.getRoleURI();

        if (roleURI.empty()) {
            WrtLogW("URI attribute in Role tag couldn't be empty.");
            return false;
        }

        if (roleURI != TOKEN_ROLE_AUTHOR_URI && data.isAuthorSignature()) {
            WrtLogW("URI attribute in Role tag does not "
              "match with signature filename.");
            return false;
        }

        if (roleURI != TOKEN_ROLE_DISTRIBUTOR_URI && !data.isAuthorSignature()) {
            WrtLogW("URI attribute in Role tag does not "
              "match with signature filename.");
            return false;
        }
        return true;
    }

    bool checkProfileURI(const SignatureData &data) {
        if (TOKEN_PROFILE_URI != data.getProfileURI()) {
            WrtLogW(
              "Profile tag contains unsupported value in URI attribute( %s ).", (data.getProfileURI()).c_str());
            return false;
        }
        return true;
    }

    bool checkObjectReferences(const SignatureData &data) {
        ObjectList objectList = data.getObjectList();
        ObjectList::const_iterator iter;
        for (iter = objectList.begin(); iter != objectList.end(); ++iter) {
            if (!data.containObjectReference(*iter)) {
                WrtLogW("Signature does not contain reference for object %s", (*iter).c_str());
                return false;
            }
        }
        return true;
    }
protected:
    bool m_complianceModeEnabled;
#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    bool m_ocspEnable;
    bool m_crlEnable;
#endif
};

class ImplTizenSignatureValidator : public SignatureValidator::ImplSignatureValidator
{
  public:
    SignatureValidator::Result check(SignatureData &data,
            const std::string &widgetContentPath);

    SignatureValidator::Result checkList(SignatureData &data,
            const std::string &widgetContentPath,
            const std::list<std::string>& uriList);
    explicit ImplTizenSignatureValidator(bool ocspEnable,
                       bool crlEnable,
                       bool complianceMode)
      : ImplSignatureValidator(ocspEnable, crlEnable, complianceMode)
    {}

    virtual ~ImplTizenSignatureValidator() {}
};

SignatureValidator::Result ImplTizenSignatureValidator::check(
        SignatureData &data,
        const std::string &widgetContentPath)
{
    bool disregard = false;

    if (!checkRoleURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    if (!checkProfileURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    //  CertificateList sortedCertificateList = data.getCertList();

    CertificateCollection collection;
    collection.load(data.getCertList());

    // First step - sort certificate
    if (!collection.sort()) {
        WrtLogW("Certificates do not form valid chain.");
        return SignatureValidator::SIGNATURE_INVALID_CERT_CHAIN;//SIGNATURE_INVALID;
    }

    // Check for error
    if (collection.empty()) {
        WrtLogW("Certificate list in signature is empty.");
        return SignatureValidator::SIGNATURE_INVALID_CERT_CHAIN;//SIGNATURE_INVALID;
    }

    CertificateList sortedCertificateList = collection.getChain();

    // TODO move it to CertificateCollection
    // Add root CA and CA certificates (if chain is incomplete)
    sortedCertificateList =
        OCSPCertMgrUtil::completeCertificateChain(sortedCertificateList);

    CertificatePtr root = sortedCertificateList.back();

    // Is Root CA certificate trusted?
    CertStoreId::Set storeIdSet = createCertificateIdentifier().find(root);

    WrtLogD("Is root certificate from TIZEN_DEVELOPER domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER));
    WrtLogD("Is root certificate from TIZEN_TEST domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_TEST));
    WrtLogD("Is root certificate from TIZEN_VERIFY domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_VERIFY));
    WrtLogD("Is root certificate from TIZEN_STORE domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_STORE));
    WrtLogD("Is root certificate from TIZEN_PUBLIC domain:  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Is root certificate from TIZEN_PARTNER domain:  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Is root certificate from TIZEN_PLATFORM domain:  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    WrtLogD("Visibility level is public :  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Visibility level is partner :  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Visibility level is platform :  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

	if (data.isAuthorSignature())
	{
		if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
			WrtLogW("author-signature.xml has got unrecognized Root CA "
					"certificate. Signature will be disregarded.");
			disregard = true;
		}
   }
   else
   {
		WrtLogD("signaturefile name = %s", data.getSignatureFileName().c_str());
		if (storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
			WrtLogE("distributor has author level siganture! Signature will be disregarded.");
			return SignatureValidator::SIGNATURE_IN_DISTRIBUTOR_CASE_AUTHOR_CERT;//SIGNATURE_INVALID;
		}


      if (data.getSignatureNumber() == 1)
      {
         if (storeIdSet.contains(CertStoreId::VIS_PUBLIC) || storeIdSet.contains(CertStoreId::VIS_PARTNER) || storeIdSet.contains(CertStoreId::VIS_PLATFORM))
         {
            WrtLogD("Root CA for signature1.xml is correct.");
         }
         else
         {
            WrtLogW("signature1.xml has got unrecognized Root CA "
                       "certificate. Signature will be disregarded.");
            disregard = true;
         }
      }
   }

    data.setStorageType(storeIdSet);
    data.setSortedCertificateList(sortedCertificateList);

    // We add only Root CA certificate because WAC ensure that the rest
    // of certificates are present in signature files ;-)
    XmlSec::XmlSecContext context;
    context.signatureFile = data.getSignatureFileName();
    context.certificatePtr = root;

    // Now we should have full certificate chain.
    // If the end certificate is not ROOT CA we should disregard signature
    // but still signature must be valid... Aaaaaa it's so stupid...
    if (!(root->isSignedBy(root))) {
        WrtLogW("Root CA certificate not found. Chain is incomplete.");
    //  context.allowBrokenChain = true;
    }

    time_t nowTime = time(NULL);

#define CHECK_TIME
#ifdef CHECK_TIME

    ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
    ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

    if (X509_cmp_time(notBeforeTime, &nowTime) > 0  || X509_cmp_time(notAfterTime, &nowTime) < 0)
    {
      struct tm *t;
      struct tm ta, tb, tc;
      char msg[1024];

      t = localtime(&nowTime);
      if (!t)
          return SignatureValidator::SIGNATURE_INVALID_CERT_TIME;

      memset(&tc, 0, sizeof(tc));

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", t->tm_year + 1900, t->tm_mon + 1,t->tm_mday );
      WrtLogD("## System's currentTime : %s", msg);
      fprintf(stderr, "## System's currentTime : %s\n", msg);

      tb = _ASN1_GetTimeT(notBeforeTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tb.tm_year + 1900, tb.tm_mon + 1,tb.tm_mday );
      WrtLogD("## certificate's notBeforeTime : %s", msg);
      fprintf(stderr, "## certificate's notBeforeTime : %s\n", msg);

      ta = _ASN1_GetTimeT(notAfterTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", ta.tm_year + 1900, ta.tm_mon + 1,ta.tm_mday );
      WrtLogD("## certificate's notAfterTime : %s", msg);
      fprintf(stderr, "## certificate's notAfterTime : %s\n", msg);

      if (storeIdSet.contains(CertStoreId::TIZEN_TEST) || storeIdSet.contains(CertStoreId::TIZEN_VERIFY))
      {
        WrtLogD("## TIZEN_VERIFY : check certificate Time : FALSE");
        fprintf(stderr, "## TIZEN_VERIFY : check certificate Time : FALSE\n");
         return SignatureValidator::SIGNATURE_INVALID_CERT_TIME;//SIGNATURE_INVALID;
      }

      int year = (ta.tm_year - tb.tm_year) / 4;

      if(year == 0)
      {
          tc.tm_year = tb.tm_year; 
          tc.tm_mon = tb.tm_mon + 1;
          tc.tm_mday = tb.tm_mday;

          if(tc.tm_mon == 12)
          {
              tc.tm_year = ta.tm_year;       
              tc.tm_mon = ta.tm_mon - 1;
              tc.tm_mday = ta.tm_mday;
              
              if(tc.tm_mon < 0)
              {
                 tc.tm_year = ta.tm_year;
                 tc.tm_mon = ta.tm_mon;
                 tc.tm_mday = ta.tm_mday -1;

                 if(tc.tm_mday == 0)
                 {
                    tc.tm_year = tb.tm_year;                
                    tc.tm_mon = tb.tm_mon;
                    tc.tm_mday = tb.tm_mday +1;
                 }
              }
          }          
      }
      else{
         tc.tm_year = tb.tm_year + year;
         tc.tm_mon = (tb.tm_mon + ta.tm_mon )/2;
         tc.tm_mday = (tb.tm_mday + ta.tm_mday)/2;  
      }

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tc.tm_year + 1900, tc.tm_mon + 1,tc.tm_mday );
      WrtLogD("## cmp cert with validation time : %s", msg);
      fprintf(stderr, "## cmp cert with validation time : %s\n", msg);

      time_t outCurrent = mktime(&tc);
      context.validationTime = outCurrent;
      fprintf(stderr, "## cmp outCurrent time : %ld\n", outCurrent);
      //return SignatureValidator::SIGNATURE_INVALID;
    }

#endif
    // WAC 2.0 SP-2066 The wrt must not block widget installation
    // due to expiration of the author certificate.
#if 0
    time_t notAfter = data.getEndEntityCertificatePtr()->getNotAfter();
    time_t notBefore = data.getEndEntityCertificatePtr()->getNotBefore();

    struct tm *t;

    if (data.isAuthorSignature())
	{
       // time_t 2038 year bug exist. So, notAtter() cann't check...
       /*
       if (notAfter < nowTime)
       {
          context.validationTime = notAfter - TIMET_DAY;
          WrtLogW("Author certificate is expired. notAfter...");
       }
       */

       if (notBefore > nowTime)
       {
          WrtLogW("Author certificate is expired. notBefore time is greater than system-time.");

          t = localtime(&nowTime);
          WrtLogD("System's current Year : %d", (t->tm_year + 1900));
          WrtLogD("System's current month : %d", (t->tm_mon + 1));
          WrtLogD("System's current day : %d", (t->tm_mday));

          t = localtime(&notBefore);
          WrtLogD("Author certificate's notBefore Year : %d", (t->tm_year + 1900));
          WrtLogD("Author certificate's notBefore month : %d", (t->tm_mon + 1));
          WrtLogD("Author certificate's notBefore day : %d", (t->tm_mday));

          context.validationTime = notBefore + TIMET_DAY;

          t = localtime(&context.validationTime);
          WrtLogD("Modified current Year : %d", (t->tm_year + 1900));
          WrtLogD("Modified current notBefore month : %d", (t->tm_mon + 1));
          WrtLogD("Modified current notBefore day : %d", (t->tm_mday));
      }
    }
#endif
    // WAC 2.0 SP-2066 The wrt must not block widget installation
    //context.allowBrokenChain = true;

    // end

	if (!data.isAuthorSignature())
	{
		if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&context)) {
			WrtLogW("Installation break - invalid package!");
			return SignatureValidator::SIGNATURE_INVALID_HASH_SIGNATURE;//SIGNATURE_INVALID;
		}

		data.setReference(context.referenceSet);
		if (!checkObjectReferences(data)) {
			WrtLogW("Failed to check Object References");
			return SignatureValidator::SIGNATURE_INVALID_HASH_SIGNATURE;//SIGNATURE_INVALID;
		}

    (void) widgetContentPath;
  /*
    ReferenceValidator fileValidator(widgetContentPath);
    if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(data)) {
        WrtLogW("Invalid package - file references broken");
		return SignatureValidator::SIGNATURE_INVALID_NO_HASH_FILE;//SIGNATURE_INVALID;
    }
 */
	}

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    // It is good time to do OCSP check
    // ocspCheck will throw an exception on any error.
    // TODO Probably we should catch this exception and add
    // some information to SignatureData.
    if (!m_complianceModeEnabled && !data.isAuthorSignature()) {
        CertificateCollection coll;
        coll.load(sortedCertificateList);

        if (!coll.sort()) {
            WrtLogD("Collection does not contain chain!");
            return SignatureValidator::SIGNATURE_INVALID_CERT_CHAIN;//SIGNATURE_INVALID;
        }

        CertificateVerifier verificator(m_ocspEnable, m_crlEnable);
        VerificationStatus result = verificator.check(coll);

        if (result == VERIFICATION_STATUS_REVOKED) {
            return SignatureValidator::SIGNATURE_REVOKED;
        }

        if (result == VERIFICATION_STATUS_UNKNOWN ||
            result == VERIFICATION_STATUS_ERROR)
        {
            #ifdef _OCSP_POLICY_DISREGARD_UNKNOWN_OR_ERROR_CERTS_
            disregard = true;
	    #endif
        }
    }
#endif

    if (disregard) {
        WrtLogW("Signature is disregard. RootCA is not a member of Tizen");
        return SignatureValidator::SIGNATURE_INVALID_DISTRIBUTOR_CERT;//SIGNATURE_DISREGARD;
    }
    return SignatureValidator::SIGNATURE_VERIFIED;
}

SignatureValidator::Result ImplTizenSignatureValidator::checkList(SignatureData &data,
            const std::string &widgetContentPath,
            const std::list<std::string>& uriList)
{
    if(uriList.size() == 0 )
       WrtLogW("checkList >> no hash");

    bool disregard = false;
   
    if (!checkRoleURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    if (!checkProfileURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    //  CertificateList sortedCertificateList = data.getCertList();

    CertificateCollection collection;
    collection.load(data.getCertList());

    // First step - sort certificate
    if (!collection.sort()) {
        WrtLogW("Certificates do not form valid chain.");
        return SignatureValidator::SIGNATURE_INVALID;
    }

    // Check for error
    if (collection.empty()) {
        WrtLogW("Certificate list in signature is empty.");
        return SignatureValidator::SIGNATURE_INVALID;
    }

    CertificateList sortedCertificateList = collection.getChain();

    // TODO move it to CertificateCollection
    // Add root CA and CA certificates (if chain is incomplete)
    sortedCertificateList =
        OCSPCertMgrUtil::completeCertificateChain(sortedCertificateList);

    CertificatePtr root = sortedCertificateList.back();

    // Is Root CA certificate trusted?
    CertStoreId::Set storeIdSet = createCertificateIdentifier().find(root);

    WrtLogD("Is root certificate from TIZEN_DEVELOPER domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER));
    WrtLogD("Is root certificate from TIZEN_TEST domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_TEST));
    WrtLogD("Is root certificate from TIZEN_VERIFY domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_VERIFY));
    WrtLogD("Is root certificate from TIZEN_PUBLIC domain:  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Is root certificate from TIZEN_PARTNER domain:  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Is root certificate from TIZEN_PLATFORM domain:  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    WrtLogD("Visibility level is public :  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Visibility level is partner :  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Visibility level is platform :  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    if (data.isAuthorSignature())
    {
     if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
     {
            WrtLogW("author-signature.xml has got unrecognized Root CA "
                       "certificate. Signature will be disregarded.");
            disregard = true;
     }
      WrtLogD("Root CA for author signature is correct.");
   }
   else
   {
	WrtLogD("signaturefile name = %s", data.getSignatureFileName().c_str());

      if (data.getSignatureNumber() == 1)
      {
         if (storeIdSet.contains(CertStoreId::VIS_PUBLIC) || storeIdSet.contains(CertStoreId::VIS_PARTNER) || storeIdSet.contains(CertStoreId::VIS_PLATFORM))
         {
            WrtLogD("Root CA for signature1.xml is correct.");
         }
         else
         {
            WrtLogW("signature1.xml has got unrecognized Root CA "
                       "certificate. Signature will be disregarded.");
            disregard = true;
         }
      }
   }

    data.setStorageType(storeIdSet);
    data.setSortedCertificateList(sortedCertificateList);

    // We add only Root CA certificate because WAC ensure that the rest
    // of certificates are present in signature files ;-)
    XmlSec::XmlSecContext context;
    context.signatureFile = data.getSignatureFileName();
    context.certificatePtr = root;

    // Now we should have full certificate chain.
    // If the end certificate is not ROOT CA we should disregard signature
    // but still signature must be valid... Aaaaaa it's so stupid...
    if (!(root->isSignedBy(root))) {
        WrtLogW("Root CA certificate not found. Chain is incomplete.");
    //  context.allowBrokenChain = true;
    }

    // WAC 2.0 SP-2066 The wrt must not block widget installation
    // due to expiration of the author certificate.
    time_t nowTime = time(NULL);

#define CHECK_TIME
#ifdef CHECK_TIME

    ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
    ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

  
	if (X509_cmp_time(notBeforeTime, &nowTime) > 0  || X509_cmp_time(notAfterTime, &nowTime) < 0)
	{
      struct tm *t;
      struct tm ta, tb, tc;
      char msg[1024];

      t = localtime(&nowTime);
      if (!t)
          return SignatureValidator::SIGNATURE_INVALID_CERT_TIME;

      memset(&tc, 0, sizeof(tc));

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", t->tm_year + 1900, t->tm_mon + 1,t->tm_mday );
      WrtLogD("## System's currentTime : %s", msg);
      fprintf(stderr, "## System's currentTime : %s\n", msg);

      tb = _ASN1_GetTimeT(notBeforeTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tb.tm_year + 1900, tb.tm_mon + 1,tb.tm_mday );
      WrtLogD("## certificate's notBeforeTime : %s", msg);
      fprintf(stderr, "## certificate's notBeforeTime : %s\n", msg);

      ta = _ASN1_GetTimeT(notAfterTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", ta.tm_year + 1900, ta.tm_mon + 1,ta.tm_mday );
      WrtLogD("## certificate's notAfterTime : %s", msg);
      fprintf(stderr, "## certificate's notAfterTime : %s\n", msg);

      if (storeIdSet.contains(CertStoreId::TIZEN_VERIFY))
      {
         WrtLogD("## TIZEN_VERIFY : check certificate Time : FALSE");
         fprintf(stderr, "## TIZEN_VERIFY : check certificate Time : FALSE\n");
         return SignatureValidator::SIGNATURE_INVALID;
      }

      int year = (ta.tm_year - tb.tm_year) / 4;
      tc.tm_year = tb.tm_year + year;
      tc.tm_mon = (tb.tm_mon + ta.tm_mon )/2;
      tc.tm_mday = (tb.tm_mday + ta.tm_mday)/2;

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tc.tm_year + 1900, tc.tm_mon + 1,tc.tm_mday );
      WrtLogD("## cmp cert with validation time : %s", msg);
      fprintf(stderr, "## cmp cert with validation time : %s\n", msg);

      time_t outCurrent = mktime(&tc);
      context.validationTime = outCurrent;
      //return SignatureValidator::SIGNATURE_INVALID;
    }

#endif

#if 0
    time_t notAfter = data.getEndEntityCertificatePtr()->getNotAfter();
    time_t notBefore = data.getEndEntityCertificatePtr()->getNotBefore();

    struct tm *t;

    if (data.isAuthorSignature())
    {
       // time_t 2038 year bug exist. So, notAtter() cann't check...
       /*
       if (notAfter < nowTime)
       {
          context.validationTime = notAfter - TIMET_DAY;
          WrtLogW("Author certificate is expired. notAfter...");
       }
       */

       if (notBefore > nowTime)
       {
          WrtLogW("Author certificate is expired. notBefore time is greater than system-time.");

          t = localtime(&nowTime);
          WrtLogD("System's current Year : %d", (t->tm_year + 1900));
          WrtLogD("System's current month : %d", (t->tm_mon + 1));
          WrtLogD("System's current day : %d", (t->tm_mday));

          t = localtime(&notBefore);
          WrtLogD("Author certificate's notBefore Year : %d", (t->tm_year + 1900));
          WrtLogD("Author certificate's notBefore month : %d", (t->tm_mon + 1));
          WrtLogD("Author certificate's notBefore day : %d", (t->tm_mday));

          context.validationTime = notBefore + TIMET_DAY;

          t = localtime(&context.validationTime);
          WrtLogD("Modified current Year : %d", (t->tm_year + 1900));
          WrtLogD("Modified current notBefore month : %d", (t->tm_mon + 1));
          WrtLogD("Modified current notBefore day : %d", (t->tm_mday));
      }
    }
#endif
    // WAC 2.0 SP-2066 The wrt must not block widget installation
    //context.allowBrokenChain = true;

    // end
   if(uriList.size() == 0)
   {
     if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validateNoHash(&context)) {
        WrtLogW("Installation break - invalid package! >> validateNoHash");
        return SignatureValidator::SIGNATURE_INVALID;
     }
   }
   else if(uriList.size() != 0)
   {
     XmlSecSingleton::Instance().setPartialHashList(uriList);
     if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validatePartialHash(&context)) {
         WrtLogW("Installation break - invalid package! >> validatePartialHash");
         return SignatureValidator::SIGNATURE_INVALID;
     }
   }

   data.setReference(context.referenceSet);
   //if (!checkObjectReferences(data)) {
   //     return SignatureValidator::SIGNATURE_INVALID;
  // }

   (void) widgetContentPath;
  /*
    ReferenceValidator fileValidator(widgetContentPath);
    if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(data)) {
        WrtLogW("Invalid package - file references broken");
        return SignatureValidator::SIGNATURE_INVALID;
    }
 */

#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    // It is good time to do OCSP check
    // ocspCheck will throw an exception on any error.
    // TODO Probably we should catch this exception and add
    // some information to SignatureData.
    if (!m_complianceModeEnabled && !data.isAuthorSignature()) {
        CertificateCollection coll;
        coll.load(sortedCertificateList);

        if (!coll.sort()) {
            WrtLogD("Collection does not contain chain!");
            return SignatureValidator::SIGNATURE_INVALID;
        }

        CertificateVerifier verificator(m_ocspEnable, m_crlEnable);
        VerificationStatus result = verificator.check(coll);

        if (result == VERIFICATION_STATUS_REVOKED) {
            return SignatureValidator::SIGNATURE_REVOKED;
        }

        if (result == VERIFICATION_STATUS_UNKNOWN ||
            result == VERIFICATION_STATUS_ERROR)
        {
	    #ifdef _OCSP_POLICY_DISREGARD_UNKNOWN_OR_ERROR_CERTS_
            disregard = true;
	    #endif
        }
    }
#endif

    if (disregard) {
        WrtLogW("Signature is disregard. RootCA is not a member of Tizen.");
        return SignatureValidator::SIGNATURE_DISREGARD;
    }
    return SignatureValidator::SIGNATURE_VERIFIED;
}

class ImplWacSignatureValidator : public SignatureValidator::ImplSignatureValidator
{
  public:
    SignatureValidator::Result check(SignatureData &data,
            const std::string &widgetContentPath);

    SignatureValidator::Result checkList(SignatureData &data,
            const std::string &widgetContentPath,
            const std::list<std::string>& uriList);
    explicit ImplWacSignatureValidator(bool ocspEnable,
                     bool crlEnable,
                     bool complianceMode)
      : ImplSignatureValidator(ocspEnable, crlEnable, complianceMode)
    {}

    virtual ~ImplWacSignatureValidator() {}
};


SignatureValidator::Result ImplWacSignatureValidator::checkList(
        SignatureData & /* data */,
        const std::string & /* widgetContentPath */,
        const std::list<std::string>& /* uriList */)
{
    return SignatureValidator::SIGNATURE_INVALID;
}


SignatureValidator::Result ImplWacSignatureValidator::check(
    SignatureData &data,
    const std::string &widgetContentPath)
{
    bool disregard = false;

    if (!checkRoleURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    if (!checkProfileURI(data)) {
        return SignatureValidator::SIGNATURE_INVALID;
    }

    //  CertificateList sortedCertificateList = data.getCertList();

    CertificateCollection collection;
    collection.load(data.getCertList());

    // First step - sort certificate
    if (!collection.sort()) {
        WrtLogW("Certificates do not form valid chain.");
        return SignatureValidator::SIGNATURE_INVALID;
    }

    // Check for error
    if (collection.empty()) {
        WrtLogW("Certificate list in signature is empty.");
        return SignatureValidator::SIGNATURE_INVALID;
    }

    CertificateList sortedCertificateList = collection.getChain();

    // TODO move it to CertificateCollection
    // Add root CA and CA certificates (if chain is incomplete)
    sortedCertificateList =
        OCSPCertMgrUtil::completeCertificateChain(sortedCertificateList);

    CertificatePtr root = sortedCertificateList.back();

    // Is Root CA certificate trusted?
    CertStoreId::Set storeIdSet = createCertificateIdentifier().find(root);

    WrtLogD("Is root certificate from TIZEN_DEVELOPER domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER));
    WrtLogD("Is root certificate from TIZEN_TEST domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_TEST));
    WrtLogD("Is root certificate from TIZEN_VERIFY domain:  %d", storeIdSet.contains(CertStoreId::TIZEN_VERIFY));
    WrtLogD("Is root certificate from TIZEN_PUBLIC domain:  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Is root certificate from TIZEN_PARTNER domain:  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Is root certificate from TIZEN_PLATFORM domain:  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

    WrtLogD("Visibility level is public :  %d", storeIdSet.contains(CertStoreId::VIS_PUBLIC));
    WrtLogD("Visibility level is partner :  %d", storeIdSet.contains(CertStoreId::VIS_PARTNER));
    WrtLogD("Visibility level is platform :  %d", storeIdSet.contains(CertStoreId::VIS_PLATFORM));

	if (data.isAuthorSignature())
	{
		if (!storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
			WrtLogW("author-signature.xml has got unrecognized Root CA "
					"certificate. Signature will be disregarded.");
			disregard = true;
		}
	} else {
        WrtLogD("signaturefile name = %s", data.getSignatureFileName().c_str());
		if (storeIdSet.contains(CertStoreId::TIZEN_DEVELOPER))
		{
			WrtLogE("distributor has author level siganture! Signature will be disregarded.");
			return SignatureValidator::SIGNATURE_INVALID;
		}


       if (data.getSignatureNumber() == 1)
       {
          if (storeIdSet.contains(CertStoreId::VIS_PUBLIC) || storeIdSet.contains(CertStoreId::VIS_PARTNER) || storeIdSet.contains(CertStoreId::VIS_PLATFORM))
          {
             WrtLogD("Root CA for signature1.xml is correct.");
          }
          else
          {
          WrtLogW("signature1.xml has got unrecognized Root CA "
                        "certificate. Signature will be disregarded.");
             disregard = true;
          }
       }
    }

    data.setStorageType(storeIdSet);
    data.setSortedCertificateList(sortedCertificateList);

    // We add only Root CA certificate because WAC ensure that the rest
    // of certificates are present in signature files ;-)
    XmlSec::XmlSecContext context;
    context.signatureFile = data.getSignatureFileName();
    context.certificatePtr = root;

    // Now we should have full certificate chain.
    // If the end certificate is not ROOT CA we should disregard signature
    // but still signature must be valid... Aaaaaa it's so stupid...
    if (!(root->isSignedBy(root))) {
        WrtLogW("Root CA certificate not found. Chain is incomplete.");
//        context.allowBrokenChain = true;
    }

    time_t nowTime = time(NULL);
    // WAC 2.0 SP-2066 The wrt must not block widget installation
    // due to expiration of the author certificate.
#define CHECK_TIME
#ifdef CHECK_TIME

    ASN1_TIME* notAfterTime = data.getEndEntityCertificatePtr()->getNotAfterTime();
    ASN1_TIME* notBeforeTime = data.getEndEntityCertificatePtr()->getNotBeforeTime();

 	if (X509_cmp_time(notBeforeTime, &nowTime) > 0  || X509_cmp_time(notAfterTime, &nowTime) < 0)
	{
      struct tm *t;
      struct tm ta, tb, tc;
      char msg[1024];

      t = localtime(&nowTime);
      if (!t)
          return SignatureValidator::SIGNATURE_INVALID_CERT_TIME;

      memset(&tc, 0, sizeof(tc));

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", t->tm_year + 1900, t->tm_mon + 1,t->tm_mday );
      WrtLogD("## System's currentTime : %s", msg);
      fprintf(stderr, "## System's currentTime : %s\n", msg);

      tb = _ASN1_GetTimeT(notBeforeTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tb.tm_year + 1900, tb.tm_mon + 1,tb.tm_mday );
      WrtLogD("## certificate's notBeforeTime : %s",  msg);
      fprintf(stderr, "## certificate's notBeforeTime : %s\n", msg);

      ta = _ASN1_GetTimeT(notAfterTime);
      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", ta.tm_year + 1900, ta.tm_mon + 1,ta.tm_mday );
      WrtLogD("## certificate's notAfterTime : %s", msg);
      fprintf(stderr, "## certificate's notAfterTime : %s\n", msg);

      if (storeIdSet.contains(CertStoreId::TIZEN_VERIFY))
      {
         WrtLogD("## TIZEN_VERIFY : check certificate Time : FALSE");
         fprintf(stderr, "## TIZEN_VERIFY : check certificate Time : FALSE\n");
         return SignatureValidator::SIGNATURE_INVALID;
      }

      int year = (ta.tm_year - tb.tm_year) / 4;
      tc.tm_year = tb.tm_year + year;
      tc.tm_mon = (tb.tm_mon + ta.tm_mon )/2;
      tc.tm_mday = (tb.tm_mday + ta.tm_mday)/2;

      snprintf(msg, sizeof(msg), "Year: %d, month: %d, day : %d", tc.tm_year + 1900, tc.tm_mon + 1,tc.tm_mday );
      WrtLogD("## cmp cert with validation time : %s", msg);
      fprintf(stderr, "## cmp cert with validation time : %s\n", msg);

      time_t outCurrent = mktime(&tc);
      context.validationTime = outCurrent;
      //return SignatureValidator::SIGNATURE_INVALID;
    }
  
#endif

#if 0
    time_t notAfter = data.getEndEntityCertificatePtr()->getNotAfter();
    time_t notBefore = data.getEndEntityCertificatePtr()->getNotBefore();

    struct tm *t;

    if (data.isAuthorSignature())
    {
      // time_t 2038 year bug exist. So, notAtter() cann't check...
      /*
      if (notAfter < nowTime)
      {
         context.validationTime = notAfter - TIMET_DAY;
         WrtLogW("Author certificate is expired. notAfter...");
      }
      */

    if (notBefore > nowTime)
    {
       WrtLogW("Author certificate is expired. notBefore time is greater than system-time.");

       t = localtime(&nowTime);
       WrtLogD("System's current Year : %d", (t->tm_year + 1900));
       WrtLogD("System's current month : %d", (t->tm_mon + 1));
       WrtLogD("System's current day : %d", (t->tm_mday));

       t = localtime(&notBefore);
       WrtLogD("Author certificate's notBefore Year : %d", (t->tm_year + 1900));
       WrtLogD("Author certificate's notBefore month : %d", (t->tm_mon + 1));
       WrtLogD("Author certificate's notBefore day : %d", (t->tm_mday));

       context.validationTime = notBefore + TIMET_DAY;

       t = localtime(&context.validationTime);
       WrtLogD("Modified current Year : %d", (t->tm_year + 1900));
       WrtLogD("Modified current notBefore month : %d", (t->tm_mon + 1));
       WrtLogD("Modified current notBefore day : %d",  (t->tm_mday));
    }
   }
#endif
	if (!data.isAuthorSignature())
	{
		if (XmlSec::NO_ERROR != XmlSecSingleton::Instance().validate(&context)) {
			WrtLogW("Installation break - invalid package!");
			return SignatureValidator::SIGNATURE_INVALID;
		}

		data.setReference(context.referenceSet);

		if (!checkObjectReferences(data)) {
			return SignatureValidator::SIGNATURE_INVALID;
		}

		ReferenceValidator fileValidator(widgetContentPath);
		if (ReferenceValidator::NO_ERROR != fileValidator.checkReferences(data)) {
			WrtLogW("Invalid package - file references broken");
			return SignatureValidator::SIGNATURE_INVALID;
		}
	}

	#ifdef TIZEN_FEATURE_CERT_SVC_OCSP_CRL
    // It is good time to do OCSP check
    // ocspCheck will throw an exception on any error.
    // TODO Probably we should catch this exception and add
    // some information to SignatureData.
    if (!m_complianceModeEnabled && !data.isAuthorSignature()) {
        CertificateCollection coll;
        coll.load(sortedCertificateList);

        if (!coll.sort()) {
            WrtLogD("Collection does not contain chain!");
            return SignatureValidator::SIGNATURE_INVALID;
        }

        CertificateVerifier verificator(m_ocspEnable, m_crlEnable);
        VerificationStatus result = verificator.check(coll);

        if (result == VERIFICATION_STATUS_REVOKED) {
            return SignatureValidator::SIGNATURE_REVOKED;
        }

        if (result == VERIFICATION_STATUS_UNKNOWN ||
            result == VERIFICATION_STATUS_ERROR)
        {
           #ifdef _OCSP_POLICY_DISREGARD_UNKNOWN_OR_ERROR_CERTS_
            disregard = true;
	    #endif
        }
    }
#endif

    if (disregard) {
        WrtLogW("Signature is disregard. RootCA is not a member of Tizen.");
        return SignatureValidator::SIGNATURE_DISREGARD;
    }
    return SignatureValidator::SIGNATURE_VERIFIED;
}

// Implementation of SignatureValidator

SignatureValidator::SignatureValidator(
    AppType appType,
    bool ocspEnable,
    bool crlEnable,
    bool complianceMode)
  : m_impl(0)
{
    WrtLogD( "appType :%d", appType );

    if(appType == TIZEN)
    {
     m_impl = new ImplTizenSignatureValidator(ocspEnable,crlEnable,complianceMode);
    }
    else if(appType == WAC20)
    {
     m_impl = new ImplWacSignatureValidator(ocspEnable,crlEnable,complianceMode);
    }
}

SignatureValidator::~SignatureValidator() {
    delete m_impl;
}

SignatureValidator::Result SignatureValidator::check(
    SignatureData &data,
    const std::string &widgetContentPath)
{
    return m_impl->check(data, widgetContentPath);
}

SignatureValidator::Result SignatureValidator::checkList(
    SignatureData &data,
    const std::string &widgetContentPath,
    const std::list<std::string>& uriList)
{
    return m_impl->checkList(data, widgetContentPath, uriList);
}

} // namespace ValidationCore

