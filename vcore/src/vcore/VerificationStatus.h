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
#ifndef _SRC_VALIDATION_CORE_VERIFICATION_STATUS_H_
#define _SRC_VALIDATION_CORE_VERIFICATION_STATUS_H_

namespace ValidationCore {
enum VerificationStatus
{
    //! The certificate has not been revoked.
    /*! Connection to OCSP responder was successful and the certificate
     *  has not been revoked.
     */
    VERIFICATION_STATUS_GOOD = 1,

    //! The certificate has been revoked.
    /*! Connection to OCSP responder was successful and the certificate
     *  has been revoked.
     *  RFC2560: "The "revoked" state indicates that the certificate has
     *  been revoked (either permanantly or temporarily
     *  (on hold))."
     */
    VERIFICATION_STATUS_REVOKED = 1 << 1,

    //! The certificate status is unknown.
    /*! Connection to OCSP responder was successful and the certificate
     *  has unknown status.
     *
     *  RFC2560: "The "unknown" state indicates that the responder
     *  doesn't know about the certificate being requested."
     */
    VERIFICATION_STATUS_UNKNOWN = 1 << 2,

    //! The certificate status was not figure out.
    /*! The response from ocsp/crl server contains broken signature. */
    VERIFICATION_STATUS_VERIFICATION_ERROR = 1 << 3,

    //! The certificate status was not figure out.
    /*! The certificate does not contain ocsp/crl extension. */
    VERIFICATION_STATUS_NOT_SUPPORT = 1 << 4,

    //! The certificate status was not figure out.
    /*! The CertMgr could not connect to OCSP responder. */
    VERIFICATION_STATUS_CONNECTION_FAILED = 1 << 5,

    //! The certificate status is unknown due to internal error inside OCSP
    VERIFICATION_STATUS_ERROR = 1 << 6
};

class VerificationStatusSet
{
  public:
    VerificationStatusSet() : m_verdictMap(0)
    {
    }

    inline void add(VerificationStatus status)
    {
        m_verdictMap |= status;
    }

    inline bool contains(VerificationStatus status) const
    {
        return m_verdictMap & status;
    }

    inline bool isEmpty() const
    {
        return 0 == m_verdictMap;
    }

    inline void operator+=(const VerificationStatusSet &second)
    {
        m_verdictMap |= second.m_verdictMap;
    }

    inline void reset()
    {
        m_verdictMap = 0;
    }

    VerificationStatus convertToStatus() const;

  private:
    unsigned int m_verdictMap;
};

/* TODO this status should be defined in wrt-engine sources */
enum WidgetVerificationStatus
{
    // All certificate has been veficated and all certificates are good.
    // Widget is able to be installed.
    WIDGET_VERIFICATION_STATUS_GOOD,
    // Some certificate has been revoked. Widget is not able to be installed.
    WIDGET_VERIFICATION_STATUS_REVOKED,
};
} // namespace ValidationCore

#endif // _SRC_VALIDATION_CORE_VERIFICATION_STATUS_H_
