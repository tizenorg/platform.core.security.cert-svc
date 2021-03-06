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
/**
 *
 *
 * @file       AbstractResponseCache.h
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      Common interface for OCSP/CRL caches
 */

#ifndef _SRC_VALIDATION_CORE_IABSTRACT_RESPONSE_CACHE_H_
#define _SRC_VALIDATION_CORE_IABSTRACT_RESPONSE_CACHE_H_

#include "Certificate.h"
#include "CertificateCollection.h"
#include "VerificationStatus.h"

namespace ValidationCore {

class IAbstractResponseCache {
  public:
    virtual VerificationStatus check(const CertificateCollection &certs) = 0;
    virtual VerificationStatus checkEndEntity(CertificateCollection &certs) = 0;
    virtual void updateCache() = 0;

    virtual ~IAbstractResponseCache()
    {
    }
};

} // namespace ValidationCore

#endif /* _SRC_VALIDATION_CORE_IABSTRACT_RESPONSE_CACHE_H_ */
