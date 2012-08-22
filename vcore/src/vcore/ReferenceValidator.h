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
#ifndef _REFERENCEVALIDATOR_H_
#define _REFERENCEVALIDATOR_H_

#include <pcrecpp.h>

#include "SignatureData.h"

namespace ValidationCore {
class ReferenceValidator
{
  public:
    enum Result
    {
        NO_ERROR = 0,
        ERROR_OPENING_DIR,
        ERROR_READING_DIR,
        ERROR_UNSUPPORTED_FILE_TYPE,
        ERROR_REFERENCE_NOT_FOUND
    };

    ReferenceValidator(const std::string &dirpath);

    virtual ~ReferenceValidator()
    {
    }

    Result checkReferences(const SignatureData &signatureData);

  private:

    Result dfsCheckDirectories(const SignatureData &signatureData,
            const std::string &directory);

    inline bool isDistributorSignature(const char *cstring) const
    {
        return m_signatureRegexp.FullMatch(cstring);
    }

    std::string m_dirpath;
    std::string m_errorDescription;
    pcrecpp::RE m_signatureRegexp;
};
}

#endif // _REFERENCEVALIDATOR_H_
