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
 * @file        SignatureFinder.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Search for author-signature.xml and signatureN.xml files.
 */
#ifndef _SIGNATUREFINDER_H_
#define _SIGNATUREFINDER_H_

#include <set>
#include <string>

#include <pcrecpp.h>

#include "SignatureData.h"

namespace ValidationCore {
class SignatureFileInfo
{
  public:
    SignatureFileInfo(const std::string &fileName,
            int num) :
        m_fileName(fileName),
        m_fileNumber(num)
    {
    }

    std::string getFileName() const
    {
        return m_fileName;
    }

    int getFileNumber() const
    {
        return m_fileNumber;
    }

    bool operator<(const SignatureFileInfo &second) const
    {
        return m_fileNumber < second.m_fileNumber;
    }
  private:
    std::string m_fileName;
    int m_fileNumber;
};

typedef std::set<SignatureFileInfo> SignatureFileInfoSet;

class SignatureFinder
{
  public:
    enum Result
    {
        NO_ERROR,
        ERROR_OPENING_DIR,
        ERROR_READING_DIR,
        ERROR_ISTREAM
    };

    SignatureFinder(const std::string& dir);

    Result find(SignatureFileInfoSet &set);

  private:
    std::string m_dir;
    pcrecpp::RE m_signatureRegexp;
};
} // namespace ValidationCore

#endif
