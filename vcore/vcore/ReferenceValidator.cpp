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
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 *              Sangwan Kwon (sangwan.kwon@samsung.com)
 * @file        ReferenceValidator.cpp
 * @version     1.0
 * @brief       Compare signature reference list and list of widget file.
 */
#include <vcore/ReferenceValidator.h>

#include <dirent.h>
#include <errno.h>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pcrecpp.h>

#include <dpl/log/log.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

namespace {

const char *SPECIAL_SYMBOL_CURRENT_DIR = ".";
const char *SPECIAL_SYMBOL_UPPER_DIR = "..";
const char *SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE = "author-signature.xml";
const char *REGEXP_DISTRIBUTOR_SIGNATURE = "^signature[1-9][0-9]*\\.xml";

const char MARK_ENCODED_CHAR = '%';

} // namespace anonymous

namespace ValidationCore {

class ReferenceValidator::Impl
{
  public:
    Impl(const std::string &dirpath)
      : m_dirpath(dirpath)
      , m_signatureRegexp(REGEXP_DISTRIBUTOR_SIGNATURE)
    {}

    virtual ~Impl(){}

    Result checkReferences(const SignatureData &signatureData)
    {
        const ReferenceSet &refSet = signatureData.getReferenceSet();
        ReferenceSet refDecoded;

        try {
            for (auto it = refSet.begin(); it != refSet.end(); ++it) {
                if (std::string::npos != it->find(MARK_ENCODED_CHAR))
                    refDecoded.insert(decodeProcent(*it));
                else
                    refDecoded.insert(*it);
            }
        } catch (Result &) {
            return ERROR_DECODING_URL;
        }
        return dfsCheckDirectories(
            refDecoded,
            std::string(),
            signatureData.isAuthorSignature());
    }

    Result checkOutbound(const std::string &linkPath, const std::string &appPath)
    {
        char resolvedPath[PATH_MAX];
        if (realpath((appPath + "/" + linkPath).c_str(), resolvedPath) == NULL)
            return ERROR_READING_LNK;

        std::string linkRealPath(resolvedPath);
        if (linkRealPath.compare(0, appPath.size(), appPath) == 0)
            return NO_ERROR;
        else
            return ERROR_OUTBOUND_LNK;
    }

  private:
    int hexToInt(char hex);
    std::string decodeProcent(const std::string &path);

    Result dfsCheckDirectories(
        const ReferenceSet &referenceSet,
        const std::string &directory,
        bool isAuthorSignature);

    inline bool isDistributorSignature(const char *cstring) const
    {
        return m_signatureRegexp.FullMatch(cstring);
    }

    std::string m_dirpath;
    pcrecpp::RE m_signatureRegexp;
};

int ReferenceValidator::Impl::hexToInt(char a) {
    if (a >= '0' && a <= '9') return a-'0';
    if (a >= 'A' && a <= 'F') return a-'A' + 10;
    if (a >= 'a' && a <= 'f') return a-'a' + 10;
    LogError("Symbol '" << a << "' is out of scope.");
    throw ERROR_DECODING_URL;
}

std::string ReferenceValidator::Impl::decodeProcent(const std::string &path) {
    std::vector<int> input(path.begin(), path.end());
    std::vector<char> output;
    try {
        size_t i = 0;
        while(i<input.size()) {
            if (MARK_ENCODED_CHAR == input[i]) {
                if (i+2 >= input.size())
                    throw ERROR_DECODING_URL;

                int result = hexToInt(input[i+1])*16 + hexToInt(input[i+2]);
                output.push_back(static_cast<char>(result));
                i+=3;
            } else {
                output.push_back(static_cast<char>(input[i]));
                ++i;
            }
        }
    } catch (Result &) {
        LogError("Error while decoding url path : " << path);
        throw ERROR_DECODING_URL;
    }
    return std::string(output.begin(), output.end());
}

ReferenceValidator::Result ReferenceValidator::Impl::dfsCheckDirectories(
    const ReferenceSet &referenceSet,
    const std::string &directory,
    bool isAuthorSignature)
{
    int ret;
    DIR *dirp;
    struct dirent entry;
    struct dirent *result;

    std::string currentDir = m_dirpath;
    if (!directory.empty()) {
        currentDir += "/";
        currentDir += directory;
    }

    if ((dirp = opendir(currentDir.c_str())) == NULL) {
        LogError("Error opening directory : " << currentDir);
        return ERROR_OPENING_DIR;
    }

    for (ret = readdir_r(dirp, &entry, &result);
            ret == 0 && result != NULL;
            ret = readdir_r(dirp, &entry, &result)) {
        if (!strcmp(result->d_name, SPECIAL_SYMBOL_CURRENT_DIR)) {
            continue;
        }

        if (!strcmp(result->d_name, SPECIAL_SYMBOL_UPPER_DIR)) {
            continue;
        }

        if (result->d_type == DT_UNKNOWN) {
            // try to stat inode when readdir is not returning known type
            std::string path = currentDir + "/" + result->d_name;
            struct stat s;
            if (lstat(path.c_str(), &s) != 0) {
                closedir(dirp);
                return ERROR_LSTAT;
            }
            if (S_ISREG(s.st_mode)) {
                result->d_type = DT_REG;
            } else if (S_ISDIR(s.st_mode)) {
                result->d_type = DT_DIR;
            }
        }

        if (currentDir == m_dirpath && result->d_type == DT_REG &&
            !strcmp(result->d_name, SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE) &&
            isAuthorSignature)
        {
            continue;
        }

        if (currentDir == m_dirpath && result->d_type == DT_REG &&
            isDistributorSignature(result->d_name)) {
            continue;
        }

        if (result->d_type == DT_DIR) {
            LogDebug("Open directory : " << (directory + result->d_name));
            std::string tmp_directory = directory + result->d_name + "/";
            Result result = dfsCheckDirectories(referenceSet,
                                                tmp_directory,
                                                isAuthorSignature);
            if (result != NO_ERROR) {
                closedir(dirp);
                return result;
            }
        } else if (result->d_type == DT_REG) {
            if (referenceSet.end() ==
                referenceSet.find(directory + result->d_name))
            {
                LogDebug("Found file : " << (directory + result->d_name));
                LogError("Unknown ERROR_REFERENCE_NOT_FOUND.");
                closedir(dirp);
                return ERROR_REFERENCE_NOT_FOUND;
            }
        } else if (result->d_type == DT_LNK) {
            std::string linkPath(directory + result->d_name);

            if (referenceSet.end() ==
                referenceSet.find(linkPath))
            {
                LogDebug("Found file : " << (directory + result->d_name));
                LogError("Unknown ERROR_REFERENCE_NOT_FOUND.");
                closedir(dirp);
                return ERROR_REFERENCE_NOT_FOUND;
            }

            Result ret = checkOutbound(linkPath, m_dirpath);
            if (ret != NO_ERROR) {
                LogError("Link file point wrong path");
                closedir(dirp);
                return ret;
            }
        } else {
            LogError("Unknown file type.");
            closedir(dirp);
            return ERROR_UNSUPPORTED_FILE_TYPE;
        }
    }

    if (ret != 0) {
        closedir(dirp);
        return ERROR_READING_DIR;
    }

    closedir(dirp);

    return NO_ERROR;
}

ReferenceValidator::ReferenceValidator(const std::string &dirpath)
  : m_impl(new Impl(dirpath))
{}

ReferenceValidator::~ReferenceValidator(){
    delete m_impl;
}

ReferenceValidator::Result ReferenceValidator::checkReferences(
    const SignatureData &signatureData)
{
    return m_impl->checkReferences(signatureData);
}

ReferenceValidator::Result ReferenceValidator::checkOutbound(
    const std::string &linkPath, const std::string &appPath)
{
    return m_impl->checkOutbound(linkPath, appPath);
}
} // ValidationCore
