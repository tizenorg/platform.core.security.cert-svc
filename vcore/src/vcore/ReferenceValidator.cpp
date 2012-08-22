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
#include <dirent.h>
#include <errno.h>
#include <fstream>
#include <memory>

#include <dpl/errno_string.h>
#include <dpl/log/log.h>

#include "Base64.h"
#include "ReferenceValidator.h"

namespace {
const char *SPECIAL_SYMBOL_CURRENT_DIR = ".";
const char *SPECIAL_SYMBOL_UPPER_DIR = "..";
const char *SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE = "author-signature.xml";
const char *REGEXP_DISTRIBUTOR_SIGNATURE = "^signature[1-9][0-9]*\\.xml";
} // namespace anonymous

namespace ValidationCore {
ReferenceValidator::ReferenceValidator(const std::string &dirpath) :
    m_dirpath(dirpath),
    m_signatureRegexp(REGEXP_DISTRIBUTOR_SIGNATURE)
{
}

ReferenceValidator::Result ReferenceValidator::checkReferences(
        const SignatureData &signatureData)
{
    return dfsCheckDirectories(signatureData, std::string());
}

ReferenceValidator::Result ReferenceValidator::dfsCheckDirectories(
        const SignatureData &signatureData,
        const std::string &directory)
{
    DIR *dp;
    struct dirent *dirp;
    std::string currentDir = m_dirpath + directory;

    if ((dp = opendir(currentDir.c_str())) == NULL) {
        LogError("Error opening directory: " << currentDir.c_str());
        m_errorDescription = currentDir;
        return ERROR_OPENING_DIR;
    }

    for (errno = 0; (dirp = readdir(dp)) != NULL; errno = 0) {
        if (!strcmp(dirp->d_name, SPECIAL_SYMBOL_CURRENT_DIR)) {
            continue;
        }

        if (!strcmp(dirp->d_name, SPECIAL_SYMBOL_UPPER_DIR)) {
            continue;
        }

        if (currentDir == m_dirpath && dirp->d_type == DT_REG &&
            !strcmp(dirp->d_name,
                    SPECIAL_SYMBOL_AUTHOR_SIGNATURE_FILE) &&
            signatureData.isAuthorSignature()) {
            continue;
        }

        if (currentDir == m_dirpath && dirp->d_type == DT_REG &&
            isDistributorSignature(dirp->d_name)) {
            continue;
        }

        if (dirp->d_type == DT_DIR) {
            LogDebug("Open directory: " << (directory + dirp->d_name));
            std::string tmp_directory = directory + dirp->d_name + "/";
            Result result = dfsCheckDirectories(signatureData, tmp_directory);
            if (result != NO_ERROR) {
                closedir(dp);
                return result;
            }
        } else if (dirp->d_type == DT_REG) {
            LogDebug("Found     file: " << (directory + dirp->d_name));
            const ReferenceSet &referenceSet = signatureData.getReferenceSet();
            if (referenceSet.end() ==
                referenceSet.find(directory + dirp->d_name)) {
                closedir(dp);
                m_errorDescription = directory + dirp->d_name;
                return ERROR_REFERENCE_NOT_FOUND;
            }
        } else {
            LogError("Unknown file type.");
            closedir(dp);
            m_errorDescription = directory + dirp->d_name;
            return ERROR_UNSUPPORTED_FILE_TYPE;
        }
    }

    if (errno != 0) {
        m_errorDescription = DPL::GetErrnoString();
        LogError("readdir failed. Errno code: " << errno <<
                 " Description: " << m_errorDescription);
        closedir(dp);
        return ERROR_READING_DIR;
    }

    closedir(dp);

    return NO_ERROR;
}
}
