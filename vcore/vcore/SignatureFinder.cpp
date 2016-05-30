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
 * @file        SignatureFinder.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Search for author-signature.xml and signatureN.xml files.
 */
#include <vcore/SignatureFinder.h>
#include <dpl/log/log.h>

#include <dirent.h>
#include <errno.h>
#include <istream>
#include <sstream>

#include <pcrecpp.h>

namespace {

}

namespace ValidationCore {
static const char *SIGNATURE_AUTHOR = "author-signature.xml";
static const char *REGEXP_DISTRIBUTOR_SIGNATURE =
	"^(signature)([1-9][0-9]*)(\\.xml)";

class SignatureFinder::Impl {
public:
	Impl(const std::string &dir)
		: m_dir(dir)
		, m_signatureRegexp(REGEXP_DISTRIBUTOR_SIGNATURE)
	{}

	virtual ~Impl() {}

	Result find(SignatureFileInfoSet &set);

private:
	std::string getFullPath(const std::string &file);

	std::string m_dir;
	pcrecpp::RE m_signatureRegexp;
};

std::string SignatureFinder::Impl::getFullPath(const std::string &file)
{
	std::string fullPath = m_dir;

	if (fullPath.back() != '/')
		fullPath += "/";

	fullPath += file;
	return fullPath;
}

SignatureFinder::Result SignatureFinder::Impl::find(SignatureFileInfoSet &set)
{
	int ret;
	DIR *dirp;
	struct dirent entry;
	struct dirent *result;

	if ((dirp = opendir(m_dir.c_str())) == NULL) {
		LogError("Error opening directory: " << m_dir);
		return ERROR_OPENING_DIR;
	}

	for (ret = readdir_r(dirp, &entry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dirp, &entry, &result)) {
		/* number for author signature is -1 */
		if (!strcmp(result->d_name, SIGNATURE_AUTHOR)) {
			std::string fullPath = getFullPath(std::string(result->d_name));
			LogDebug("Found author signature file full path : " << fullPath);
			set.insert(SignatureFileInfo(fullPath, -1));
			continue;
		}

		std::string sig;
		std::string num;
		std::string xml; /* just for cutting out .xml */

		if (m_signatureRegexp.FullMatch(result->d_name, &sig, &num, &xml)) {
			std::istringstream stream(num);
			int number;
			stream >> number;

			if (stream.fail()) {
				closedir(dirp);
				return ERROR_ISTREAM;
			}

			std::string fullPath = getFullPath(std::string(result->d_name));
			LogDebug("Found signature file full path : " << fullPath);
			set.insert(SignatureFileInfo(fullPath, number));
		}
	}

	if (ret != 0) {
		LogError("Error in readdir");
		closedir(dirp);
		return ERROR_READING_DIR;
	}

	closedir(dirp);
	return NO_ERROR;
}

SignatureFinder::SignatureFinder(const std::string &dir)
	: m_impl(new Impl(dir))
{}

SignatureFinder::~SignatureFinder()
{
	delete m_impl;
}

SignatureFinder::Result SignatureFinder::find(SignatureFileInfoSet &set)
{
	return m_impl->find(set);
}

} // namespace ValidationCore
