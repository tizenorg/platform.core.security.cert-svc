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
 * @file        XmlSecAdapter.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     2.0
 * @brief
 */
#pragma once

#include <string>
#include <list>

#include <xmlsec/keysmngr.h>

#include <dpl/exception.h>
#include <dpl/noncopyable.h>
#include <dpl/singleton.h>

#include <vcore/Certificate.h>
#include <vcore/SignatureData.h>

namespace ValidationCore {
class XmlSec : public VcoreDPL::Noncopyable {

public:
	struct XmlSecContext {
		/* You _must_ set one of the value: certificatePath or certificate. */
		XmlSecContext()
			: validationTime(0)
			, allowBrokenChain(false)
			, errorBrokenChain(false) {}

		/*
		 * Absolute path to signature file.
		 */
		std::string signatureFile;
		/*
		 * Direcotory with signed data.
		 * If you leave it empty xmlsec will use directory extracted
		 * from signatureFile.
		 */
		std::string workingDirectory;
		/*
		 * Path to trusted certificate.
		 */
		std::string certificatePath;
		/*
		 * Trusted certificate. In most cases it should be Root CA certificate.
		 */
		CertificatePtr certificatePtr;
		/*
		 * Validation date.
		 * 0 - uses current time.
		 */
		time_t validationTime;
		/*
		 * Input parameter.
		 * If true, signature validation will not be interrupted by chain error.
		 * If true and chain is broken then the value errorBrokenChain will be
		 * set to true.
		 */
		bool allowBrokenChain;
		/*
		 * Output parameter.
		 * This will be set if chain is incomplete or broken.
		 */
		bool errorBrokenChain;
		/*
		 * Output parameter.
		 * Reference checked by xmlsec
		 */
		ReferenceSet referenceSet;
	};

	struct Exception {
		DECLARE_EXCEPTION_TYPE(VcoreDPL::Exception, Base)
		DECLARE_EXCEPTION_TYPE(Base, InternalError)
		DECLARE_EXCEPTION_TYPE(Base, InvalidFormat)
		DECLARE_EXCEPTION_TYPE(Base, InvalidSig)
		DECLARE_EXCEPTION_TYPE(Base, OutOfMemory)
	};

	/* context - input/output param. */
	void validate(XmlSecContext &context);
	void validateNoHash(XmlSecContext &context);
	void validatePartialHash(XmlSecContext &context, const std::list<std::string> &targetUri);

protected:
	XmlSec();
	~XmlSec();

private:
	enum class ValidateMode : int {
		NORMAL,
		NO_HASH,
		PARTIAL_HASH
	};

	ValidateMode m_mode;
	bool m_initialized;
	const std::list<std::string> *m_pList;

	void loadDERCertificateMemory(XmlSecContext &context, xmlSecKeysMngrPtr mngr);
	void loadPEMCertificateFile(XmlSecContext &context, xmlSecKeysMngrPtr mngr);
	void validateInternal(XmlSecContext &context);
	void validateFile(XmlSecContext &context, xmlSecKeysMngrPtr mngr);

	static std::string s_prefixPath;
	static int fileMatchCallback(const char *filename);
	static void *fileOpenCallback(const char *filename);
	static int fileReadCallback(void *context, char *buffer, int len);
	static int fileCloseCallback(void *context);
	static void fileExtractPrefix(XmlSecContext &context);
};

typedef VcoreDPL::Singleton<XmlSec> XmlSecSingleton;

} // namespace ValidationCore
