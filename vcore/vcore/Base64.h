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
#ifndef _BASE64_H_
#define _BASE64_H_

#include <string>
#include <vcore/exception.h>

struct bio_st;
typedef bio_st BIO;

namespace ValidationCore {
class Base64Encoder {
public:
	class Exception {
	public:
		VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, InternalError)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, NotFinalized)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, AlreadyFinalized)
	};
	Base64Encoder();
	void append(const std::string &data);
	void finalize();
	std::string get();
	void reset();
	~Base64Encoder();

private:
	Base64Encoder(const Base64Encoder &);
	const Base64Encoder &operator=(const Base64Encoder &);

	BIO *m_b64;
	BIO *m_bmem;
	bool m_finalized;
};

class Base64Decoder {
public:
	class Exception {
	public:
		VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, InternalError)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, NotFinalized)
		VCORE_DECLARE_EXCEPTION_TYPE(Base, AlreadyFinalized)
	};
	Base64Decoder();
	void append(const std::string &data);

	/*
	 *  Function will return false when BIO_read fails
	 *  (for example: when string was not in base64 format).
	 */
	bool finalize();
	std::string get() const;
	void reset();
	~Base64Decoder() {}

private:
	Base64Decoder(const Base64Decoder &);
	const Base64Decoder &operator=(const Base64Decoder &);

	std::string m_input;
	std::string m_output;
	bool m_finalized;
};
} // namespace ValidationCore

#endif
