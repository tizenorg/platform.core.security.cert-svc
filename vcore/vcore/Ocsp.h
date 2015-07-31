/*
 *  Copyright (c) 2015 Samsung Electronics Co.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        Ocsp.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       OCSP check for signature validator. It should be used only internally.
 */
#pragma once

#include <vcore/SignatureData.h>
#include <vcore/exception.h>

namespace ValidationCore {

class Ocsp {
public:
	virtual ~Ocsp();

	class Exception {
	public:
		VCORE_DECLARE_EXCEPTION_TYPE(ValidationCore::Exception, Base);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, InvalidParam);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, OcspUnsupported);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, InvalidUrl);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, InvalidResponse);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, ServerError);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, NetworkError);
		VCORE_DECLARE_EXCEPTION_TYPE(Base, UnknownError);
	};

	enum Result {
		GOOD,
		REVOKED
	};

	/*
	 *  Remarks: input cert chain should be sorted state.
	 */
	static Result check(const SignatureData &data);

private:
	explicit Ocsp();
};

}
