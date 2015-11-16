/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file        ValidatonPluginApi.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Validator plugin interface.
 */
#pragma once

#include <string>

#include <vcore/SignatureData.h>
#include <vcore/SignatureValidator.h>
#include <vcore/Error.h>

namespace ValidationCore {

const std::string PLUGIN_PATH = "/usr/lib/libcert-svc-validator-plugin.so";

class ValidatorPlugin {
public:
	virtual ~ValidatorPlugin() {}
	virtual VCerr step(VCerr result, SignatureData &data) = 0;
	virtual std::string errorToString(VCerr)
	{
		return std::string("Plugin developer should implement if error code added");
	}
};

/*
 *  plugin developer should implement create/destroy pair functions
 *
 *  1. function extern C named 'create' of CreateValidatorPlugin_t
 *  2. function extern C named 'destroy' of DestroyValidatorPlugin_t
 */
typedef ValidatorPlugin *(*CreateValidatorPlugin_t)(void);
typedef void (*DestroyValidatorPlugin_t)(ValidatorPlugin *ptr);

} // namespace ValidatonCore
