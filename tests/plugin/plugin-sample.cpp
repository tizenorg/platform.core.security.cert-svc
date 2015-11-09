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
 * @file        plugin-sample.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       signature validator plugin sample.
 */

#include <dlog.h>

#include <vcore/ValidatorPluginApi.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CERT_SVC_PLUGIN"

#define PLUGIN_API __attribute__((visibility("default")))

extern "C" {
ValidationCore::ValidatorPlugin *create(void);
void destroy(ValidationCore::ValidatorPlugin *obj);
}

namespace ValidationCore {

class PLUGIN_API Plugin : public ValidatorPlugin {
public:
	Plugin() {}
	virtual ~Plugin() {}

	virtual SignatureValidator::Result step(SignatureValidator::Result result, SignatureData &data);
};

SignatureValidator::Result Plugin::step(SignatureValidator::Result result, SignatureData &data)
{
	(void)data;
	SLOGI("Plugin::Step called!");
	return result;
}

} // namespace ValidationCore

PLUGIN_API
ValidationCore::ValidatorPlugin *create(void)
{
	ValidationCore::Plugin *plugin = new ValidationCore::Plugin;

	SLOGI("Plugin create!");

	return plugin;
}

PLUGIN_API
void destroy(ValidationCore::ValidatorPlugin *obj)
{
	delete obj;

	SLOGI("Plugin destroy!");
}
