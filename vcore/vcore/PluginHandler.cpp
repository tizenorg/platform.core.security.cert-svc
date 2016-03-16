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
 * @file        PluginHandler.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Validator plugin handler.
 */

#include <dlfcn.h>

#include <dpl/log/log.h>

#include <vcore/PluginHandler.h>

namespace ValidationCore {

PluginHandler::PluginHandler()
	: m_dlhandle(nullptr)
	, m_plugin(nullptr)
	, m_destroy(nullptr)
	, m_fail(true)
{
	m_dlhandle = dlopen(PLUGIN_PATH.c_str(), RTLD_NOW);
	if (!m_dlhandle) {
		LogInfo("Plugin library has not been found/opened : " << PLUGIN_PATH);
		return;
	}

	CreateValidatorPlugin_t createFun =
		reinterpret_cast<CreateValidatorPlugin_t>(dlsym(m_dlhandle, "create"));
	if (!createFun) {
		LogError("create symbol cannot found from " << PLUGIN_PATH
				 << ". dlerror : " << dlerror());
		return;
	}

	m_destroy =
		reinterpret_cast<DestroyValidatorPlugin_t>(dlsym(m_dlhandle, "destroy"));
	if (!m_destroy) {
		LogError("destroy symbole cannot found from " << PLUGIN_PATH
				 << ". dlerror : " << dlerror());
		return;
	}

	m_plugin = createFun();
	if (!m_plugin) {
		LogError("cannot create plugin with create func.");
		return;
	}

	LogDebug("create plugin with createFun success.");

	m_fail = false;
}

PluginHandler::~PluginHandler()
{
	if (m_plugin && m_destroy)
		m_destroy(m_plugin);

	if (m_dlhandle)
		dlclose(m_dlhandle);
}

bool PluginHandler::fail() const
{
	return m_fail;
}

VCerr PluginHandler::step(VCerr result, SignatureData &data)
{
	if (!m_plugin) {
		LogError("Plugin is not initialized.");
		return result;
	}

	return m_plugin->step(result, data);
}

std::string PluginHandler::errorToString(VCerr code)
{
	if (!m_plugin)
		return "Plugin is not initialized";

	return m_plugin->errorToString(code);
}

} // namespace ValidationCore
