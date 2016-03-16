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
 * @file        log.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of log system
 */
#include <stddef.h>
#include <string.h>
#include <stdexcept>
#include <cassert>

#include <dpl/singleton_impl.h>
#include <dpl/log/old_style_log_provider.h>
#include <dpl/log/dlog_log_provider.h>
#include <dpl/log/journal_log_provider.h>

#include <dpl/log/log.h>

IMPLEMENT_SINGLETON(VcoreDPL::Log::LogSystem)

namespace VcoreDPL {
namespace Log {
namespace { // anonymous
const char *const CERTSVC_LOG_LEVEL    = "CERTSVC_LOG_LEVEL";
const char *const CERTSVC_LOG_PROVIDER = "CERTSVC_LOG_PROVIDER";

const char *const CONSOLE  = "CONSOLE";
const char *const DLOG     = "DLOG";
const char *const JOURNALD = "JOURNALD";
} // namespace anonymous

LogSystem::LogSystem()
	: m_providerCtor({
#ifdef TIZEN_ENGINEER_MODE
	{ CONSOLE,  []{ return static_cast<AbstractLogProvider *>(new OldStyleLogProvider()); }},
#endif
	{ DLOG,     []{ return static_cast<AbstractLogProvider *>(new DLOGLogProvider());     }},
	{ JOURNALD, []{ return static_cast<AbstractLogProvider *>(new JournalLogProvider());  }}
})
{
	SetLogLevel(getenv(CERTSVC_LOG_LEVEL));

	AbstractLogProvider *prv = NULL;
	try {
		prv = m_providerCtor.at(getenv(CERTSVC_LOG_PROVIDER))();
	} catch (const std::exception &) {
		prv = m_providerCtor[DLOG]();
	}

	AddProvider(prv);
}

LogSystem::~LogSystem()
{
	RemoveProviders();
}

void LogSystem::SetTag(const char *tag)
{
	for (auto & it : m_providers)
		it->SetTag(tag);
}

void LogSystem::AddProvider(AbstractLogProvider *provider)
{
	m_providers.push_back(provider);
}

void LogSystem::RemoveProvider(AbstractLogProvider *provider)
{
	m_providers.remove(provider);
}

void LogSystem::SelectProvider(const std::string &name)
{
	ProviderFn &prv = m_providerCtor.at(name);

	RemoveProviders();
	AddProvider(prv());
}

void LogSystem::SetLogLevel(const char *level)
{
	if (!level) {
		m_level = AbstractLogProvider::LogLevel::Debug;
	} else {
		try {
			m_level = static_cast<AbstractLogProvider::LogLevel>(std::stoi(level));
		} catch (const std::exception &) {
			m_level = AbstractLogProvider::LogLevel::Debug;
		}
	}

	if (m_level < AbstractLogProvider::LogLevel::None)
		m_level = AbstractLogProvider::LogLevel::None;
	else if (m_level > AbstractLogProvider::LogLevel::Pedantic)
		m_level = AbstractLogProvider::LogLevel::Pedantic;

#ifndef TIZEN_ENGINEER_MODE
	if (m_level > AbstractLogProvider::LogLevel::Error)
		m_level = AbstractLogProvider::LogLevel::Error;
#endif
}

void LogSystem::Log(AbstractLogProvider::LogLevel level,
					const char *message,
					const char *filename,
					int line,
					const char *function) const
{
	for (const auto & it : m_providers)
		it->Log(level, message, filename, line, function);
}

void LogSystem::RemoveProviders()
{
	for (auto & it : m_providers)
		delete it;

	m_providers.clear();
}
}
} // namespace VcoreDPL
