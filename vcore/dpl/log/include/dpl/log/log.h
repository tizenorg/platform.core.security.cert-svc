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
 * @file        log.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of log system
 */
#ifndef DPL_LOG_H
#define DPL_LOG_H

#include <sstream>
#include <list>
#include <unordered_map>
#include <string>

#include <dpl/singleton.h>
#include <dpl/noncopyable.h>

#include <dpl/log/abstract_log_provider.h>

namespace VcoreDPL {
namespace Log {
/**
 * DPL log system
 *
 * To switch logs into old style, export
 * DPL_USE_OLD_STYLE_LOGS before application start
 */
class LogSystem : private Noncopyable
{
public:
    LogSystem();
    virtual ~LogSystem();

    AbstractLogProvider::LogLevel GetLogLevel() const { return m_level; }

    void Log(AbstractLogProvider::LogLevel level,
             const char *message,
             const char *filename,
             int line,
             const char *function) const;


    /**
     * Set default's DLOG provider Tag
     */
    void SetTag(const char *tag);

    /**
     * Add abstract provider to providers list
     *
     * @notice Ownership is transfered to LogSystem and deleted upon exit
     */
    void AddProvider(AbstractLogProvider *provider);

    /**
     * Remove abstract provider from providers list
     */
    void RemoveProvider(AbstractLogProvider *provider);

    /**
     * Selects given provider by name (overwrites environment setting)
     *
     * Throws std::out_of_range exception if not found.
     */
    void SelectProvider(const std::string& name);

    /**
     * Sets log level (overwrites environment settings)
     */
    void SetLogLevel(const char* level);

private:
    void RemoveProviders();

    typedef std::list<AbstractLogProvider *> AbstractLogProviderPtrList;
    AbstractLogProviderPtrList m_providers;
    AbstractLogProvider::LogLevel m_level;

    typedef AbstractLogProvider *(*ProviderFn)();
    /*
     * It cannot be global as it is used in library constructor and we can't be sure which
     * constructor is called first: library's or new_provider's.
     */
    std::unordered_map<std::string, ProviderFn> m_providerCtor;
};

/*
 * Replacement low overhead null logging class
 */
class NullStream
{
  public:
    NullStream() {}

    template <typename T>
    NullStream& operator<<(const T&)
    {
        return *this;
    }
};

/**
 * Log system singleton
 */
typedef Singleton<LogSystem> LogSystemSingleton;
}
} // namespace VcoreDPL


/* avoid warnings about unused variables */
#define DPL_MACRO_DUMMY_LOGGING(message, level)                                 \
    do {                                                                        \
        VcoreDPL::Log::NullStream ns;                                           \
        ns << message;                                                          \
    } while (0)

#define DPL_MACRO_FOR_LOGGING(message, level)                                   \
do                                                                              \
{                                                                               \
    if (level > VcoreDPL::Log::AbstractLogProvider::LogLevel::None &&           \
        VcoreDPL::Log::LogSystemSingleton::Instance().GetLogLevel() >= level)   \
    {                                                                           \
        std::ostringstream platformLog;                                         \
        platformLog << message;                                                 \
        VcoreDPL::Log::LogSystemSingleton::Instance().Log(level,                \
                                                     platformLog.str().c_str(), \
                                                     __FILE__,                  \
                                                     __LINE__,                  \
                                                     __FUNCTION__);             \
    }                                                                           \
} while (0)


#ifdef BUILD_TYPE_DEBUG
    #define LogDebug(message)    DPL_MACRO_FOR_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Debug)
    #define LogPedantic(message) DPL_MACRO_FOR_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Pedantic)
#else
    #define LogDebug(message)    DPL_MACRO_DUMMY_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Debug)
    #define LogPedantic(message) DPL_MACRO_DUMMY_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Pedantic)
#endif // BUILD_TYPE_DEBUG

#define LogInfo(message)    DPL_MACRO_FOR_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Info)
#define LogWarning(message) DPL_MACRO_FOR_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Warning)
#define LogError(message)   DPL_MACRO_FOR_LOGGING(message, VcoreDPL::Log::AbstractLogProvider::LogLevel::Error)

#endif // DPL_LOG_H
