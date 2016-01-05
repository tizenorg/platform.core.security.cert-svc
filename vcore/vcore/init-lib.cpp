/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 * @file        init-lib.cpp
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       init/deinit global configuration for library
 */

#include <dpl/log/log.h>

__attribute__((constructor))
static void init_lib(void)
{
	try {
		VcoreDPL::Log::LogSystemSingleton::Instance().SetTag("CERT_SVC");
		VcoreDPL::Log::LogSystemSingleton::Instance().SetLogLevel(nullptr);
	} catch (...) {
		LogError("Failed to init lib for initialize log system");
	}
}
