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
#pragma once

#include <string>

#include <vcore/SignatureValidator.h>

const char *validatorErrorToString(ValidationCore::SignatureValidator::Result error);

namespace TestData {

extern const std::string certEE;   /* MBANK,    signed by SYMANTEC, expires 04 Feb 2016 */
extern const std::string certIM;   /* SYMANTEC, signed by VERISIGN, expires 30 Oct 2023 */
extern const std::string certRoot; /* VERISIGN, signed by self,     expires 30 Oct 2023 */

}
