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
 * @file        Error.h
 * @author      Kyungwook Tak (k.tak@samsung.com)
 * @version     1.0
 * @brief       Error codes of signature validator.
 */
#pragma once

namespace ValidationCore {

using VCerr = int;

const VCerr E_SIG_NONE           = 0;
const VCerr E_SIG_INVALID_FORMAT = -1;
const VCerr E_SIG_INVALID_CERT   = -2;
const VCerr E_SIG_INVALID_CHAIN  = -3;
const VCerr E_SIG_INVALID_REF    = -4;
const VCerr E_SIG_CERT_EXPIRED   = -5;
const VCerr E_SIG_CERT_NOT_YET   = -6;
const VCerr E_SIG_DISREGARDED    = -7;
const VCerr E_SIG_REVOKED        = -8;
const VCerr E_SIG_PLUGIN         = -9;
const VCerr E_SIG_OUT_OF_MEM     = -10;
const VCerr E_SIG_UNKNOWN        = -11;

const VCerr E_SCOPE_FIRST        = E_SIG_INVALID_FORMAT;
const VCerr E_SCOPE_LAST         = E_SIG_UNKNOWN;

}
