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
 * @file        TimeConversion.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     0.1
 * @brief
 */
#ifndef _VALIDATION_CORE_TIMECONVERSION_H_
#define _VALIDATION_CORE_TIMECONVERSION_H_

#include <ctime>
#include <openssl/asn1.h>

namespace ValidationCore {

/*
 * openssl/crypto/asn1/a_time.c based version 1.0.2d
 * return 1 on success, 0 on error
 */
int asn1TimeToTimeT(ASN1_TIME *t, time_t *res);

} // namespace ValidationCore

#endif // _VALIDATION_CORE_TIMECONVERSION_H_
