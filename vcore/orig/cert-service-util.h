/*
 * certification service
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef CERT_SERVICE_UTIL_H
#define CERT_SERVICE_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

int cert_svc_util_load_file_to_buffer(const char* filePath, cert_svc_mem_buff* certBuf);

int release_certificate_buf(cert_svc_mem_buff* certBuf);
int release_certificate_data(cert_svc_cert_descriptor* certDesc);
int release_cert_list(cert_svc_linked_list* certList);
int release_filename_list(cert_svc_filename_list* fileNames);

#ifdef __cplusplus
}
#endif

#endif // CERT_SERVICE_UTIL_H
