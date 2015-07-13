#pragma once

#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

char *get_complete_path(const char *str1, const char *str2);
int get_common_name(const char *path, struct x509_st *x509Struct, char **commonName);

#ifdef __cplusplus
}
#endif
