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
 * @file        TimeConversion.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Sangwan Kwon (sangwan.kwon@samsung.com)
 * @version     0.1
 * @brief
 */
#include <vcore/TimeConversion.h>
#include <dpl/log/log.h>

#include <cstring>
#include <climits>

#define TIME_MAX LONG_MAX // time_t max value in arch 32bit

namespace {

void _gmtime_adj(struct tm *tm, int offset)
{
    time_t t = mktime(tm);
    t += offset;

    memset(tm, 0, sizeof(struct tm));

    gmtime_r(&t, tm);
}

/*
 * from openssl/crypto/asn1/a_gentm.c, openssl version 1.0.2d
 * return 1 on success, 0 on error
 * 1. local time only                        : yyyymmddHHMMSS[.fff]
 * 2. UTC time only                          : yyyymmddHHMM[SS[.fff]]Z
 * 3. Difference between local and UTC times : yyyymmddHHMM[SS[.fff]](+|-)HHMM
 */
int asn1_generalizedtime_to_tm(struct tm *tm, const ASN1_GENERALIZEDTIME *d)
{
    static const int min[9] = { 0, 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[9] = { 99, 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_GENERALIZEDTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;
    /*
     * GENERALIZEDTIME is similar to UTCTIME except the year is represented
     * as YYYY. This stuff treats everything as a two digit field so make
     * first two fields 00 to 99
     */
    if (l < 13)
        goto err;
    for (i = 0; i < 7; i++) {
        if ((i == 6) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n * 100 - 1900;
                break;
            case 1:
                tm->tm_year += n;
                break;
            case 2:
                tm->tm_mon = n - 1;
                break;
            case 3:
                tm->tm_mday = n;
                break;
            case 4:
                tm->tm_hour = n;
                break;
            case 5:
                tm->tm_min = n;
                break;
            case 6:
                tm->tm_sec = n;
                break;
            }
        }
    }
    /*
     * Optional fractional seconds: decimal point followed by one or more
     * digits.
     */
    if (a[o] == '.') {
        if (++o > l)
            goto err;
        i = o;
        while ((a[o] >= '0') && (a[o] <= '9') && (o <= l))
            o++;
        /* Must have at least one digit after decimal point */
        if (i == o)
            goto err;
    }

    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? -1 : 1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 7; i < 9; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 7)
                    offset = n * 3600;
                else if (i == 8)
                    offset += n * 60;
            }
            o++;
        }
        if (offset)
            _gmtime_adj(tm, offset * offsign);
    } else if (a[o]) {
        /* Missing time zone information. */
        goto err;
    }
    return (o == l);
 err:
    return (0);
}

/*
 * from openssl/crypto/asn1/a_utctm.c, openssl version 1.0.2d
 * return 1 on success, 0 on error
 * 1. yymmddHHMM[SS]Z
 * 2. yymmddHHMM[SS](+|-)HHMM
 */
int asn1_utctime_to_tm(struct tm *tm, const ASN1_UTCTIME *d)
{
    static const int min[8] = { 0, 1, 1, 0, 0, 0, 0, 0 };
    static const int max[8] = { 99, 12, 31, 23, 59, 59, 12, 59 };
    char *a;
    int n, i, l, o;

    if (d->type != V_ASN1_UTCTIME)
        return (0);
    l = d->length;
    a = (char *)d->data;
    o = 0;

    if (l < 11)
        goto err;
    for (i = 0; i < 6; i++) {
        if ((i == 5) && ((a[o] == 'Z') || (a[o] == '+') || (a[o] == '-'))) {
            i++;
            if (tm)
                tm->tm_sec = 0;
            break;
        }
        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = a[o] - '0';
        if (++o > l)
            goto err;

        if ((a[o] < '0') || (a[o] > '9'))
            goto err;
        n = (n * 10) + a[o] - '0';
        if (++o > l)
            goto err;

        if ((n < min[i]) || (n > max[i]))
            goto err;
        if (tm) {
            switch (i) {
            case 0:
                tm->tm_year = n < 50 ? n + 100 : n;
                break;
            case 1:
                tm->tm_mon = n - 1;
                break;
            case 2:
                tm->tm_mday = n;
                break;
            case 3:
                tm->tm_hour = n;
                break;
            case 4:
                tm->tm_min = n;
                break;
            case 5:
                tm->tm_sec = n;
                break;
            }
        }
    }
    if (a[o] == 'Z')
        o++;
    else if ((a[o] == '+') || (a[o] == '-')) {
        int offsign = a[o] == '-' ? -1 : 1, offset = 0;
        o++;
        if (o + 4 > l)
            goto err;
        for (i = 6; i < 8; i++) {
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = a[o] - '0';
            o++;
            if ((a[o] < '0') || (a[o] > '9'))
                goto err;
            n = (n * 10) + a[o] - '0';
            if ((n < min[i]) || (n > max[i]))
                goto err;
            if (tm) {
                if (i == 6)
                    offset = n * 3600;
                else if (i == 7)
                    offset += n * 60;
            }
            o++;
        }
        if (offset)
            _gmtime_adj(tm, offset * offsign);
    }
    return o == l;
 err:
    return 0;
}

} // namespace anonymous

namespace ValidationCore {

int asn1TimeToTimeT(ASN1_TIME *t, time_t *res)
{
    if (res == NULL)
        return 0;

    int ret = 0;
    struct tm tm;

    memset(&tm, 0, sizeof(tm));

    if (t->type == V_ASN1_UTCTIME)
        ret = asn1_utctime_to_tm(&tm, t);
    else if (t->type == V_ASN1_GENERALIZEDTIME)
        ret = asn1_generalizedtime_to_tm(&tm, t);
    else
        ret = 0;

    if (ret == 0)
        return 0;

    char buf[27]; // asctime_r return 26 characters
    LogDebug("Convert asn1 to tm: " << asctime_r(&tm, buf));
    *res = mktime(&tm);

    // If time_t occured overflow, set TIME_MAX.
    if(*res == -1) {
        LogDebug("Occured overflow time_t. it may year 2038 problem.");
        *res = TIME_MAX;
    }

    LogDebug("Result time_t(tm format): " << asctime_r(localtime(res), buf));

    return 1;
}

} // namespace ValidationCore
