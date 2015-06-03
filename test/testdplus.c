/* Copyright (c) 2006-2015, DNSPod Inc.
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2.Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the FreeBSD Project.
*/

#include "testmain.h"
#include "../dplus.h"

#define DP_DES_ID   12
#define DP_DES_KEY  "@o]T<oX/"
#define HTTPDNS_DEFAULT_SERVER "119.29.29.29"

extern struct dp_env *dpe;

static void test_http_query()
{
    time_t ttl = 0;
    struct host_info *hi;

    hi = http_query("www.qq.com", &ttl);
    unit_assert(ttl && hi);

    dpe->serv_ip = "127.0.0.1";
    hi = http_query("www.qq.com", &ttl);
    unit_assert(hi == NULL);

    dpe->serv_ip = HTTPDNS_DEFAULT_SERVER;
}

static void test_enterprise_http_query()
{
    time_t ttl = 0;
    struct host_info *hi;

    dpe->des_used = 1;
    dpe->des_id = DP_DES_ID;
    dpe->des_key = DP_DES_KEY;
    hi = http_query("www.qq.com", &ttl);
    unit_assert(ttl && hi);

    dpe->serv_ip = "127.0.0.1";
    hi = http_query("www.qq.com", &ttl);
    unit_assert(hi == NULL);

    dpe->serv_ip = HTTPDNS_DEFAULT_SERVER;
    dpe->des_used = 0;
}

static void test_dns_query()
{
    time_t ttl = 0;
    struct host_info *hi;

    hi = dns_query("www.qq.com", &ttl);
    unit_assert(ttl && hi);
}

static void test_prefetch()
{
    int ret;
    hashvalue_t h;
    struct lruhash_entry *e;
    struct reply_info *repinfo;
    struct query_info qinfo;
    qinfo.node = "www.qq.com";

    h = query_info_hash(&qinfo);
    ret = prefetch_new_query(&qinfo, h);
    unit_assert(ret == 0);
    unit_assert(dpe->prefetch_list->used == 1);
    sleep(5);
    unit_assert(dpe->prefetch_list->used == 0);

    e = lruhash_lookup(dpe->cache, h, &qinfo);
    unit_assert(e);
    repinfo = (struct reply_info*)e->data;
    unit_assert(repinfo && repinfo->host);
    lock_basic_unlock(&e->lock);
}

void dplus_test()
{
    printf("test dplus functions\n");
    dp_env_init();

    test_http_query();
    test_enterprise_http_query();
    test_dns_query();
    test_prefetch();

    dp_env_destroy();
}
