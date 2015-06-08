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

#include "dplus.h"
#include "lruhash.h"


#define HTTPDNS_DEFAULT_SERVER "119.29.29.29"
#define HTTPDNS_DEFAULT_PORT   80

#define CACHE_DEFAULT_MIN_TTL  90

#define INVALID_DES_ID -1
#define DES_KEY_SIZE 16

#define HTTP_DEFAULT_DATA_SIZE 256

//calculate the prefetch TTL as 75% of original
#define PREFETCH_TTL_CALC(ttl) ((ttl) - (ttl)/4)

//dplus environment
struct dp_env *dpe = NULL;

//max memory of dns cache
static size_t cache_maxmem = HASH_DEFAULT_MAXMEM;

//min cache ttl
static int min_ttl = CACHE_DEFAULT_MIN_TTL;

// des id and key
static uint32_t des_id = INVALID_DES_ID;
static char des_key[DES_KEY_SIZE] = { 0 };
// 是否使用des加密
static uint32_t des_used = 0;

//http dns server and port
static char *serv_ip = HTTPDNS_DEFAULT_SERVER;
static int port = HTTPDNS_DEFAULT_PORT;

void dp_set_cache_mem(size_t maxmem)
{
    cache_maxmem = maxmem;
}

void dp_set_ttl(int ttl)
{
    min_ttl = ttl;
}

void dp_set_des_id_key(uint32_t id, const char *key)
{
    if (0 == id || NULL == key)
        return;

    des_id = id;
    snprintf(des_key, DES_KEY_SIZE - 1, "%s", key);
    des_key[DES_KEY_SIZE - 1] = 0;

    des_used = 1;
}

/*
* 对域名进行DES加密
* 如果不是UTF8格式，则需要转化为UTF8
* 返回值如果非NULL，需要释放
*/
char *dp_des_encrypt(const char *domain)
{
    EVP_CIPHER_CTX ctx;
    unsigned char buf[DOMAIN_MAX_SIZE] = { 0 };
    char *des_domain;
    int blen1, blen2, dlen = strlen(domain), des_len;
    int i;

    if (INVALID_DES_ID == des_id || dlen > DOMAIN_MAX_SIZE)
        return NULL;

    // 初始化ctx结构，使用des/ecb方式，padding方式默认即可
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, (const unsigned char*)des_key, NULL);
    //EVP_CIPHER_CTX_set_padding(&ctx, 0x0001);

    // 对称加密数据并padding
    EVP_EncryptUpdate(&ctx, buf, &blen1, (const unsigned char*)domain, dlen);
    EVP_EncryptFinal_ex(&ctx, buf + blen1, &blen2);
    EVP_CIPHER_CTX_cleanup(&ctx);

    des_len = (blen1 + blen2) * 2;
    des_domain = malloc(des_len + 1);
    if (NULL == des_domain)
        return NULL;

    for (i = 0; i < (blen1 + blen2); i++) {
        snprintf(des_domain + i * 2, des_len - i * 2 + 1, "%02x", ((u_char *)buf)[i]);
    }
    des_domain[des_len] = '\0';

    return des_domain;
}

/*
* 对域名进行DES解密
* 如果不是UTF8格式，则需要转化为UTF8
* 返回值如果非NULL，需要释放
*/
char *dp_des_decrypt(const char *des_ip)
{
    EVP_CIPHER_CTX ctx;
    char *buf, *sip;
    int blen1, blen2, des_len = strlen(des_ip), iplen;
    int i;

    if (INVALID_DES_ID == des_id)
        return NULL;

    iplen = des_len / 2;
    buf = malloc(iplen + 1);
    if (NULL == buf)
        return NULL;
    sip = malloc(iplen + 1);
    if (NULL == sip) {
        free(buf);
        return NULL;
    }

    //将16进制的字符串转换为字节字符串
    for (i = 0; i < iplen; i++) {
        char tmp[3] = { 0 };
        strncpy(tmp, des_ip + i * 2, 2);
        buf[i] = (char)strtoul(tmp, NULL, 16);
    }
    buf[iplen] = '\0';

    //初始化ctx结构，使用des/ecb方式，padding方式默认即可
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_des_ecb(), NULL, (const unsigned char*)des_key, NULL);
    //EVP_CIPHER_CTX_set_padding(&ctx, 0x0001);

    //解密数据并移除padding
    EVP_DecryptUpdate(&ctx, (unsigned char*)sip, &blen1, (const unsigned char*)buf, iplen);
    EVP_DecryptFinal_ex(&ctx, (unsigned char*)(sip + blen1), &blen2);
    EVP_CIPHER_CTX_cleanup(&ctx);

    iplen = blen1 + blen2;
    sip[iplen] = '\0';

    free(buf);
    return sip;
}

static int wait_event(int sockfd, struct timeval *timeout, int read, int write)
{
    int ret;
    fd_set *readset, *writeset;
    fd_set set;

    FD_ZERO(&set);
    FD_SET(sockfd, &set);

    readset = read ? &set : NULL;
    writeset = write ? &set : NULL;

    ret = select(FD_SETSIZE, readset, writeset, NULL, timeout);
    return (ret <= 0 || !FD_ISSET(sockfd, &set)) ? -1 : 0;
}

int wait_readable(int sockfd, struct timeval timeout) {
    return wait_event(sockfd, &timeout, 1, 0);
}

int wait_writable(int sockfd, struct timeval timeout) {
    return wait_event(sockfd, &timeout, 0, 1);
}

//djb2 hash function
static hashvalue_t hashfunc(const char *key, size_t klen) {
    hashvalue_t hash = 5381;
    while (klen--) {
        hash = ((hash << 5) + hash) + *key++; //hash * 33 + c
    }
    return hash;
}

hashvalue_t query_info_hash(struct query_info *q)
{
    return hashfunc(q->node, strlen(q->node));
}

static size_t msgreply_sizefunc(void *k, void *d)
{
    struct msgreply_entry *q = (struct msgreply_entry *)k;
    struct reply_info *r = (struct reply_info *)d;
    size_t s = sizeof(struct msgreply_entry);
    s += strlen(q->key.node);
    s += sizeof(struct reply_info);
    s += sizeof(struct host_info);
    s += sizeof(char) * (r->host->h_length) * (r->host->addr_list_len);
    return s;
}

static int query_info_compare(void *k1, void *k2)
{
    struct query_info *q1 = (struct query_info *)k1;
    struct query_info *q2 = (struct query_info *)k2;
    return strcmp(q1->node, q2->node);
}

static void query_info_copy(struct query_info *d, struct query_info *s)
{
    memcpy(d, s, sizeof(*s));
    d->node = strdup(s->node);
}

static void query_info_clear(struct query_info *qinfo)
{
    free(qinfo->node);
}

void query_entry_delete(void *k)
{
    struct msgreply_entry *q = (struct msgreply_entry *)k;
    lock_basic_destroy(&q->entry.lock);
    query_info_clear(&q->key);
    free(q);
}

static void host_info_clear(struct host_info *host)
{
    int i;
    for (i = 0; i < host->addr_list_len; i++) {
        if (host->h_addr_list[i]) {
            free(host->h_addr_list[i]);
        }
    }
    free(host->h_addr_list);
    free(host);
}

static void reply_info_delete(void *d)
{
    struct reply_info *r = (struct reply_info *)d;
    host_info_clear(r->host);
    free(r);
}

static struct msgreply_entry *query_info_entrysetup(struct query_info *q,
struct reply_info *r, hashvalue_t h)
{
    struct msgreply_entry *e = (struct msgreply_entry *)malloc(
        sizeof(struct msgreply_entry));
    if (!e) return NULL;
    query_info_copy(&e->key, q);
    e->entry.hash = h;
    e->entry.key = e;
    e->entry.data = r;
    lock_basic_init(&e->entry.lock);
    return e;
}

static void dns_cache_store_msg(struct query_info *qinfo, hashvalue_t hash,
struct host_info *hi, time_t ttl)
{
    struct msgreply_entry *e;
    struct reply_info *rep;
    time_t now = time(NULL);
    rep = (struct reply_info *)malloc(sizeof(struct reply_info));
    if (rep == NULL) {
        fprintf(stderr, "malloc struct reply_info failed\n");
        return;
    }

    rep->host = hi;
    ttl = ttl < CACHE_DEFAULT_MIN_TTL ? CACHE_DEFAULT_MIN_TTL : ttl;
    rep->ttl = ttl + now;
    rep->prefetch_ttl = PREFETCH_TTL_CALC(ttl) + now;

    if (!(e = query_info_entrysetup(qinfo, rep, hash))) {
        fprintf(stderr, "store_msg: malloc failed");
        reply_info_delete(rep);
        return;
    }
    lruhash_insert(dpe->cache, hash, &e->entry, rep);
}

static struct prefetch_stat_list *new_prefetch_list()
{
    struct prefetch_stat_list *prefetch_list;
    prefetch_list = (struct prefetch_stat_list *)malloc(
        sizeof(struct prefetch_stat_list));
    if (prefetch_list == NULL) {
        fprintf(stderr, "new_prefetch_list failed");
        exit(1);
    }

    lock_basic_init(&prefetch_list->lock);
    prefetch_list->head = NULL;
    prefetch_list->used = 0;

    return prefetch_list;
}

static struct prefetch_stat *new_prefetch_stat(struct query_info *qinfo)
{
    struct prefetch_stat *prefetch;
    prefetch = (struct prefetch_stat *)malloc(sizeof(struct prefetch_stat));
    if (prefetch == NULL) {
        fprintf(stderr, "malloc struct prefetch_stat failed\n");
        return NULL;
    }
    query_info_copy(&prefetch->qinfo, qinfo);
    prefetch->next = NULL;
    return prefetch;
}

static void free_prefetch_stat(struct prefetch_stat *prefetch)
{
    query_info_clear(&prefetch->qinfo);
    free(prefetch);
}

static void prefetch_list_destroy(struct prefetch_stat_list *list)
{
    struct prefetch_stat *s, *t;

    lock_basic_destroy(&list->lock);
    s = list->head;
    while (s) {
        t = s;
        s = s->next;
        free_prefetch_stat(t);
    }
    free(list);
}

static int prefetch_stat_exist(struct query_info *qinfo,
struct prefetch_stat *s)
{
    while (s) {
        if (query_info_compare((void *)qinfo, (void *)(&s->qinfo)) == 0){
            return 1;
        }
        s = s->next;
    }
    return 0;
}

static struct prefetch_stat *prefetch_stat_insert(struct query_info *qinfo,
struct prefetch_stat_list *list)
{
    struct prefetch_stat *s, *new_prefetch;
    int ret;

    lock_basic_lock(&list->lock);
    ret = prefetch_stat_exist(qinfo, list->head);
    if (ret) {
        lock_basic_unlock(&list->lock);
        return NULL;
    }

    new_prefetch = new_prefetch_stat(qinfo);
    if (new_prefetch == NULL) {
        lock_basic_unlock(&list->lock);
        return NULL;
    }
    s = list->head;
    if (s == NULL) {
        list->head = new_prefetch;
    }
    else {
        while (s->next)
            s = s->next;
        s->next = new_prefetch;
    }
    list->used++;
    lock_basic_unlock(&list->lock);
    return new_prefetch;
}

static int prefetch_stat_delete(struct query_info *qinfo,
struct prefetch_stat_list *list)
{
    struct prefetch_stat *s, *prev = NULL;
    lock_basic_lock(&list->lock);
    s = list->head;
    while (s) {
        if (query_info_compare((void *)qinfo, (void *)(&s->qinfo)) == 0){
            if (prev == NULL) {
                list->head = s->next;
            }
            else {
                prev->next = s->next;
            }
            lock_basic_unlock(&list->lock);
            free_prefetch_stat(s);
            list->used--;
            return 1;
        }
        prev = s;
        s = s->next;
    }
    lock_basic_unlock(&list->lock);
    return 0;
}

static void *prefetch_job(void *arg)
{
    struct prefetch_job_info *tinfo = (struct prefetch_job_info *)arg;
    struct host_info *hi;
    time_t ttl = 0;
    hi = http_query(tinfo->qinfo.node, &ttl);
    if (hi == NULL) {
        prefetch_stat_delete(&tinfo->qinfo, dpe->prefetch_list);
        free(tinfo);
        return NULL;
    }
    dns_cache_store_msg(&tinfo->qinfo, tinfo->hash, hi, ttl);
    prefetch_stat_delete(&tinfo->qinfo, dpe->prefetch_list);
    free(tinfo);
    return NULL;
}

int prefetch_new_query(struct query_info *qinfo, hashvalue_t hash)
{
    struct prefetch_job_info *tinfo;
    dp_thread_t tid;
    struct prefetch_stat *prefetch;

    prefetch = prefetch_stat_insert(qinfo, dpe->prefetch_list);
    if (prefetch == NULL) {
        return -1;
    }

    tinfo = (struct prefetch_job_info *)malloc(sizeof(struct prefetch_job_info));
    tinfo->qinfo = prefetch->qinfo;
    tinfo->hash = hash;

    dp_thread_create(&tid, &prefetch_job, tinfo);
    dp_thread_detach(tid);
    return 0;
}

static int is_integer(const char *s)
{
    if (*s == '-' || *s == '+')
        s++;
    if (*s < '0' || '9' < *s)
        return 0;
    s++;
    while ('0' <= *s && *s <= '9')
        s++;
    return (*s == '\0');
}

static int is_address(const char *s)
{
    unsigned char buf[sizeof(struct in6_addr)];
    int r;

    r = inet_pton(AF_INET, s, buf);
    if (r <= 0) {
        r = inet_pton(AF_INET6, s, buf);
        return (r > 0);
    }

    return 1;
}

static struct addrinfo *malloc_addrinfo(int port, uint32_t addr,
    int socktype, int proto)
{
    struct addrinfo *ai;
    struct sockaddr_in *sa_in;
    size_t socklen;
    socklen = sizeof(struct sockaddr_in);

    ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo) + socklen);
    if (!ai)
        return NULL;

    ai->ai_socktype = socktype;
    ai->ai_protocol = proto;

    ai->ai_addr = (struct sockaddr *)(ai + 1);
    ai->ai_addrlen = socklen;
    ai->ai_addr->sa_family = ai->ai_family = AF_INET;

    sa_in = (struct sockaddr_in *)ai->ai_addr;
    sa_in->sin_port = port;
    sa_in->sin_addr.s_addr = addr;

    return ai;
}

static int fillin_addrinfo_res(struct addrinfo **res, struct host_info *hi,
    int port, int socktype, int proto)
{
    int i;
    struct addrinfo *cur, *prev = NULL;
    for (i = 0; i < hi->addr_list_len; i++) {
        struct in_addr *in = ((struct in_addr *)hi->h_addr_list[i]);
        cur = malloc_addrinfo(port, in->s_addr, socktype, proto);
        if (cur == NULL) {
            if (*res)
                dp_freeaddrinfo(*res);
            return EAI_MEMORY;
        }
        if (prev)
            prev->ai_next = cur;
        else
            *res = cur;
        prev = cur;
    }

    return 0;
}

void dp_env_init()
{
    if (dpe != NULL)
        return;
    dpe = (struct dp_env*)calloc(1, sizeof(struct dp_env));
    if (!dpe) {
        fprintf(stderr, "dp_env_init: malloc failed");
        exit(1);
    }

    dpe->cache_maxmem = cache_maxmem;
    dpe->min_ttl = min_ttl;
    dpe->serv_ip = serv_ip;
    dpe->port = port;
    dpe->cache = lruhash_create(HASH_DEFAULT_ARRAY_SIZE, dpe->cache_maxmem,
        msgreply_sizefunc, query_info_compare,
        query_entry_delete, reply_info_delete);
    if (dpe->cache == NULL) {
        fprintf(stderr, "lruhash_create failed");
        exit(1);
    }
    dpe->prefetch_list = new_prefetch_list();

    dpe->des_used = des_used;
    dpe->des_id = des_id;
    dpe->des_key = des_key;
    if (dpe->des_used) {
        if (!dp_openssl_lock_init()){
            fprintf(stderr, "init openssl locks failed\n");
            exit(1);
        }
    }
}

void dp_env_destroy()
{
    if (dpe == NULL)
        return;

    lruhash_delete(dpe->cache);
    prefetch_list_destroy(dpe->prefetch_list);
    if (dpe->des_used) {
        dp_openssl_lock_delete();
    }
    free(dpe);
}

void dp_flush_cache(const char *node)
{
    hashvalue_t h;
    struct query_info qinfo;

    qinfo.node = (char *)node;
    h = query_info_hash(&qinfo);
    lruhash_remove(dpe->cache, h, &qinfo);
}

static void print_key(void *key)
{
    struct msgreply_entry *q = (struct msgreply_entry *)key;
    fprintf(stdout, "entry key:%s;", q->key.node);
}

static void print_value(void *data)
{
    struct reply_info *rep = (struct reply_info *)data;
    int i;
    char ipstr[16] = { 0 };
    fprintf(stdout, "ip count[%d]:", rep->host->addr_list_len);
    for (i = 0; i < rep->host->addr_list_len; ++i) {
        inet_ntop(AF_INET, rep->host->h_addr_list[i], ipstr, 16);
        fprintf(stdout, "%s,", ipstr);
    }
    fprintf(stdout, "ttl:%llu, prefetch_ttl:%llu\n", (unsigned long long)rep->ttl, 
        (unsigned long long)rep->prefetch_ttl);
}

void dp_cache_status()
{
    lruhash_status(dpe->cache, print_key, print_value);
}

static int strchr_num(const char *str, char c)
{
    int count = 0;
    while (*str){
        if (*str++ == c){
            count++;
        }
    }
    return count;
}

struct host_info *http_query(const char *node, time_t *ttl)
{
    int i, ret, sockfd;
    struct host_info *hi;
    char http_data[HTTP_DEFAULT_DATA_SIZE + 1];
    char *http_data_ptr, *http_data_ptr_head;
    char *comma_ptr;

#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    sockfd = make_connection(dpe->serv_ip, dpe->port);
    if (sockfd < 0) {
#ifdef WIN32
        WSACleanup();
#endif
        return NULL;
    }

    if (des_used)
        snprintf(http_data, HTTP_DEFAULT_DATA_SIZE, "/d?dn=%s&ttl=1&id=%d", node, des_id);
    else
        snprintf(http_data, HTTP_DEFAULT_DATA_SIZE, "/d?dn=%s&ttl=1", node);
    http_data[HTTP_DEFAULT_DATA_SIZE] = 0;

    ret = make_request(sockfd, dpe->serv_ip, http_data);
    if (ret < 0){
#ifdef WIN32
        closesocket(sockfd);
        WSACleanup();
#else
        close(sockfd);
#endif
        return NULL;
    }

    ret = fetch_response(sockfd, http_data, HTTP_DEFAULT_DATA_SIZE);
#ifdef WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    if (ret < 0)
        return NULL;

    if (des_used) {
        http_data_ptr = dp_des_decrypt(http_data);
        if (NULL == http_data_ptr)
            return NULL;
        http_data_ptr_head = http_data_ptr;
    }
    else {
        http_data_ptr = http_data;
    }

    comma_ptr = strchr(http_data_ptr, ',');
    if (comma_ptr != NULL) {
        sscanf(comma_ptr + 1, "%ld", ttl);
        *comma_ptr = '\0';
    }
    else {
        *ttl = 0;
    }

    hi = (struct host_info *)malloc(sizeof(struct host_info));
    if (hi == NULL) {
        fprintf(stderr, "malloc struct host_info failed\n");
        return NULL;
    }

    //Only support IPV4
    hi->h_addrtype = AF_INET;
    hi->h_length = sizeof(struct in_addr);
    hi->addr_list_len = strchr_num(http_data_ptr, ';') + 1;
    hi->h_addr_list = (char **)calloc(hi->addr_list_len, sizeof(char *));
    if (hi->h_addr_list == NULL) {
        fprintf(stderr, "calloc addr_list failed\n");
        free(hi);
        goto error;
    }

    for (i = 0; i < hi->addr_list_len; ++i) {
        char *addr;
        char *ipstr = http_data_ptr;
        char *semicolon = strchr(ipstr, ';');
        if (semicolon != NULL) {
            *semicolon = '\0';
            http_data_ptr = semicolon + 1;
        }

        addr = (char *)malloc(sizeof(struct in_addr));
        if (addr == NULL) {
            fprintf(stderr, "malloc struct in_addr failed\n");
            host_info_clear(hi);
            goto error;
        }
        ret = inet_pton(AF_INET, ipstr, addr);
        if (ret <= 0) {
            fprintf(stderr, "invalid ipstr:%s\n", ipstr);
            host_info_clear(hi);
            goto error;
        }

        hi->h_addr_list[i] = addr;
    }

    if (des_used)
        free(http_data_ptr_head);

    return hi;

error:
    if (des_used)
        free(http_data_ptr_head);

    return NULL;
}

struct host_info *dns_query(const char *node, time_t *ttl)
{
    char buf[DNS_DEFAULT_DATA_SIZE] = { 0 };
    int query_len;
    struct host_info *hi = NULL;
    int Anum = 0, i, ret;

    ret = make_dns_query_format(node, buf, &query_len);
    if (ret < 0) {
        fprintf(stderr, "make dns query format failed\n");
        return NULL;
    }

    ret = make_dns_query(buf, query_len, ttl, &Anum);
    if (ret < 0) {
        fprintf(stderr, "make dns query failed\n");
        return NULL;
    }

    hi = (struct host_info *)malloc(sizeof(struct host_info));
    if (hi == NULL) {
        fprintf(stderr, "malloc struct host_info failed\n");
        return NULL;
    }

    hi->h_addrtype = AF_INET;
    hi->h_length = sizeof(struct in_addr);
    hi->addr_list_len = Anum;
    hi->h_addr_list = (char **)calloc(hi->addr_list_len, sizeof(char *));
    if (hi->h_addr_list == NULL) {
        fprintf(stderr, "calloc addr_list failed\n");
        free(hi);
        return NULL;
    }

    for (i = 0; i < Anum; i++) {
        char *addr = (char *)malloc(sizeof(struct in_addr));
        if (addr == NULL) {
            fprintf(stderr, "malloc struct in_addr failed\n");
            host_info_clear(hi);
            return NULL;
        }
        memcpy(addr, buf + i * 4, sizeof(struct in_addr));
        hi->h_addr_list[i] = addr;
    }

    return hi;
}

void dp_freeaddrinfo(struct addrinfo *ai)
{
    //freeaddrinfo(res);
    struct addrinfo *next;
    while (ai != NULL) {
        if (ai->ai_canonname != NULL)
            free(ai->ai_canonname);
        next = ai->ai_next;
        free(ai);
        ai = next;
    }
}

int dp_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
{
    struct host_info *hi = NULL;
    int port = 0, socktype, proto, ret = 0;
    char *dnode;

    hashvalue_t h;
    struct lruhash_entry *e;
    struct query_info qinfo;
    time_t now = time(NULL);
    time_t ttl;

    if (node == NULL)
        return EAI_NONAME;

    //AI_NUMERICHOST not supported
    if (is_address(node) || (hints && (hints->ai_flags & AI_NUMERICHOST)))
        return EAI_BADFLAGS;

    if (hints && hints->ai_family != PF_INET
        && hints->ai_family != PF_UNSPEC
        && hints->ai_family != PF_INET6) {
        return EAI_FAMILY;
    }
    if (hints && hints->ai_socktype != SOCK_DGRAM
        && hints->ai_socktype != SOCK_STREAM
        && hints->ai_socktype != 0) {
        return EAI_SOCKTYPE;
    }

    socktype = (hints && hints->ai_socktype) ? hints->ai_socktype
        : SOCK_STREAM;
    if (hints && hints->ai_protocol)
        proto = hints->ai_protocol;
    else {
        switch (socktype) {
        case SOCK_DGRAM:
            proto = IPPROTO_UDP;
            break;
        case SOCK_STREAM:
            proto = IPPROTO_TCP;
            break;
        default:
            proto = 0;
            break;
        }
    }

    if (service != NULL && service[0] == '*' && service[1] == 0)
        service = NULL;

    if (service != NULL) {
        if (is_integer(service))
            port = htons(atoi(service));
        else {
            struct servent *servent;
            char *pe_proto;
#ifdef WIN32
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
            switch (socktype){
            case SOCK_DGRAM:
                pe_proto = "udp";
                break;
            case SOCK_STREAM:
                pe_proto = "tcp";
                break;
            default:
                pe_proto = "tcp";
                break;
            }
            servent = getservbyname(service, pe_proto);
            if (servent == NULL) {
#ifdef WIN32
                WSACleanup();
#endif
                return EAI_SERVICE;
            }
            port = servent->s_port;
#ifdef WIN32
            WSACleanup();
#endif
        }
    }
    else {
        port = htons(0);
    }

    qinfo.node = (char *)node;
    h = query_info_hash(&qinfo);
    e = lruhash_lookup(dpe->cache, h, &qinfo);
    if (e) {
        struct reply_info *repinfo = (struct reply_info*)e->data;
        time_t ttl = repinfo->ttl;
        time_t prefetch_ttl = repinfo->prefetch_ttl;
        if (ttl > now) {
            ret = fillin_addrinfo_res(res, repinfo->host,
                port, socktype, proto);
            lock_basic_unlock(&e->lock);

            //prefetch it if the prefetch ttl expired
            if (prefetch_ttl <= now)
                prefetch_new_query(&qinfo, h);
            return ret;
        }
        lock_basic_unlock(&e->lock);
    }

    // 企业版需要先对域名进行对称加密
    if (des_used) {
        dnode = dp_des_encrypt(node);
        if (NULL == dnode) {
            fprintf(stderr, "dp_des_encrypt: %s\n", node);
            return -1;
        }
    }
    else {
        dnode = (char *)node;
    }

    /*
    * 首先使用HttpDNS向D+服务器进行请求,
    * 如果失败则向Public DNS进行请求，
    * 如果再失败则调用系统接口进行解析，该结果不会缓存
    */
    hi = http_query(dnode, &ttl);
    if (des_used)
        free(dnode);
    if (NULL == hi) {
        hi = dns_query(node, &ttl);
        if (NULL == hi) {
            return getaddrinfo(node, service, hints, res);
        }
    }
    ret = fillin_addrinfo_res(res, hi, port, socktype, proto);

    dns_cache_store_msg(&qinfo, h, hi, ttl);

    return ret;
}
