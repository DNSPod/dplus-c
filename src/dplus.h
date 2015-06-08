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

#ifndef DPLUS_H
#define DPLUS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define snprintf(buf, size, format, ...) _snprintf_s(buf, size, size - 1, format, __VA_ARGS__)
#define strncpy(dest, src, n) strncpy_s(dest, sizeof(dest), src, n)
#define strcasecmp _stricmp
#define strdup _strdup
#define sscanf sscanf_s

#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#endif

#include <openssl/evp.h>

#include "lruhash.h"
#include "locks.h"

#define DOMAIN_MAX_SIZE 256
#define DNS_DEFAULT_DATA_SIZE 512

struct query_info {
    char *node;
};

struct host_info {
    //host address type: AF_INET or AF_INET6
    int h_addrtype;

    /*length of address in bytes:
        sizeof(struct in_addr) or sizeof(struct in6_addr)
    */
    int h_length;

    //length of addr list
    int addr_list_len;
    //list of addresses
    char **h_addr_list;
};

struct reply_info {
    struct host_info *host;

    time_t ttl;
    time_t prefetch_ttl;
};

struct msgreply_entry {
    //hash table key
    struct query_info key;
    //hash table entry, data is struct reply_info
    struct lruhash_entry entry;
};

struct prefetch_stat {
    //query info
    struct query_info qinfo;

    //next in linked list
    struct prefetch_stat *next;
};

struct prefetch_stat_list {
    lock_basic_t lock;
    int used;
    struct prefetch_stat *head;
};

//dplus environment
struct dp_env {
    //dns cache
    struct lruhash *cache;
    //max memory of dns cache
    size_t cache_maxmem;

    //min cache ttl
    int min_ttl;

    //prefech job list;
    struct prefetch_stat_list *prefetch_list;

    //http dns server and port
    char *serv_ip;
    int port;

    //des_used
    int des_used;
    int des_id;
    char *des_key;
};

/** API */

//set cache and ttl before init env
void dp_set_cache_mem(size_t maxmem);
void dp_set_ttl(int ttl);

//enterprise version interface
void dp_set_des_id_key(uint32_t id, const char *key);
char *dp_des_encrypt(const char *domain);
char *dp_des_decrypt(const char *des_ip);

//dplus environment init and destroy
void dp_env_init();
void dp_env_destroy();

//flush host name from cache
void dp_flush_cache(const char *node);

//dplus cache status
void dp_cache_status();

//similar with getaddrinfo
int dp_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res);

//similar with freeaddrinfo
void dp_freeaddrinfo(struct addrinfo *res);

/** */

/** internal functions */

int wait_readable(int sockfd, struct timeval timeout);
int wait_writable(int sockfd, struct timeval timeout);

struct host_info *http_query(const char *node, time_t *ttl);
struct host_info *dns_query(const char *node, time_t *ttl);

//http request api
int make_connection(char *serv_ip, int port);
int make_request(int sockfd, char *hostname, char *request_path);
int fetch_response(int sockfd, char *http_data, size_t http_data_len);

// dns request api
int make_dns_query_format(const char *node, char *buf, int *query_len);
int make_dns_query(char *buf, int query_len, time_t *ttl, int *Anum);

/** for tests **/

extern struct dp_env *dpe;

//hash function
hashvalue_t query_info_hash(struct query_info *q);

void host_info_clear(struct host_info *host);

//prefetch job struct and function
struct prefetch_job_info {
    struct query_info qinfo;
    hashvalue_t hash;
};
int prefetch_new_query(struct query_info *qinfo, hashvalue_t hash);


/** */

#endif
