#ifndef DPLUS_H
#define DPLUS_H

#include <netdb.h>
#include <sys/time.h>

#include "lruhash.h"

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
};

//set cache and ttl before init env
void dp_set_cache_mem(size_t maxmem);
void dp_set_ttl(int ttl);

//dplus environment init and destroy
void dp_env_init();
void dp_env_destroy();

//flush host name from cache
void dp_flush_cache(const char *node);

//similar with getaddrinfo
int dp_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res);

//similar with freeaddrinfo
void dp_freeaddrinfo(struct addrinfo *res);

/** internal functions */
struct host_info *dp_query(const char *node);
struct host_info *http_query(const char *node, time_t *ttl);

//http request api
int make_connection(char *serv_ip, int port);
int make_request(int sockfd, char *hostname, char *request_path);
int fetch_response(int sockfd, char *http_data, size_t http_data_len);

/** */

#endif
