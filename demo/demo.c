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

#include "../src/dplus.h"

#define DP_DES_ID   12
#define DP_DES_KEY  "@o]T<oX/"
#define BUF_SIZE 102400

#ifdef WIN32
int gettimeofday(struct timeval *tp, void *tzp)
{
    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;
    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm. tm_isdst = -1;
    clock = mktime(&tm);
    tp->tv_sec = (long)clock;
    tp->tv_usec = wtm.wMilliseconds * 1000;
    return 0;
}
#else
#include <sys/time.h>
#endif

int main(int argc, char **argv)
{
    struct addrinfo *answer, hint, *curr;
    char ipstr[16];
    int ret, sfd;
    struct timeval time, time2;
    char http_data[BUF_SIZE];
    char *domain;

    if (argc != 2) {
        //fprintf(stderr, "Usage: %s hostname\n", argv[0]);
        //exit(1);
        domain = "www.dnspod.com";
    }
    else {
        domain = argv[1];
    }

    //init dplus environment
    dp_set_cache_mem(4*1024*1024);
    dp_set_ttl(90);

#ifdef ENTERPRISE_EDITION
    // 设置企业版加密ID和KEY
    dp_set_des_id_key(DP_DES_ID, DP_DES_KEY);
#endif

    dp_env_init();

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    //first
    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(domain, "http", &hint, &answer);
    if (ret != 0) {
        fprintf(stderr, "dp_getaddrinfo: %s\n", gai_strerror(ret));
        dp_env_destroy();
        return 1;
    }

    for (curr = answer; curr != NULL; curr = curr->ai_next) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr),
            ipstr, sizeof(ipstr));
        printf("%s\n", ipstr);
    }
    dp_freeaddrinfo(answer);
    gettimeofday(&time2, NULL);
    printf("first time:%lu ms\n\n", (time2.tv_usec - time.tv_usec)/1000);

    //second
    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(domain, "http", &hint, &answer);
    if (ret != 0) {
        fprintf(stderr, "dp_getaddrinfo: %s\n", gai_strerror(ret));
        dp_env_destroy();
        return 1;
    }

    for (curr = answer; curr != NULL; curr = curr->ai_next) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr),
            ipstr, 16);
        printf("%s\n", ipstr);
    }
    gettimeofday(&time2, NULL);
    printf("second time:%lu ms\n\n", (time2.tv_usec - time.tv_usec)/1000);

    printf("cache status:\n");
    dp_cache_status();
    printf("\n");

#ifdef WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    printf("start http query:%s\n", domain);
    for (curr = answer; curr != NULL; curr = curr->ai_next) {
        sfd = socket(curr->ai_family, curr->ai_socktype,
               curr->ai_protocol);
        if (sfd == -1)
           continue;

        if (connect(sfd, curr->ai_addr, curr->ai_addrlen) != -1)
            break;

#ifdef WIN32
        closesocket(sfd);
        WSACleanup();
#else
        close(sfd);
#endif
    }
    //no longer needed
    dp_freeaddrinfo(answer);

    ret = make_request(sfd, domain, "/");
    if (ret < 0) {
        printf("make request failed\n");
#ifdef WIN32
        closesocket(sfd);
        WSACleanup();
#else
        close(sfd);
#endif
        return -1;
    }

    ret = fetch_response(sfd, http_data, BUF_SIZE);
    if (ret < 0) {
        printf("fetch response failed\n");
#ifdef WIN32
        closesocket(sfd);
        WSACleanup();
#else
        close(sfd);
#endif
        return -1;
    }
#ifdef WIN32
    closesocket(sfd);
    WSACleanup();
#else
    close(sfd);
#endif

    printf("%s\n", http_data);

    dp_env_destroy();
    return 0;
}
