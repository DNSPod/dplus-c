#include "../dplus.h"

int main(int argc, char **argv)
{
    struct addrinfo *answer, hint, *curr;
    char ipstr[16];
    int ret;
    struct timeval time, time2;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s hostname\n", argv[1]);
        exit(1);
    }

    //init dplus environment
    dp_set_cache_mem(4*1024*1024);
    dp_set_ttl(90);
#ifdef ENTERPRISE_EDITION
    dp_set_des_id(DP_DES_ID);
    dp_set_des_key(DP_DES_KEY);
#endif
    
    dp_env_init();

    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    
    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(argv[1], NULL, &hint, &answer);
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
   
    dp_freeaddrinfo(answer);
    gettimeofday(&time2, NULL);
    printf("first time:%lu ms\n", (time2.tv_usec - time.tv_usec)/1000);

    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(argv[1], NULL, &hint, &answer);
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
    dp_freeaddrinfo(answer);
    gettimeofday(&time2, NULL);
    printf("second time:%lu ms\n", (time2.tv_usec - time.tv_usec)/1000);
    
    dp_env_destroy();
    return 0;
}
