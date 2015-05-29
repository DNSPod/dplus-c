#include "../dplus.h"

int main(int argc, char **argv)
{
    struct addrinfo *answer, hint, *curr;
    char ipstr[16];
    int ret;

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
    dp_env_destroy();
    return 0;
}
