#include "../dplus.h"

#define BUF_SIZE 102400

int main(int argc, char **argv)
{
    struct addrinfo *answer, hint, *curr;
    char ipstr[16];
    int ret, sfd;
    struct timeval time, time2;
    char http_data[BUF_SIZE];

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

    //first
    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(argv[1], "http", &hint, &answer);
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
    printf("first time:%lu ms\n\n", (time2.tv_usec - time.tv_usec)/1000);

    //second
    gettimeofday(&time, NULL);
    ret = dp_getaddrinfo(argv[1], "http", &hint, &answer);
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

    printf("start http query:%s\n", argv[1]);
    for (curr = answer; curr != NULL; curr = curr->ai_next) {
        sfd = socket(curr->ai_family, curr->ai_socktype,
               curr->ai_protocol);
        if (sfd == -1)
           continue;

        if (connect(sfd, curr->ai_addr, curr->ai_addrlen) != -1)
            break;

        close(sfd);
    }
    //no longer needed
    dp_freeaddrinfo(answer);

    ret = make_request(sfd, argv[1], "/");
    if (ret < 0) {
        printf("make request failed\n");
        close(sfd);
        return -1;
    }

    ret = fetch_response(sfd, http_data, BUF_SIZE);
    if (ret < 0) {
        printf("fetch response failed\n");
        close(sfd);
        return -1;
    }
    close(sfd);

    printf("%s\n", http_data);

    dp_env_destroy();
    return 0;
}
