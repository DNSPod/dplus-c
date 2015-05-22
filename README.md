# dplus-c

## 关于
    dplus-c 是d+的c语言sdk。

## dplus-c模块
    缓存模块: 使用的是LRU算法，当缓存超过预设值后，剔除最久未使用的信息。
    http模块: 发送和接收http请求。
    dplus模块: 包括初始化缓存、配置等，实现类似getaddrinfo的功能。

## dplus-c的DNS查询流程
    首先查找缓存中是否存在域名的信息:
    如果存在且ttl未过期，直接返回结果, 如果预取ttl过期，则进行预取;
    如果不存在或ttl过期， 则向d+服务器请求，返回结果后进行缓存;
    如果d+服务器未正确返回（返回空，超时等），则调用getaddrinfo;

## API说明
    在初始化之前，可以修改配置，初始化之后将不能修改。
    dp_set_cache_mem
        设置缓存的大小，单位是字节，默认是4M。
    dp_set_ttl
        设置最短ttl时间，默认90s。
        缓存中存储了域名的ttl和预取ttl，当预取ttl到期时，会开一个线程去d+重新请求，
        请求完成后再进行缓存，而d+服务器也会进行预取和缓存，所以此次请求有可能会得到
        一个很小的ttl值，需要对比设置的最短ttl时间，按ttl大的进行存储。

    dp_env_init
        初始化dplus-c环境
    dp_env_destroy
        销毁dplus-c环境

    dp_flush_cache(const char *node)
        必要时可调用此函数清除域名的缓存信息。

    dp_getaddrinfo与dp_freeaddrinfo
        调用dp_getaddrinfo进行域名的解析
        调用dp_freeaddrinfo释放内存
        与系统函数getaddrinfo,freeaddrinfo类似
        使用手册: man getaddrinfo

    具体实例，参考demo。
