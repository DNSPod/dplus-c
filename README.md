# dplus-c

## 关于
dplus-c 是d+的c语言sdk。D+就是DNSPod研发的移动解析服务的专用名称。使用HTTP协议向D+服务器的80端口进行请求，代替传统的DNS协议向DNS服务器的53端口进行请求，绕开了运营商的Local DNS，从而避免了使用运营商Local DNS造成的劫持和跨网问题。
[详情请点击](https://www.dnspod.cn/httpdns)

## dplus-c模块
    lruhash.c: 缓存模块, 使用的是LRU算法，当缓存大小超过预设值后，剔除最久未使用的信息。
    http.c: http模块,发送和接收http请求。
    dns.c: dns模块,发送和接受dns请求。
    locks.c: 锁与线程的定义以及跨平台的处理。
    dplus.c: D+模块, 包括初始化缓存、配置等，实现类似getaddrinfo的功能。

## dplus-c的DNS查询流程
    1. 修改必要的参数配置。
        1.1 缓存大小、最小TTL等，如果是企业版还需要设置DES加密ID、KEY等。
    2. SDK初始化。
    3. （企业版）对域名进行DES加密得到加密后的字符串。（TODO：批量解析说明）
    4. 调用dp_getaddrinfo接口进行查询，使用方法与getaddrinfo完全相同，具体可以查看DEMO或man getaddrinfo。
        4.1 首先查找缓存中是否存在域名的信息:
        4.2 如果存在且TTL未过期，直接返回结果, 如果预取TTL过期，则在返回结果的同时会异步进行预取;
        4.3 如果不存在或ttl过期， 则向d+服务器请求(注意，此处的返回结果直接返回到上层接口，不会进行缓存)
            4.3.1 如果D+服务器未正确返回（返回空，超时等），则使用DNS协议向Public DNS 119.29.29.29进行请求
            4.3.2 如果Public DNS服务器未正确返回（返回空，超时等），则调用系统接口getaddrinfo。
        （TODO：IP测速，筛选最优ip进行排序返回）
        4.4 将返回结果中的IP构造填充到struct addrinfo格式的输出参数res中。
        4.5 将返回结果进行缓存，如果得到的TTL小于设置的最小TTL，则按照最小TTL进行缓存和计算预取TTL。
    5. 遍历返回的res结构，获取所有解析结果。
    6. （企业版）对解析结果进行解密得到最终的IP。
    7. 选择合适的IP进行实际的业务请求。

## API使用说明
    1.   在初始化之前，可以修改配置，初始化之后将不能修改。
    
    dp_set_cache_mem()
        设置缓存的大小，单位是字节，默认是4M。
        
    dp_set_ttl()
        设置最短ttl时间，默认90s。
        缓存中存储了域名的ttl和预取ttl；当预取ttl到期时，会异步去d+重新请求。
        请求完成后再进行缓存，而d+服务器也会进行预取和缓存，所以此次请求有可能会得到一个很小的ttl值，需要对比设置的最短ttl时间，按ttl大的进行存储。

    dp_set_des_id_key()
        设置DES加密id, KEY。
        企业版才需要设置。

    2. SDK初始化
    dp_env_init()
        初始化dplus-c环境
        
    dp_env_destroy
        销毁dplus-c环境

    3. 获取域名IP
    dp_getaddrinfo与dp_freeaddrinfo
        调用dp_getaddrinfo进行域名的解析
        调用dp_freeaddrinfo释放内存
        与系统函数getaddrinfo,freeaddrinfo类似
        使用手册: man getaddrinfo
        
    4. 缓存操作
    dp_flush_cache(const char *node)
        必要时可调用此函数清除域名的缓存信息。

    dp_cache_status()
        打印缓存信息。

    具体实例，参考DEMO。
