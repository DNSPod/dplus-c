# dplus-c

## C SDK 不再维护声明

本 SDK 目前已经很久没有进行维护了，大量新功能都未进行支持，目前（截止2024.06.06）也暂无继续更新维护计划。

如果需要在PC端等继续使用 HttpDNS 可以参照[腾讯云官网-移动解析 HTTPDNS API 接入说明](https://cloud.tencent.com/document/product/379/95500)中的 API 最佳实践流程和接口说明，对本SDK进行修改（也欢迎提交pull request），或直接调用 API 使用。



移动端的 SDK 还在继续维护更新中，见：

[IOS SDK](https://github.com/DNSPod/httpdns-sdk-ios)

[Android SDK](https://github.com/DNSPod/httpdns-sdk-android)


## 关于
dplus-c 是 D+ 的 C 语言 SDK。D+ 就是 DNSPod 研发的移动解析服务的专用名称。使用 HTTP 协议向 D+ 服务器的80端口进行请求，代替传统的 DNS 协议向 DNS 服务器的53端口进行请求，绕开了运营商的 Local DNS，从而避免了使用运营商 Local DNS 造成的劫持和跨网问题。

[详情请点击](https://www.dnspod.cn/httpdns)


## dplus-c 模块
| 模块名　  | 功能描述                                                                  |
|-----------|---------------------------------------------------------------------------|
| lruhash.c | 缓存模块, 使用的是LRU算法，当缓存大小超过预设值后，剔除最久未使用的信息。 |
| http.c    | HTTP 模块,发送和接收 HTTP 请求。                                          |
| dns.c     | DNS 模块,发送和接收 DNS 请求。                                            |
| locks.c   | 锁与线程的定义以及跨平台的处理。                                          |
| dplus.c   | D+模块, 包括初始化缓存、配置等，实现类似 getaddrinfo 的功能。             |


## dplus-c的DNS查询流程
1. 修改必要的参数配置。
2. 缓存大小、最小TTL等，如果是企业版还需要设置DES加密ID、KEY等。
3. SDK 初始化。
4. （企业版）对域名进行DES加密得到加密后的字符串。（TODO：批量解析说明）
5. 调用dp_getaddrinfo接口进行查询，使用方法与getaddrinfo完全相同，具体可以查看DEMO或man getaddrinfo。
6. 首先查找缓存中是否存在域名的信息:
7. 如果存在且TTL未过期，直接返回结果, 如果预取TTL过期，则在返回结果的同时会异步进行预取;
8. 如果不存在或ttl过期， 则向d+服务器请求(注意，此处的返回结果直接返回到上层接口，不会进行缓存)
      1. 如果D+服务器未正确返回（返回空，超时等），则使用DNS协议向Public DNS 119.29.29.29进行请求
      2. 如果Public DNS服务器未正确返回（返回空，超时等），则调用系统接口getaddrinfo。

9. 将返回结果中的IP构造填充到struct addrinfo格式的输出参数res中。
10. 将返回结果进行缓存，如果得到的TTL小于设置的最小TTL，则按照最小TTL进行缓存和计算预取TTL。
11. 遍历返回的res结构，获取所有解析结果。
12. （企业版）对解析结果进行解密得到最终的IP。
13. 选择合适的IP进行实际的业务请求。


## API 使用说明
**1. 在初始化之前，可以修改配置，初始化之后将不能修改。**
```
void dp_set_cache_mem(size_t maxmem)
```
设置缓存的大小为maxmem， 单位为字节(默认是4M)。
```
void dp_set_ttl(int ttl)
```
设置最短ttl时间，默认90s。
缓存中存储了域名的ttl和预取ttl；当预取ttl到期时，会异步去d+重新请求。
请求完成后再进行缓存，而d+服务器也会进行预取和缓存，
所以此次请求有可能会得到一个很小的ttl值，需要对比设置的最短ttl时间，按ttl大的进行存储。

```
void dp_set_des_id_key(uint32_t id, const char *key)
```
设置DES加密id, KEY。企业版才需要设置。

**2. SDK初始化**
```
void dp_env_init()
```
初始化 dplus-c 环境
```
void dp_env_destroy()
```
销毁 dplus-c 环境

**3. 获取域名IP**
```
int dp_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
```
```
void dp_freeaddrinfo(struct addrinfo *res)
```
调用 dp_getaddrinfo 进行域名的解析, 调用 dp_freeaddrinfo 释放内存。
与系统函数getaddrinfo,freeaddrinfo类似。
使用手册: man getaddrinfo

**4. 缓存操作**
```
void dp_flush_cache(const char *node)
```
必要时可调用此函数清除域名的缓存信息。
```
void dp_cache_status()
```
打印缓存信息。

具体示例，参考 DEMO 目录。
