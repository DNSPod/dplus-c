#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include "dplus.h"

#define CHUNK_SIZE 256
#define MAXLEN_VALUE 120

#define HTTP_OK 200
#define HTTP_DEFAULT_TIMEOUT 5

#define MIN(x,y) (((x)<(y))?(x):(y))

static int wait_event(int sockfd, struct timeval *timeout, int read, int write)
{
    int ret;
    fd_set *readset, *writeset;
    fd_set set;

    FD_ZERO(&set);
    FD_SET(sockfd, &set);

    readset  = read ? &set : NULL;
    writeset = write ? &set : NULL;

    ret = select(FD_SETSIZE, readset, writeset, NULL, timeout);
    return (ret <= 0 || !FD_ISSET(sockfd, &set)) ? -1 : 0;
}

static int wait_readable(int sockfd, struct timeval timeout) {
    return wait_event(sockfd, &timeout, 1, 0);
}

static int wait_writable(int sockfd, struct timeval timeout) {
    return wait_event(sockfd, &timeout, 0, 1);
}

static int send_all(int sockfd, char *buf, size_t length)
{
    int bytes_sent = 0;
    struct timeval timeout = {HTTP_DEFAULT_TIMEOUT, 0};
    while (bytes_sent < length) {
        int ret = wait_writable(sockfd, timeout);
        if (ret != 0)
            return -1;

        ret = send(sockfd, buf + bytes_sent, length - bytes_sent, 0);
        if (ret > 0) {
            bytes_sent += ret;
            continue;
        } else if (ret == 0) {
            return bytes_sent;
        } else {
            return -1;
        }
    }
    return bytes_sent;
}

static int receive_all(int sockfd, char *buf, size_t length) {
    int bytes_received = 0;
    struct timeval timeout = {HTTP_DEFAULT_TIMEOUT, 0};

    while (bytes_received < length) {
        int ret;
        ret = wait_readable(sockfd, timeout);
        if (ret != 0)
            return -1;

        ret = recv(sockfd, buf + bytes_received, length - bytes_received, 0);
        if (ret > 0) {
            bytes_received += ret;
        } else if (ret == 0) {
            return bytes_received;
        } else {
            return -1;
        }
    }
    return bytes_received;
}

int make_connection(char *serv_ip, int port)
{
    int sockfd, ret;
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(serv_ip);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "create socket error");
        return -1;
    }

    ret = connect(sockfd, (struct sockaddr *)&serv_addr,
        sizeof(struct sockaddr));
    if(ret < 0){
        fprintf(stderr, "connect socket error");
        return -1;
    }

    return sockfd;
}

int make_request(int sockfd, char *hostname, char *request_path)
{
    char buf[CHUNK_SIZE];
    snprintf(buf, sizeof(buf),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
        request_path, hostname);

    return send_all(sockfd, buf, strlen(buf));
}

struct buffer {
    char *str;
    size_t size;
    size_t pos;
};

static void buffer_init(struct buffer *b, char *buf, size_t len)
{
    b->str = buf;
    b->size = len;
    b->pos = 0;
    b->str[b->pos] = '\0';
}

static int buffer_write(struct buffer *b, const char *buf, size_t len)
{
    size_t write_len = MIN(len, b->size - 1 - b->pos);
    memcpy(b->str + b->pos, buf, write_len);
    b->pos += write_len;
    b->str[b->pos] = '\0';
    return 1;
}

int fetch_response(int sockfd, char *http_data, size_t http_data_len)
{
    char buf[CHUNK_SIZE];
    char *crlf;
    int bytes_received, content_length = 0;
    int crlf_pos = 0, http_response_code = 0;
    char key[32];
    char value[MAXLEN_VALUE];
    int ret;
    struct buffer http_data_buf;

    bytes_received = receive_all(sockfd, buf, CHUNK_SIZE - 1);
    if (bytes_received <= 0) {
        return -1;
    }
    buf[bytes_received] = '\0';
    //printf("%s\n", buf);

    crlf = strstr(buf, "\r\n");
    if(crlf == NULL) {
        return -1;
    }

    crlf_pos = crlf - buf;
    buf[crlf_pos] = '\0';

    //parse HTTP response
    if(sscanf(buf, "HTTP/%*d.%*d %d %*[^\r\n]", &http_response_code) != 1 ) {
        fprintf(stderr, "not a correct HTTP answer : {%s}\n", buf);
        return -1;
    }
    if (http_response_code != HTTP_OK) {
        fprintf(stderr, "response code %d\n", http_response_code);
        return -1;
    }

    memmove(buf, &buf[crlf_pos + 2], bytes_received-(crlf_pos+2)+1);
    bytes_received -= (crlf_pos + 2);

    //get headers
    while(1) {
        crlf = strstr(buf, "\r\n");
        if(crlf == NULL) {
            if(bytes_received < CHUNK_SIZE - 1) {
                ret = receive_all(sockfd, buf + bytes_received,
                    CHUNK_SIZE - bytes_received - 1);
                if (ret <= 0) {
                    return -1;
                }
                bytes_received += ret;
                buf[bytes_received] = '\0';
                continue;
            } else {
                return -1;
            }
        }

        crlf_pos = crlf - buf;
        if(crlf_pos == 0) {
            memmove(buf, &buf[2], bytes_received - 2 + 1);
            bytes_received -= 2;
            break;
        }

        buf[crlf_pos] = '\0';

        key[31] = '\0';
        value[MAXLEN_VALUE - 1] = '\0';

        ret = sscanf(buf, "%31[^:]: %160[^\r\n]", key, value);
        if (ret == 2) {
            //printf("Read header : %s: %s\n", key, value);
            if(!strcasecmp(key, "Content-Length")) {
                sscanf(value, "%d", &content_length);
            }

            memmove(buf, &buf[crlf_pos+2], bytes_received-(crlf_pos+2)+1);
            bytes_received -= (crlf_pos + 2);
        } else {
            fprintf(stderr, "could not parse header");
            return -1;
        }
    }

    if (content_length <= 0) {
        fprintf(stderr, "Content-Length not found\n");
        return -1;
    }

    //receive data
    buffer_init(&http_data_buf, http_data, http_data_len);
    do {
        //printf("buffer write %d,%d:%s\n", bytes_received, content_length, buf);
        buffer_write(&http_data_buf, buf, MIN(bytes_received, content_length));
        if(bytes_received > content_length) {
            memmove(buf, &buf[content_length], bytes_received - content_length);
            bytes_received -= content_length;
            content_length = 0;
        } else {
            content_length -= bytes_received;
        }

        if(content_length) {
            ret = receive_all(sockfd, buf, CHUNK_SIZE - bytes_received - 1);
            if (ret <= 0) {
                return -1;
            }
            bytes_received = ret;
            buf[bytes_received] = '\0';
        }
    } while(content_length);

    return 0;
}
