#ifndef BASE_HTTP_MODELS_H
#define BASE_HTTP_MODELS_H

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#define HTTP_ERR_HOST (-1)
#define HTTP_ERR_SOCKET (-2)
#define HTTP_ERR_SOCKET_CONNECT (-3)
#define HTTP_ERR_CONN_WRITE (-4)
#define HTTP_ERR_MEMORY (-5)
#define HTTP_ERR_CONN_RECV (-6)
#define HTTP_ERR_INVALID_METHOD (-7)
#define HTTP_ERR_SSL (-8)
#define HTTP_ERR_URL (-9)
#define HTTP_ERR_REDIRECTS (-10)

typedef enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH
} HttpMethod;

typedef struct {
    const char *key;
    const char *value;
} HttpHeader;

typedef struct {
    int statusCode;
    char statusMessage[256];
    HttpHeader *headers;
    int headersCount;
    char *body;
    unsigned int bodyLength;
} HttpResponse;

typedef struct {
    uint16_t port;
    const char *domain;
    const char *path;
    int isHttps;
} HttpUrl;

struct HttpRequest {
    const char *url;
    const char *body;
    unsigned int bodyLength;
    HttpMethod method;
    HttpUrl urlInfo;
    void *tag;
    HttpHeader *headers;
    int headersCount;
    bool followRedirects;
    bool ssl;
    struct timeval receiveTimeout;
    struct timeval sendTimeout;
    struct timeval connectTimeout;

    void (*onError)(
            struct HttpRequest *request,
            const char *error_message,
            int error_code
    );

    void (*onProgress)(
            struct HttpRequest *request,
            unsigned int bytes_read,
            int total_bytes
    );

    void (*onResponse)(
            struct HttpRequest *request,
            HttpResponse *response
    );

    void (*onRedirect)(
            struct HttpRequest *oldRequest,
            struct HttpRequest *newRequest,
            HttpResponse *response
    );

    void (*onStart)(
            struct HttpRequest *request
    );

    void (*onComplete)(
            struct HttpRequest *request
    );
};

typedef struct HttpRequest HttpRequest;

struct HttpOptions {
    unsigned int maxRedirects;
    unsigned int bufferSize;
    bool earlyTerminateRedirects;

    SSL_CTX *(*onCreateSSLCTX)(
            struct HttpRequest *request
    );
};

#endif
