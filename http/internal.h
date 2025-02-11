#ifndef BASE_HTTP_INTERNAL_H
#define BASE_HTTP_INTERNAL_H

#include "models.h"

typedef struct {
    int socket;
    SSL *ssl;
    SSL_CTX *ctx;
} HttpConnection;

int send_http_request(
        HttpConnection *connection,
        HttpRequest *request
);

int read_http_response(
        HttpConnection *connection,
        HttpResponse *response,
        HttpRequest *request,
        struct HttpOptions *options
);

char *http_response_get_header(
        HttpResponse *response,
        char *key
);

int has_redirected(HttpResponse *response);

#endif //BASE_HTTP_INTERNAL_H
