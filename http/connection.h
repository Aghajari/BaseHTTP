#ifndef BASE_HTTP_CONNECTION_H
#define BASE_HTTP_CONNECTION_H

#include "internal.h"

HttpConnection *create_and_connect_socket(
        HttpRequest *request,
        struct HttpOptions *options
);

int create_url(HttpRequest *request);

int write_connection(
        HttpConnection *connection,
        const void *data,
        size_t len
);

int recv_connection(
        HttpConnection *connection,
        void *buffer,
        size_t len
);

void close_connection(HttpConnection *connection);

char *error_message(HttpConnection *connection);

int error(
        HttpConnection *connection,
        HttpRequest *request,
        const char *error_message,
        int error_code
);

#endif //BASE_HTTP_CONNECTION_H
