#include <stdio.h>
#include <string.h>
#include "internal.h"
#include "connection.h"

const char *get_http_method_string(HttpMethod method) {
    switch (method) {
        case GET:
            return "GET";
        case POST:
            return "POST";
        case PUT:
            return "PUT";
        case DELETE:
            return "DELETE";
        case HEAD:
            return "HEAD";
        case OPTIONS:
            return "OPTIONS";
        case PATCH:
            return "PATCH";
        default:
            return NULL;
    }
}

int send_http_request(HttpConnection *connection, HttpRequest *request) {
    const char *method = get_http_method_string(request->method);
    if (method == NULL) {
        return error(connection, request, "HTTP Method is invalid!", HTTP_ERR_INVALID_METHOD);
    }

    int hasBody = request->body != NULL && request->bodyLength > 0;
    unsigned long send_buffer_size = 22
                                     + strlen(method)
                                     + strlen(request->urlInfo.domain)
                                     + (request->urlInfo.path == NULL ? 0 : strlen(request->urlInfo.path));
    for (int i = 0; i < request->headersCount; i++) {
        send_buffer_size += 3
                            + strlen(request->headers[i].key)
                            + strlen(request->headers[i].value);
    }
    if (hasBody) {
        send_buffer_size += 30;
    }


    char send_data[send_buffer_size];
    int offset;

    char *path_start = "";
    if (request->urlInfo.path == NULL || strncmp("/", request->urlInfo.path, 1) != 0) {
        path_start = "/";
    }

    offset = snprintf(
            send_data,
            sizeof(send_data),
            "%s %s%s HTTP/1.1\n",
            method,
            path_start,
            request->urlInfo.path == NULL ? "" : request->urlInfo.path
    );
    offset += snprintf(
            send_data + offset,
            sizeof(send_data) - offset,
            "Host: %s\n",
            request->urlInfo.domain
    );
    if (hasBody) {
        offset += snprintf(
                send_data + offset,
                sizeof(send_data) - offset,
                "Content-Length: %d\n",
                request->bodyLength
        );
    }

    for (int i = 0; i < request->headersCount; i++) {
        offset += snprintf(
                send_data + offset,
                sizeof(send_data) - offset,
                "%s: %s\n",
                request->headers[i].key,
                request->headers[i].value
        );
    }
    offset += snprintf(send_data + offset, sizeof(send_data) - offset, "\n");

    unsigned int total_sent = 0;
    unsigned int to_send = offset;

    while (total_sent < to_send) {
        int bytes_sent = write_connection(connection, send_data + total_sent, to_send - total_sent);
        if (bytes_sent <= 0) {
            return error(connection, request, error_message(connection), HTTP_ERR_CONN_WRITE);
        }
        total_sent += bytes_sent;
    }

    if (!hasBody) {
        return 0;
    }

    total_sent = 0;
    to_send = request->bodyLength;
    while (total_sent < to_send) {
        int bytes_sent = write_connection(connection, request->body + total_sent, to_send - total_sent);
        if (bytes_sent <= 0) {
            return error(connection, request, error_message(connection), HTTP_ERR_CONN_WRITE);
        }
        total_sent += bytes_sent;
    }
    return 0;
}
