#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "internal.h"
#include "connection.h"

#define PARSING_STATUS 0
#define PARSING_HEADERS 1
#define PARSING_BODY 2

void parse_status_line(char *line, HttpResponse *response) {
    sscanf(
            line,
            "HTTP/1.1 %d %[^\r\n]",
            &response->statusCode,
            response->statusMessage
    );
}

void parse_header_line(char *line, HttpHeader *header) {
    char *colon = strchr(line, ':');
    if (colon) {
        *colon = '\0';
        header->key = strdup(line);
        header->value = strdup(colon + 2);
    }
}

int read_http_response(HttpConnection *connection, HttpResponse *response, HttpRequest *request) {
    unsigned int recv_buffer_size = 4096;
    char recv_data[recv_buffer_size + 1];
    char *line_feed_data = NULL;
    unsigned int line_feed_data_size = 0;

    unsigned int total_bytes = 0, data_buffer_size = recv_buffer_size;
    int bytes_received;
    response->body = NULL;
    response->bodyLength = 0;

    unsigned int parser_step = 0;

    unsigned int max_headers = 10;
    response->headersCount = 0;
    response->headers = malloc(sizeof(HttpResponse) * max_headers);

    if (!response->headers) {
        return error(connection, request, "Failed to malloc headers", HTTP_ERR_MEMORY);
    }

    while ((bytes_received = recv_connection(connection, recv_data, recv_buffer_size)) > 0) {
        if (parser_step != PARSING_BODY) {
            recv_data[bytes_received] = '\0';
            char *newline_ptr = strchr(recv_data, '\n');
            if (newline_ptr == NULL) {
                unsigned int old_size = line_feed_data_size;
                line_feed_data_size += bytes_received;
                if (line_feed_data == NULL) {
                    line_feed_data = malloc(line_feed_data_size);
                } else {
                    line_feed_data = realloc(line_feed_data, line_feed_data_size);
                }
                if (!line_feed_data) {
                    return error(connection, request, "Failed to malloc response", HTTP_ERR_MEMORY);
                }
                memcpy(line_feed_data + old_size, recv_data, bytes_received);
            } else {
                char *data = recv_data;
                int this_recv_read = 0;
                while (newline_ptr != NULL) {
                    this_recv_read += (int) (newline_ptr - data) + 1;
                    *newline_ptr = '\0';
                    char *line_str = data;
                    if (line_feed_data != NULL) {
                        unsigned int old_size = line_feed_data_size;
                        unsigned int line_len = strlen(data);
                        line_feed_data_size += line_len;
                        line_feed_data = realloc(line_feed_data, line_feed_data_size + 1);
                        if (!line_feed_data) {
                            return error(connection, request, "Failed to realloc response", HTTP_ERR_MEMORY);
                        }
                        memcpy(line_feed_data + old_size, data, line_len);
                        line_feed_data[line_feed_data_size] = '\0';
                        line_str = line_feed_data;
                    }

                    if (parser_step == PARSING_STATUS) {
                        parse_status_line(line_str, response);
                        parser_step = PARSING_HEADERS;
                    } else {
                        if ((line_str[0] == '\r' && line_str[1] == '\0') || line_str[0] == '\0') {
                            parser_step = PARSING_BODY;
                        } else {
                            if (max_headers <= response->headersCount) {
                                max_headers *= 2;
                                response->headers = realloc(
                                        response->headers,
                                        sizeof(HttpResponse) * max_headers
                                );
                                if (!response->headers) {
                                    if (line_feed_data != NULL) {
                                        free(line_feed_data);
                                    }
                                    return error(connection, request, "Failed to realloc headers", HTTP_ERR_MEMORY);
                                }
                            }

                            parse_header_line(line_str, &response->headers[response->headersCount]);
                            response->headersCount++;
                        }
                    }

                    if (line_feed_data != NULL) {
                        free(line_feed_data);
                        line_feed_data = NULL;
                        line_feed_data_size = 0;
                    }

                    data = newline_ptr + 1;
                    if (parser_step == PARSING_BODY || data > recv_data + recv_buffer_size) {
                        break;
                    } else {
                        newline_ptr = strchr(data, '\n');
                    }
                }
                if (data < recv_data + recv_buffer_size) {
                    line_feed_data_size = bytes_received - this_recv_read;
                    line_feed_data = malloc(line_feed_data_size);
                    if (!line_feed_data) {
                        return error(connection, request, "Failed to malloc response", HTTP_ERR_MEMORY);
                    }
                    memcpy(line_feed_data, data, line_feed_data_size);
                }
            }
        } else {
            if (response->body == NULL) {
                data_buffer_size += line_feed_data_size;
                response->body = malloc(data_buffer_size);
                if (!response->body) {
                    if (line_feed_data != NULL) {
                        free(line_feed_data);
                    }
                    return error(connection, request, "Failed to malloc body", HTTP_ERR_MEMORY);
                }
                if (line_feed_data != NULL) {
                    memcpy(response->body, line_feed_data, line_feed_data_size);
                    total_bytes += line_feed_data_size;
                    free(line_feed_data);
                    line_feed_data = NULL;
                    line_feed_data_size = 0;
                }
            } else if (data_buffer_size < total_bytes + bytes_received) {
                data_buffer_size += recv_buffer_size;
                response->body = realloc(response->body, data_buffer_size);

                if (!response->body) {
                    if (line_feed_data != NULL) {
                        free(line_feed_data);
                    }
                    return error(connection, request, "Failed to realloc body", HTTP_ERR_MEMORY);
                }
            }

            memcpy(response->body + total_bytes, recv_data, bytes_received);
            total_bytes += bytes_received;
        }
    }
    if (bytes_received != 0) {
        return error(connection, request, error_message(connection), HTTP_ERR_CONN_RECV);
    }

    if (response->body == NULL && line_feed_data != NULL) {
        response->body = malloc(line_feed_data_size);
        if (!response->body) {
            free(line_feed_data);
            return error(connection, request, "Failed to malloc body", HTTP_ERR_MEMORY);
        }
        memcpy(response->body, line_feed_data, line_feed_data_size);
        total_bytes += line_feed_data_size;
        free(line_feed_data);
    }

    response->bodyLength = total_bytes;
    close_connection(connection);
    return 0;
}

void http_free_response(HttpResponse *response) {
    if (response == NULL) return;

    for (int i = 0; i < response->headersCount; i++) {
        free((void *) response->headers[i].key);
        free((void *) response->headers[i].value);
    }

    free(response->headers);
    free(response->body);
    free(response);
}

char *http_response_get_header(HttpResponse *response, char *key) {
    for (int i = 0; i < response->headersCount; ++i) {
        if (strcasecmp(response->headers[i].key, key) == 0) {
            return strdup(response->headers[i].value);
        }
    }
    return NULL;
}

int http_save_response_as_file(HttpResponse *response, const char *file_name) {
    FILE *file = fopen(file_name, "wb");
    if (!file) {
        return -1;
    }

    fwrite(response->body, 1, response->bodyLength, file);
    fclose(file);
    return 0;
}