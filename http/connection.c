#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include "connection.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>

int create_url(HttpRequest *request) {
    if (request->url == NULL) {
        if (request->onError != NULL) {
            request->onError(request, "url can not be null!", HTTP_ERR_URL);
        }
        return -1;
    }

    const char *url_start;
    const char *path_start;
    const char *port_start;
    size_t domain_length;
    size_t path_length;

    char *domain = NULL;
    char *path = NULL;
    request->urlInfo.port = 80;
    request->urlInfo.isHttps = 0;

    if (strncasecmp(request->url, "http://", 7) == 0) {
        url_start = request->url + 7;
    } else if (strncasecmp(request->url, "https://", 8) == 0) {
        url_start = request->url + 8;
        request->urlInfo.port = 443;
        request->urlInfo.isHttps = 1;
    } else {
        url_start = request->url;
    }

    path_start = strchr(url_start, '/');
    if (path_start == NULL) {
        domain_length = strlen(url_start);
        path_length = 0;
    } else {
        domain_length = path_start - url_start;
        path_length = strlen(path_start);
    }

    port_start = strchr(url_start, ':');
    if (port_start != NULL && (path_start == NULL || port_start < path_start)) {
        domain_length = port_start - url_start;
        char *port_end;
        long port_num = strtol(port_start + 1, &port_end, 10);
        if (*port_end != '\0' && *port_end != '/') {
            if (request->onError != NULL) {
                request->onError(request, "Invalid port number!", HTTP_ERR_URL);
            }
            return -1;
        }
        request->urlInfo.port = port_num;
    }

    domain = (char *) malloc(domain_length + 1);
    if (domain == NULL) {
        if (request->onError != NULL) {
            request->onError(request, "Failed to malloc domain!", HTTP_ERR_URL);
        }
        return -1;
    }
    strncpy(domain, url_start, domain_length);
    domain[domain_length] = '\0';

    if (path_length > 0) {
        path = (char *) malloc(path_length + 1);
        if (path == NULL) {
            free(domain);
            if (request->onError != NULL) {
                request->onError(request, "Failed to malloc path!", HTTP_ERR_URL);
            }
            return -1;
        }
        strncpy(path, path_start, path_length);
        path[path_length] = '\0';
    } else {
        path = NULL;
    }

    request->urlInfo.domain = domain;
    request->urlInfo.path = path;
    return 0;
}

HttpConnection *create_ssl(int sock, HttpRequest *request) {
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *sslMethod = request->sslMethod;
    if (sslMethod == NULL) {
        sslMethod = TLS_client_method();
    }

    ctx = SSL_CTX_new(sslMethod);
    if (!ctx) {
        if (request->onError) {
            request->onError(request, "Unable to create SSL context", HTTP_ERR_SSL);
        }
        close(sock);
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        if (request->onError) {
            request->onError(request, "Unable to create SSL connection state", HTTP_ERR_SSL);
        }
        close(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        if (request->onError) {
            request->onError(request, "SSL handshake failed", HTTP_ERR_SSL);
        }
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }

    HttpConnection *conn = malloc(sizeof(HttpConnection));
    if (!conn) {
        if (request->onError != NULL) {
            request->onError(request, "Failed to malloc HttpConnection", HTTP_ERR_MEMORY);
        }
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return NULL;
    }
    conn->ssl = ssl;
    conn->ctx = ctx;
    conn->socket = sock;
    return conn;
}

int connect_socket(
        HttpRequest *request,
        int sock,
        struct sockaddr *addr,
        socklen_t addrlen
) {
    if (request->connectTimeout.tv_sec == 0 && request->connectTimeout.tv_usec == 0) {
        return connect(sock, addr, addrlen);
    }

    int result;
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    result = connect(sock, addr, addrlen);
    if (result < 0) {
        if (errno == EINPROGRESS) {
            fd_set wait_set;
            struct timeval timeout = request->connectTimeout;

            FD_ZERO(&wait_set);
            FD_SET(sock, &wait_set);

            result = select(sock + 1, NULL, &wait_set, NULL, &timeout);
            if (result > 0) {
                int so_error;
                socklen_t len = sizeof(so_error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0) {
                    result = 0;
                } else {
                    errno = so_error;
                    result = -1;
                }
            } else if (result == 0) {
                errno = ETIMEDOUT;
                result = -1;
            } else {
                result = -1;
            }
        } else {
            result = -1;
        }
    }

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        return -1;
    }
    return result;
}

HttpConnection *create_and_connect_socket(HttpRequest *request) {
    int sock;
    struct sockaddr_in server_addr;
    struct hostent *he;

    he = gethostbyname(request->urlInfo.domain);
    if (he == NULL) {
        if (request->onError != NULL) {
            request->onError(request, hstrerror(h_errno), HTTP_ERR_HOST);
        }
        return NULL;
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        if (request->onError != NULL) {
            request->onError(request, strerror(errno), HTTP_ERR_SOCKET);
        }
        return NULL;
    }

    if ((request->receiveTimeout.tv_sec != 0 || request->receiveTimeout.tv_usec != 0) &&
        setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (const char *) &request->receiveTimeout,
                sizeof(struct timeval)
        ) < 0) {
        if (request->onError != NULL) {
            request->onError(request, strerror(errno), HTTP_ERR_SOCKET);
        }
        close(sock);
        return NULL;
    }

    if ((request->sendTimeout.tv_sec != 0 || request->sendTimeout.tv_usec != 0) &&
        setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVTIMEO,
                (const char *) &request->sendTimeout,
                sizeof(struct timeval)
        ) < 0) {
        if (request->onError != NULL) {
            request->onError(request, strerror(errno), HTTP_ERR_SOCKET);
        }
        close(sock);
        return NULL;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(request->urlInfo.port);
    server_addr.sin_addr = *((struct in_addr *) he->h_addr);
    bzero(&(server_addr.sin_zero), 8);

    if (connect_socket(request, sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
        if (request->onError != NULL) {
            request->onError(request, strerror(errno), HTTP_ERR_SOCKET_CONNECT);
        }
        close(sock);
        return NULL;
    }

    if (request->ssl && request->urlInfo.isHttps) {
        return create_ssl(sock, request);
    } else {
        HttpConnection *conn = malloc(sizeof(HttpConnection));
        if (!conn) {
            if (request->onError != NULL) {
                request->onError(request, "Failed to malloc HttpConnection", HTTP_ERR_MEMORY);
            }
            close(sock);
            return NULL;
        }
        conn->ssl = NULL;
        conn->ctx = NULL;
        conn->socket = sock;
        return conn;
    }
}

char *err_connection(HttpConnection *connection) {
    if (connection->ssl != NULL) {
        unsigned long err_code = ERR_get_error();
        if (err_code != 0) {
            return ERR_error_string(err_code, NULL);
        } else {
            return "SSL failed";
        }
    } else {
        return strerror(errno);
    }
}

int write_connection(HttpConnection *connection, const void *data, size_t len) {
    if (connection->ssl != NULL) {
        return SSL_write(connection->ssl, data, (int) len);
    } else {
        return (int) send(connection->socket, data, len, 0);
    }
}

int recv_connection(HttpConnection *connection, void *buffer, size_t len) {
    if (connection->ssl != NULL) {
        return SSL_read(connection->ssl, buffer, (int) len);
    } else {
        return (int) recv(connection->socket, buffer, len, 0);
    }
}

void close_connection(HttpConnection *connection) {
    if (connection->ssl != NULL) {
        SSL_free(connection->ssl);
        connection->ssl = NULL;
    }
    close(connection->socket);
    if (connection->ctx != NULL) {
        SSL_CTX_free(connection->ctx);
        connection->ctx = NULL;
        EVP_cleanup();
    }
    free(connection);
}