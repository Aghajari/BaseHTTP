#include "http.h"
#include "connection.h"
#include "internal.h"

SSL_CTX *create_default_ssl_ctx(__attribute__((unused)) HttpRequest *request) {
    return SSL_CTX_new(SSLv23_client_method());
}

struct HttpOptions HttpOptions = {
        .maxRedirects = 30,
        .bufferSize = 4096,
        .earlyTerminateRedirects = true,
        .onCreateSSLCTX = create_default_ssl_ctx
};

void free_url_info(HttpRequest *request) {
    if (request->urlInfo.domain != NULL) {
        free((void *) request->urlInfo.domain);
        request->urlInfo.domain = NULL;
    }
    if (request->urlInfo.path != NULL) {
        free((void *) request->urlInfo.path);
        request->urlInfo.path = NULL;
    }
}

void call_on_complete_request(HttpRequest *request) {
    if (request->onComplete != NULL) {
        request->onComplete(request);
    }
    free_url_info(request);
}

HttpRequest clone_redirect_http_request(HttpRequest *request, const char *new_url) {
    HttpRequest clone = {
            .method = request->method,
            .url = new_url,
            .body = request->body,
            .bodyLength = request->bodyLength,
            .headers = request->headers,
            .headersCount = request->headersCount,
            .ssl = request->ssl,
            .followRedirects = request->followRedirects,
            .tag = request->tag,
            .onComplete = request->onComplete,
            .onStart = NULL,
            .onError = request->onError,
            .onRedirect = request->onRedirect,
            .onResponse = request->onResponse,
            .onProgress = request->onProgress,
            .receiveTimeout = request->receiveTimeout,
            .sendTimeout = request->sendTimeout,
            .connectTimeout = request->connectTimeout,
    };
    return clone;
}

HttpResponse *internal_http_request(HttpRequest *request, int redirect_num) {
    request->urlInfo.path = NULL;
    request->urlInfo.domain = NULL;

    if (HttpOptions.maxRedirects > 0 && HttpOptions.maxRedirects < redirect_num) {
        if (request->onError != NULL) {
            request->onError(request, "Reached max redirects.", HTTP_ERR_REDIRECTS);
        }
        call_on_complete_request(request);
        return NULL;
    }

    if (create_url(request) == -1) {
        call_on_complete_request(request);
        return NULL;
    }

    if (request->onStart != NULL) {
        request->onStart(request);
    }

    HttpConnection *connection = create_and_connect_socket(request, &HttpOptions);
    if (connection == NULL) {
        call_on_complete_request(request);
        return NULL;
    }

    if (send_http_request(connection, request) == -1) {
        call_on_complete_request(request);
        return NULL;
    }

    HttpResponse *response = malloc(sizeof(HttpResponse));
    if (!response) {
        call_on_complete_request(request);
        return NULL;
    }

    if (read_http_response(connection, response, request, &HttpOptions) == -1) {
        call_on_complete_request(request);
        free(response);
        return NULL;
    }

    if (request->followRedirects && has_redirected(response)) {
        char *location = http_response_get_header(response, "location");
        if (location == NULL) {
            if (request->onResponse != NULL) {
                request->onResponse(request, response);
            }
            call_on_complete_request(request);
            return response;
        } else {
            free_url_info(request);
        }

        HttpRequest newRequest = clone_redirect_http_request(request, location);

        if (request->onRedirect != NULL) {
            request->onRedirect(request, &newRequest, response);
        }
        http_free_response(response);

        HttpResponse *redirectedResponse = internal_http_request(&newRequest, redirect_num + 1);
        free(location);
        return redirectedResponse;
    } else {
        if (request->onResponse != NULL) {
            request->onResponse(request, response);
        }
        call_on_complete_request(request);
    }
    return response;
}

HttpResponse *http_request(HttpRequest *request) {
    return internal_http_request(request, 0);
}
