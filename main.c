#include <stdio.h>
#include "http/http.h"

void start_callback(HttpRequest *request) {
    printf("Request started %s\n", request->url);
}

void complete_callback(HttpRequest *request) {
    printf("Request completed %s\n", request->url);
}

void error_callback(HttpRequest *request, const char *error_message, int error_code) {
    printf("Error %s (%d): %s\n", request->url, error_code, error_message);
}

void response_callback(HttpRequest *request, HttpResponse *response) {
    printf("\n%d %s\n", response->statusCode, response->statusMessage);
    printf("Headers:\n");
    for (int i = 0; i < response->headersCount; i++) {
        printf("%s: %s\n", response->headers[i].key, response->headers[i].value);
    }
    printf("\nBody:\n%s\n", response->body);
    http_free_response(response);
}

void redirect_callback(HttpRequest *oldRequest, HttpRequest *newRequest, HttpResponse *response) {
    printf("Request redirected from %s to %s", oldRequest->url, newRequest->url);
}

int main(void) {
    HttpHeader headers[] = {
            {"Connection", "close"},
            {"User-Agent", "Test"}
    };

    HttpRequest request = {
            .method = GET,
            .url = "google.com",
            .body = NULL,
            .bodyLength = 0,
            .headers = headers,
            .headersCount = sizeof(headers) / sizeof(headers[0]),
            .followRedirects = true,
            .ssl = true,
            .sslMethod = NULL,
            .receiveTimeout = {.tv_sec = 1},
            .sendTimeout = {.tv_sec = 1},
            .connectTimeout = {.tv_sec = 2},
            .onStart = start_callback,
            .onComplete = complete_callback,
            .onError = error_callback,
            .onRedirect = redirect_callback,
            .onResponse = response_callback,
    };

    http_request(&request);
    return 0;
}
