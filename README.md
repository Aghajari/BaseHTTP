# BaseHTTP
 
A simple C-based HTTP client designed to demonstrate the basics of sending and receiving HTTP requests and handling responses. It supports various HTTP methods such as GET and POST, and includes features for setting timeouts, handling binary data, and processing HTTP headers. This project is intended for educational purposes to help understand HTTP communication and socket programming in C. It demonstrates the fundamental concepts required to build a basic HTTP client from scratch.

You can read about the HTTP/1.1 protocol in the RFC document [here](https://www.w3.org/Protocols/rfc2616/rfc2616.html).

The `read_http_response` function is designed to handle the complete reception of an HTTP response from the server in a single continuous process. It reads the response status line, headers, and body, managing chunks of data as they are received from the server. This function ensures that it parses the status line and headers correctly before proceeding to read the response body. By handling data in chunks, it efficiently manages network communication and ensures that the entire response is processed seamlessly, regardless of how the data is fragmented during transmission.

## Features
- **Send HTTP requests**: Easily send GET, POST, HEAD and other requests to interact with web servers.
- **SSL/TLS Support**: Secure HTTP communication using SSL/TLS for HTTPS requests.
- **Handle binary data in request bodies**: Send binary data, including null characters, in the body of HTTP requests.
- **Set connection and read timeouts**: Configure timeouts for connecting to servers and receiving data.
- **Process and handle HTTP response headers**: Parse and utilize headers from HTTP responses.
- **Follow Redirects**: Automatically handle HTTP redirects and follow them to the new location.

## Usage
Here is an example of how to use the BaseHTTP client, including setting callbacks for various events:

```c
#include <stdio.h>
#include "http/http.h"

void start_callback(HttpRequest *request) {
    printf("Request started %s\n", request->url);
}

void complete_callback(HttpRequest *request) {
    printf("Request completed %s\n", request->url);
}

void error_callback(HttpRequest *request, const char *error_message, int error_code) {
    printf("Error: %s\n", error_message);
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
    printf("Request redirected from %s to %s\n", oldRequest->url, newRequest->url);
}

void progress_callback(HttpRequest *request, unsigned int bytes_read, int content_length) {
    if (content_length > 0) {
        printf("Progress: %lf\n", bytes_read * 100.0 / content_length);
    }
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
            .headers = headers,
            .headersCount = sizeof(headers) / sizeof(headers[0]),
            .followRedirects = true,
            .ssl = true,
            .receiveTimeout = {.tv_sec = 1},
            .sendTimeout = {.tv_sec = 1},
            .connectTimeout = {.tv_sec = 2},
            .onStart = start_callback,
            .onComplete = complete_callback,
            .onError = error_callback,
            .onRedirect = redirect_callback,
            .onResponse = response_callback,
            .onProgress = progress_callback,
    };

    http_request(&request);
    return 0;
}

```

## Author
Amir Hossein Aghajari

License
=======

    Copyright 2024 Amir Hossein Aghajari
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

<br>
<div align="center">
  <img width="64" alt="LCoders | AmirHosseinAghajari" src="https://user-images.githubusercontent.com/30867537/90538314-a0a79200-e193-11ea-8d90-0a3576e28a18.png">
  <br><a>Amir Hossein Aghajari</a> • <a href="mailto:amirhossein.aghajari.82@gmail.com">Email</a> • <a href="https://github.com/Aghajari">GitHub</a>
</div>
