#ifndef BASE_HTTP_HTTP_H
#define BASE_HTTP_HTTP_H

#include "models.h"

extern struct HttpOptions HttpOptions;

HttpResponse *http_request(HttpRequest *request);

void http_free_response(HttpResponse *response);

int http_save_response_as_file(HttpResponse *response, const char *file_name);

#endif
