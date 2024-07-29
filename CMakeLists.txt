cmake_minimum_required(VERSION 3.23)
project(base_http)

set(CMAKE_CXX_STANDARD 14)
find_package(OpenSSL REQUIRED)

add_executable(
        base_http
        main.c
        http/models.h
        http/connection.c
        http/connection.h
        http/request.c
        http/response.c
        http/http.c
        http/http.h
)

target_link_libraries(base_http OpenSSL::SSL OpenSSL::Crypto)