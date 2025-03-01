#ifndef CRED_ALERT_HIBP_H
#define CRED_ALERT_HIBP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <curl/curl.h>
#include "ngx_http_cred_alert_module.h"

// Structure for memory handling
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Function declarations
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
ngx_int_t check_hibp(ngx_http_request_t *r, const char *prefix, const char *suffix);

#endif /* CRED_ALERT_HIBP_H */ 