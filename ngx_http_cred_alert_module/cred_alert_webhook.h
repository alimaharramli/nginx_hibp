#ifndef CRED_ALERT_WEBHOOK_H
#define CRED_ALERT_WEBHOOK_H

#include <ngx_http.h>
#include <jansson.h>
#include <curl/curl.h>

// Function declarations
void send_data_async(ngx_http_request_t *r, const char *json_data);

#endif /* CRED_ALERT_WEBHOOK_H */ 