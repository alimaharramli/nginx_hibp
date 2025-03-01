#ifndef CRED_ALERT_LOG_H
#define CRED_ALERT_LOG_H

#include <ngx_http.h>
#include <jansson.h>
#include "ngx_http_cred_alert_module.h"

// Function declarations
void write_to_log(ngx_http_request_t *r, const char *username, const char *email, 
                 const char *hash, const char *uri, const char *method, 
                 ngx_uint_t status, const char *host);
void ngx_log_json(ngx_log_t *log, json_t *root);

#endif /* CRED_ALERT_LOG_H */ 