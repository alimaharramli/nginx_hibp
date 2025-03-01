#ifndef NGX_HTTP_CRED_ALERT_MODULE_H
#define NGX_HTTP_CRED_ALERT_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t target_url;
    ngx_str_t log_file;
    ngx_str_t hibp_url;
    ngx_str_t username_field;
    ngx_str_t password_field;
    ngx_str_t email_field;
    ngx_str_t uri_filter;
    ngx_uint_t status_filter;
    ngx_flag_t should_log;
    char *username;
    char *email;
    char *hash;
} ngx_http_cred_alert_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    char *json_data;
    ngx_str_t target_url;
} webhook_data_t;

extern ngx_module_t ngx_http_cred_alert_module;

#endif /* NGX_HTTP_CRED_ALERT_MODULE_H */ 