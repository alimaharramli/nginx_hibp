#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include "ngx_http_cred_alert_module.h"
#include "cred_alert_hibp.h"
#include "cred_alert_log.h"
#include "cred_alert_webhook.h"

// Forward declarations of internal functions
static ngx_int_t ngx_http_cred_alert_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cred_alert_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_cred_alert_header_filter(ngx_http_request_t *r);
static ngx_int_t process_form_data(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_cred_alert_loc_conf_t *conf);
static ngx_int_t process_json_data(ngx_http_request_t *r, ngx_chain_t *in, ngx_http_cred_alert_loc_conf_t *conf);

static ngx_command_t ngx_http_cred_alert_commands[] = {
    { ngx_string("cred_alert_target_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, target_url),
      NULL },
    { ngx_string("cred_alert_log_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, log_file),
      NULL },
    { ngx_string("cred_alert_hibp_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, hibp_url),
      NULL },
    { ngx_string("cred_alert_username_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, username_field),
      NULL },
    { ngx_string("cred_alert_password_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, password_field),
      NULL },
    { ngx_string("cred_alert_email_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, email_field),
      NULL },
    { ngx_string("cred_alert_uri_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, uri_filter),
      NULL },
    { ngx_string("cred_alert_status_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cred_alert_loc_conf_t, status_filter),
      NULL },
    ngx_null_command
};

static void *ngx_http_cred_alert_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cred_alert_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->target_url.len = 0;
    conf->target_url.data = NULL;
    conf->log_file.len = 0;
    conf->log_file.data = NULL;
    conf->hibp_url.len = 0;
    conf->hibp_url.data = NULL;
    conf->username_field.len = 0;
    conf->username_field.data = NULL;
    conf->password_field.len = 0;
    conf->password_field.data = NULL;
    conf->email_field.len = 0;
    conf->email_field.data = NULL;
    conf->uri_filter.len = 0;
    conf->uri_filter.data = NULL;
    conf->status_filter = (ngx_uint_t) NGX_CONF_UNSET;
    conf->should_log = 0;
    conf->username = NULL;
    conf->email = NULL;
    conf->hash = NULL;
    return conf;
}

static ngx_http_module_t ngx_http_cred_alert_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_cred_alert_init,          /* postconfiguration */
    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */
    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */
    ngx_http_cred_alert_create_loc_conf,  /* create location configuration */
    NULL                               /* merge location configuration */
};

ngx_module_t ngx_http_cred_alert_module = {
    NGX_MODULE_V1,
    &ngx_http_cred_alert_module_ctx,   /* module context */
    ngx_http_cred_alert_commands,      /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_request_body_filter_pt ngx_http_next_request_body_filter;
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_cred_alert_init(ngx_conf_t *cf) {
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_cred_alert_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cred_alert_header_filter;
    
    return NGX_OK;
}

static ngx_int_t ngx_http_cred_alert_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
    if (!r || !r->headers_in.content_type) {
        return ngx_http_next_request_body_filter(r, in);
    }

    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_cred_alert_module);

    ngx_str_t type = r->headers_in.content_type->value;
    if (!type.data) {
        return ngx_http_next_request_body_filter(r, in);
    }

    if (ngx_strnstr(type.data, "application/x-www-form-urlencoded", type.len) != NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing URL-encoded form body");
        process_form_data(r, in, conf);
    } else if (ngx_strnstr(type.data, "application/json", type.len) != NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Processing JSON body");
        process_json_data(r, in, conf);
    }

    return ngx_http_next_request_body_filter(r, in);
}

static ngx_int_t ngx_http_cred_alert_header_filter(ngx_http_request_t *r) {
    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_cred_alert_module);

    if (conf && conf->should_log) {
        // Check URI filter if configured
        if (conf->uri_filter.len > 0) {
            if (r->uri.len != conf->uri_filter.len ||
                ngx_strncmp(r->uri.data, conf->uri_filter.data, conf->uri_filter.len) != 0) {
                return ngx_http_next_header_filter(r);
            }
        }

        // Check status filter if configured
        if (conf->status_filter != (ngx_uint_t) NGX_CONF_UNSET && 
            r->headers_out.status != conf->status_filter) {
            return ngx_http_next_header_filter(r);
        }

        // Clean the URI by removing any query parameters or extra data
        char clean_uri[256] = {0};
        if (r->uri.len > 0) {
            size_t uri_len = r->uri.len;
            if (uri_len > sizeof(clean_uri) - 1) {
                uri_len = sizeof(clean_uri) - 1;
            }
            ngx_memcpy(clean_uri, r->uri.data, uri_len);
            clean_uri[uri_len] = '\0';
            
            // Remove anything after space or control characters
            char *space = strchr(clean_uri, ' ');
            if (space) *space = '\0';
        } else {
            strcpy(clean_uri, "/");
        }

        // Clean the method
        char clean_method[32] = {0};
        if (r->method_name.len > 0) {
            size_t method_len = r->method_name.len;
            if (method_len > sizeof(clean_method) - 1) {
                method_len = sizeof(clean_method) - 1;
            }
            ngx_memcpy(clean_method, r->method_name.data, method_len);
            clean_method[method_len] = '\0';
            
            // Remove anything after space or control characters
            char *space = strchr(clean_method, ' ');
            if (space) *space = '\0';
        } else {
            strcpy(clean_method, "UNKNOWN");
        }

        // Get clean remote IP
        char clean_ip[64] = {0};
        if (r->connection && r->connection->addr_text.len > 0) {
            size_t ip_len = r->connection->addr_text.len;
            if (ip_len > sizeof(clean_ip) - 1) {
                ip_len = sizeof(clean_ip) - 1;
            }
            ngx_memcpy(clean_ip, r->connection->addr_text.data, ip_len);
            clean_ip[ip_len] = '\0';
        } else {
            strcpy(clean_ip, "unknown");
        }

        // Get clean host
        char clean_host[256] = {0};
        if (r->headers_in.host && r->headers_in.host->value.len > 0) {
            size_t host_len = r->headers_in.host->value.len;
            if (host_len > sizeof(clean_host) - 1) {
                host_len = sizeof(clean_host) - 1;
            }
            ngx_memcpy(clean_host, r->headers_in.host->value.data, host_len);
            clean_host[host_len] = '\0';
            
            // Remove anything after space or control characters
            char *space = strchr(clean_host, ' ');
            if (space) *space = '\0';
        }

        // First log to file
        write_to_log(r, conf->username, conf->email, conf->hash,
                    clean_uri, clean_method, r->headers_out.status, clean_host);

        // Then send webhook if configured
        if (conf->target_url.len > 0) {
            json_t *root = json_object();
            json_object_set_new(root, "password_hash", json_string(conf->hash ? conf->hash : ""));
            if (conf->username) json_object_set_new(root, "username", json_string(conf->username));
            if (conf->email) json_object_set_new(root, "email", json_string(conf->email));
            json_object_set_new(root, "request_uri", json_string(clean_uri));
            json_object_set_new(root, "remote_ip", json_string(clean_ip));
            json_object_set_new(root, "method", json_string(clean_method));
            json_object_set_new(root, "status_code", json_integer(r->headers_out.status));
            json_object_set_new(root, "host", json_string(clean_host[0] ? clean_host : "-"));

            char *json_data = json_dumps(root, 0);
            if (json_data) {
                send_data_async(r, json_data);
                free(json_data);
            }
            json_decref(root);
        }

        // Clean up
        if (conf->username) free(conf->username);
        if (conf->email) free(conf->email);
        if (conf->hash) free(conf->hash);
        conf->should_log = 0;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t process_form_data(ngx_http_request_t *r, ngx_chain_t *in, 
                                 ngx_http_cred_alert_loc_conf_t *conf) {
    ngx_chain_t *cur;
    char *username = NULL, *email = NULL, *password = NULL;
    ngx_int_t rc = NGX_OK;

    for (cur = in; cur; cur = cur->next) {
        if (ngx_buf_in_memory(cur->buf) && cur->buf->pos && cur->buf->last && 
            cur->buf->last > cur->buf->pos) {
            
            size_t size = cur->buf->last - cur->buf->pos;
            char *data = ngx_pnalloc(r->pool, size + 1);
            if (data == NULL) {
                rc = NGX_ERROR;
                goto cleanup;
            }
            ngx_memcpy(data, cur->buf->pos, size);
            data[size] = '\0';

            char *saveptr1;
            char *pair = strtok_r(data, "&", &saveptr1);
            while (pair) {
                char *saveptr2;
                char *key = strtok_r(pair, "=", &saveptr2);
                if (key) {
                    char *value = strtok_r(NULL, "=", &saveptr2);
                    if (value) {
                        // Use custom field names if configured
                        if ((conf->password_field.len == 0 && strcmp(key, "password") == 0) ||
                            (conf->password_field.len > 0 && 
                             strncmp(key, (char *)conf->password_field.data, conf->password_field.len) == 0)) {
                            if (password) free(password);
                            password = strdup(value);
                        } else if ((conf->username_field.len == 0 && strcmp(key, "username") == 0) ||
                                  (conf->username_field.len > 0 && 
                                   strncmp(key, (char *)conf->username_field.data, conf->username_field.len) == 0)) {
                            if (username) free(username);
                            username = strdup(value);
                        } else if ((conf->email_field.len == 0 && strcmp(key, "email") == 0) ||
                                  (conf->email_field.len > 0 && 
                                   strncmp(key, (char *)conf->email_field.data, conf->email_field.len) == 0)) {
                            if (email) free(email);
                            email = strdup(value);
                        }
                    }
                }
                pair = strtok_r(NULL, "&", &saveptr1);
            }
        }
    }

    if (password && (username || email)) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char *)password, strlen(password), hash);
        char hex_hash[SHA_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf(&hex_hash[i * 2], "%02x", hash[i]);
        }

        char prefix[6], suffix[36];
        strncpy(prefix, hex_hash, 5);
        prefix[5] = '\0';
        strcpy(suffix, hex_hash + 5);

        if (check_hibp(r, prefix, suffix)) {
            conf->should_log = 1;
            if (username) conf->username = strdup(username);
            if (email) conf->email = strdup(email);
            conf->hash = strdup(hex_hash);
        }
    }

cleanup:
    if (username) free(username);
    if (email) free(email);
    if (password) free(password);
    return rc;
}

static ngx_int_t process_json_data(ngx_http_request_t *r, ngx_chain_t *in,
                                 ngx_http_cred_alert_loc_conf_t *conf) {
    ngx_chain_t *cur;
    char *username = NULL, *email = NULL, *password = NULL;
    ngx_int_t rc = NGX_OK;

    for (cur = in; cur; cur = cur->next) {
        if (ngx_buf_in_memory(cur->buf)) {
            json_error_t error;
            json_t *root = json_loadb((const char *)cur->buf->pos, ngx_buf_size(cur->buf), 0, &error);
            if (root) {
                json_t *json_password = json_object_get(root, 
                    conf->password_field.len > 0 ? (char *)conf->password_field.data : "password");
                json_t *json_username = json_object_get(root, 
                    conf->username_field.len > 0 ? (char *)conf->username_field.data : "username");
                json_t *json_email = json_object_get(root, 
                    conf->email_field.len > 0 ? (char *)conf->email_field.data : "email");

                if (json_password && json_is_string(json_password)) 
                    password = strdup(json_string_value(json_password));
                if (json_username && json_is_string(json_username)) 
                    username = strdup(json_string_value(json_username));
                if (json_email && json_is_string(json_email)) 
                    email = strdup(json_string_value(json_email));
                
                json_decref(root);
            }
        }
    }

    if (password && (username || email)) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1((unsigned char *)password, strlen(password), hash);
        char hex_hash[SHA_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            sprintf(&hex_hash[i * 2], "%02x", hash[i]);
        }

        char prefix[6], suffix[36];
        strncpy(prefix, hex_hash, 5);
        prefix[5] = '\0';
        strcpy(suffix, hex_hash + 5);

        if (check_hibp(r, prefix, suffix)) {
            conf->should_log = 1;
            if (username) conf->username = strdup(username);
            if (email) conf->email = strdup(email);
            conf->hash = strdup(hex_hash);
        }
    }

    if (username) free(username);
    if (email) free(email);
    if (password) free(password);
    return rc;
}