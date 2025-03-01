#include "cred_alert_log.h"
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>

void ngx_log_json(ngx_log_t *log, json_t *root) {
    char *json_str = json_dumps(root, JSON_INDENT(4));
    if (json_str) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "JSON output:\n%s", json_str);
        free(json_str);
    } else {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "Failed to print JSON");
    }
}

void write_to_log(ngx_http_request_t *r, const char *username, const char *email, 
                 const char *hash, const char *uri, const char *method, 
                 ngx_uint_t status, const char *host) {
    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_cred_alert_module);

    if (!conf || !conf->log_file.data) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm;
    char timestamp[32];
    localtime_r(&now, &tm);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);

    FILE *f = fopen((const char *)conf->log_file.data, "a");
    if (!f) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                     "Failed to open log file: %s", conf->log_file.data);
        return;
    }

    fprintf(f, "[%s] %s - %s - %s - %s - %s - %s - %lu\n",
            timestamp,
            r->connection->addr_text.data,
            host ? host : "-",
            method ? method : "-",
            uri ? uri : "-",
            username ? username : (email ? email : "-"),
            hash ? hash : "-",
            status);

    fclose(f);
} 