#include "cred_alert_hibp.h"
#include <string.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

ngx_int_t check_hibp(ngx_http_request_t *r, const char *prefix, const char *suffix) {
    CURL *curl;
    CURLcode res;
    long response_code;
    ngx_int_t found = 0;
    struct MemoryStruct chunk;
    char url[512];
    
    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_cred_alert_module);

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if (curl) {
        // Use configured HIBP URL if available, otherwise use default
        if (conf && conf->hibp_url.len > 0) {
            snprintf(url, sizeof(url), "%.*s%s", 
                    (int)conf->hibp_url.len, conf->hibp_url.data, prefix);
        } else {
            snprintf(url, sizeof(url), "https://api.pwnedpasswords.com/range/%s", prefix);
        }

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "User-Agent: Nginx-Cred-Alert-Module");
        headers = curl_slist_append(headers, "Add-Padding: true");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code == 200) {
                char *line = strtok(chunk.memory, "\r\n");
                while (line != NULL) {
                    if (strncasecmp(line, suffix, strlen(suffix)) == 0) {
                        found = 1;
                        break;
                    }
                    line = strtok(NULL, "\r\n");
                }
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                         "HIBP API request failed: %s", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    if (chunk.memory) {
        free(chunk.memory);
    }
    return found;
} 