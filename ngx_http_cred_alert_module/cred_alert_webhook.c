#include "cred_alert_webhook.h"
#include "cred_alert_hibp.h"
#include "ngx_http_cred_alert_module.h"

static void *webhook_thread(void *arg) {
    // Detach the thread so resources are automatically cleaned up
    pthread_detach(pthread_self());

    // Cast the argument back to our data structure
    ngx_http_request_t *r = ((webhook_data_t *)arg)->r;
    char *json_data = ((webhook_data_t *)arg)->json_data;
    ngx_str_t target_url = ((webhook_data_t *)arg)->target_url;

    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, (char *)target_url.data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L); // 5 seconds timeout
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L); // 3 seconds connect timeout

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                         "Webhook call failed: %s", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    // Free the allocated memory
    free(json_data);
    free(arg);
    return NULL;
}

void send_data_async(ngx_http_request_t *r, const char *json_data) {
    ngx_http_cred_alert_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_cred_alert_module);

    if (!conf || !conf->target_url.data || !json_data) {
        return;
    }

    // Allocate memory for the data we need to pass to the thread
    webhook_data_t *data = malloc(sizeof(webhook_data_t));
    if (!data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for webhook data");
        return;
    }

    // Copy the data we need
    data->r = r;
    data->json_data = strdup(json_data);
    data->target_url = conf->target_url;

    if (!data->json_data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to copy JSON data");
        free(data);
        return;
    }

    // Create a thread to handle the webhook call
    pthread_t thread_id;
    int ret = pthread_create(&thread_id, NULL, webhook_thread, data);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to create webhook thread");
        free(data->json_data);
        free(data);
        return;
    }
} 