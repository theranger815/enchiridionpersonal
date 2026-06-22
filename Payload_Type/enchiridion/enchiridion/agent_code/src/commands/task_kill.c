#include "task_kill.h"
#include "download.h"
#include "upload.h"
#include "utils.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

typedef struct RunningTask {
    char task_uuid[UUIDSIZE + 1];
    pthread_t tid;
    pid_t child_pid; // non-zero for shell tasks
    ThreadPool *pool;
    struct RunningTask *next;
} RunningTask;

static RunningTask *g_tasks_head = NULL;
static pthread_mutex_t g_tasks_lock = PTHREAD_MUTEX_INITIALIZER;

void taskRegister(const char *task_uuid, pthread_t tid, ThreadPool *pool) {
    RunningTask *rt = calloc(1, sizeof(RunningTask));
    if (!rt)
        return;
    strncpy(rt->task_uuid, task_uuid, UUIDSIZE);
    rt->tid = tid;
    rt->pool = pool;

    pthread_mutex_lock(&g_tasks_lock);
    rt->next = g_tasks_head;
    g_tasks_head = rt;
    pthread_mutex_unlock(&g_tasks_lock);
    DBGPRINT("TaskRegister: uuid=%s tid=%lu", task_uuid, (unsigned long)tid);
}

void taskSetChildPid(const char *task_uuid, pid_t pid) {
    pthread_mutex_lock(&g_tasks_lock);
    for (RunningTask *cur = g_tasks_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            cur->child_pid = pid;
            break;
        }
    }
    pthread_mutex_unlock(&g_tasks_lock);
    DBGPRINT("TaskSetChildPid: uuid=%s pid=%d", task_uuid, pid);
}

void taskDeregister(const char *task_uuid) {
    pthread_mutex_lock(&g_tasks_lock);
    RunningTask **prev = &g_tasks_head;
    for (RunningTask *cur = g_tasks_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, task_uuid, UUIDSIZE) == 0) {
            *prev = cur->next;
            pthread_mutex_unlock(&g_tasks_lock);
            free(cur);
            DBGPRINT("TaskDeregister: uuid=%s", task_uuid);
            return;
        }
        prev = &cur->next;
    }
    pthread_mutex_unlock(&g_tasks_lock);
}

int taskKillCommand(const char *target_uuid, Agent *agent, TaskResponse *resp) {
    resp->output = malloc(ERR_MSG_SIZE);
    if (!resp->output) {
        resp->status = -1;
        return -1;
    }

    pthread_t tid = 0;
    pid_t child_pid = 0;
    ThreadPool *pool = NULL;
    int found = 0;

    // Pull the entry atomically so we own it before acting on it.
    pthread_mutex_lock(&g_tasks_lock);
    RunningTask **prev = &g_tasks_head;
    for (RunningTask *cur = g_tasks_head; cur; cur = cur->next) {
        if (strncmp(cur->task_uuid, target_uuid, UUIDSIZE) == 0) {
            tid = cur->tid;
            child_pid = cur->child_pid;
            pool = cur->pool;
            *prev = cur->next;
            free(cur);
            found = 1;
            break;
        }
        prev = &cur->next;
    }
    pthread_mutex_unlock(&g_tasks_lock);

    int killed = 0;

    if (found) {
        if (child_pid != 0) {
            // Shell task: kill the child process only. The write ends of the
            // pipes close, so read() in shellExecute returns 0 (EOF) naturally,
            // and shellExecute then calls waitpid() to reap the child cleanly.
            // Calling pthread_cancel here would race with waitpid() and leave
            // the child in a defunct state.
            if (kill(child_pid, SIGKILL) == 0) {
                DBGPRINT("TaskKill: SIGKILL -> pid=%d uuid=%s", child_pid, target_uuid);
                killed = 1;
            } else {
                DBGPRINT("TaskKill: kill pid=%d failed: %s", child_pid, strerror(errno));
            }
        } else if (!pthread_equal(tid, pthread_self())) {
            // Non-shell blocking task: cancel the worker thread.
            if (pthread_cancel(tid) == 0) {
                DBGPRINT("TaskKill: cancelled tid=%lu uuid=%s", (unsigned long)tid, target_uuid);
                killed = 1;
                // Spawn a detached replacement to keep the pool at full size.
                if (pool) {
                    pthread_t replacement;
                    if (pthread_create(&replacement, NULL, worker, pool) == 0)
                        pthread_detach(replacement);
                }
            }
        }
    }

    // Clean up async transfer state. The worker thread for these tasks has
    // already returned, so no one else will send Mythic a completion response
    // for the killed task's UUID — we must do it here.
    int transfer_killed = 0;
    if (processDownloadAck(target_uuid, NULL, 0) == -1)
        transfer_killed = 1;
    if (!transfer_killed && processUploadChunk(target_uuid, 0, 0, NULL, 0) == -1)
        transfer_killed = 1;
    if (transfer_killed) {
        killed = 1;
        TaskResponse transfer_resp = {0};
        transfer_resp.task_uuid = (char *)target_uuid;
        transfer_resp.status = -1;
        transfer_resp.output = malloc(ERR_MSG_SIZE);
        if (transfer_resp.output)
            memcpy(transfer_resp.output, "Task killed", sizeof("Task killed"));
        sendResponse(agent, &transfer_resp);
    }

    if (killed) {
        memcpy(resp->output, "Task killed", sizeof("Task killed"));
        resp->status = 0;
    } else {
        memcpy(resp->output, "Task not found or already completed",
               sizeof("Task not found or already completed"));
        resp->status = -1;
    }
    return 0;
}
