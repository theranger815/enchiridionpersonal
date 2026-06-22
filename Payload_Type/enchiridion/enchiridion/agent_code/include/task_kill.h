#ifndef TASK_KILL_H
#define TASK_KILL_H

#include "commands.h"
#include "enchiridion.h"
#include <pthread.h>
#include <sys/types.h>

// Register the worker thread and its pool before dispatching a command.
void taskRegister(const char *task_uuid, pthread_t tid, ThreadPool *pool);

// Update the registered entry with the child PID spawned by a shell task.
void taskSetChildPid(const char *task_uuid, pid_t pid);

// Remove the registry entry when a task completes normally.
void taskDeregister(const char *task_uuid);

// Kill the task identified by target_uuid and fill resp with the result.
// agent is used to send a completion response for async transfer tasks whose
// worker thread has already returned (download/upload), since no other code
// path will close them out in Mythic.
int taskKillCommand(const char *target_uuid, Agent *agent, TaskResponse *resp);

#endif // !TASK_KILL_H
