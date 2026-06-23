#ifndef COMMANDS_H
#define COMMANDS_H
#include "agent.h"
#include "cJSON.h"


typedef struct {
    char *task_uuid;
    char *output;
    int status;
    char *formatted_response_key;
    cJSON *formatted_response;
} TaskResponse;

void shellExecute(char *cmd, char *task_uuid, TaskResponse *resp);
void fileListing(char *path, TaskResponse *resp);
int download(char *path, char *task_uuid, Agent *agent, TaskResponse *resp);
int upload(char *file_id, char *remote_path, char *task_uuid, Agent *agent, TaskResponse *resp);
void updateConfigCommand(Agent *agent, cJSON *params, TaskResponse *resp);
void configCommand(Agent *agent, TaskResponse *resp);

#endif // !COMMANDS_H
